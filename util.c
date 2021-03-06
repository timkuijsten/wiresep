/*
 * Copyright (c) 2018, 2019 Tim Kuijsten
 *
 * Permission to use, copy, modify, and distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright
 * notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "util.h"

#define MAXUID ((1 << 16) - 1)
#define MAXGID ((1 << 16) - 1)

extern int background, verbose;

const signed char asciihexmap[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, /* ! */
	-1, /* " */
	-1, /* # */
	-1, /* $ */
	-1, /* % */
	-1, /* & */
	-1, /* ' */
	-1, /* ( */
	-1, /* ) */
	-1, /* * */
	-1, /* + */
	-1, /* , */
	-1, /* - */
	-1, /* . */
	-1, /* / */
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 0-9 */
	-1, /* : */
	-1, /* ; */
	-1, /* < */
	-1, /* = */
	-1, /* > */
	-1, /* ? */
	-1, /* @ */
	10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, /* A-Z */
	-1, /* [ */
	-1, /* \ */
	-1, /* ] */
	-1, /* ^ */
	-1, /* _ */
	-1, /* ` */
	10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	    -1, -1, /* a-z */
	-1, /* { */
	-1, /* | */
	-1, /* } */
	-1,  /* ~ */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1
};

/*
 * Check if the given file descriptor is open.
 *
 * Return 1 if fd is open, 0 if not.
 */
int
isopenfd(int fd)
{
	if (fcntl(fd, F_GETFL) == -1)
		return 0;

        return 1;
}

/*
 * Convert a null terminated ASCII encoded hexadecimal string into binary data
 * without leaving any bits in memory other than in "dst". "srclen" must be
 * excluding the terminating null byte. "dst" is not null terminated since it
 * contains binary data.
 *
 * Return 0 on success, -1 on error.
 */
int
readhexnomem(uint8_t *dst, size_t dstlen, const char *src, size_t srclen)
{
	size_t i;

	assert(sizeof(asciihexmap) / sizeof(asciihexmap[0]) == 256);

	if (dstlen < 1 || srclen < 1)
		return -1;

	/* determine if dst is big enough */
	if ((srclen + 1) / 2 > dstlen)
		return -1;

	/* init start position */
	if (srclen & 1) {
		/* odd, init new digit */
		dst[0] = 0;
		i = 1;
	} else {
		/* even, let loop init new digit */
		i = 0;
	}

	for (; i < srclen; i++) {
		if (asciihexmap[(unsigned char)src[i]] < 0)
			break;

		if (i & 1) {
			/* assume digit is initalized */
			dst[i/2] += asciihexmap[(unsigned char)src[i]];
		} else {
			/* init new digit */
			dst[i/2] = asciihexmap[(unsigned char)src[i]] * 16;
		}
	}

	if (i != srclen)
		return -1;

	return 0;
}

void
hexdump(FILE *fp, const uint8_t *data, size_t datalen, size_t maxwidth)
{
	size_t i, j;

	if (datalen < 1)
		return;

	if (maxwidth < 1)
		return;

	for (i = 0; i < datalen;) {
		if (i % maxwidth == 0)
			fprintf(fp, "%04zx  ", i);

		fprintf(fp, "%02x ", data[i]);

		i++;

		if (i % maxwidth == 0) {
			j = maxwidth;
		} else if (i == datalen) {
			/* pad */
			j = maxwidth - i % maxwidth;
			while (j-- > 0)
				fprintf(fp, "   ");

			j = i % maxwidth;
		} else {
			j = 0;
		}

		if (j > 0) {
			fprintf(fp, "  ");
			for (; j > 0; j--) {
				if (isgraph(data[i - j]))
					fprintf(fp, "%c", data[i - j]);
				else
					fprintf(fp, ".");
			}

			fprintf(fp, "\n");
		}
	}
}

/*
 * If the current or maximum limit of "resource" exceed "limit", set both to
 * "limit".
 *
 * Exit on error.
 */
void
xensurelimit(int resource, size_t limit)
{
	struct rlimit rl;
	const char *infostr;

	switch (resource) {
	case RLIMIT_CORE:
		infostr = "core";
		break;
	case RLIMIT_CPU:
		infostr = "cpu";
		break;
	case RLIMIT_DATA:
		infostr = "data";
		break;
	case RLIMIT_FSIZE:
		infostr = "fsize";
		break;
	case RLIMIT_MEMLOCK:
		infostr = "memlock";
		break;
	case RLIMIT_NOFILE:
		infostr = "nofile";
		break;
	case RLIMIT_NPROC:
		infostr = "nproc";
		break;
	case RLIMIT_RSS:
		infostr = "rss";
		break;
	case RLIMIT_STACK:
		infostr = "stack";
		break;
	default:
		infostr = "";
	}

	if (getrlimit(resource, &rl) == -1) {
		logwarn("getrlimit error when trying to fetch the %s limits",
		    infostr);
		exit(1);
	}

	if (rl.rlim_cur > limit) {
		rl.rlim_cur = limit;

		if (setrlimit(resource, &rl) == -1) {
			logwarn("setrlimit error when trying to lower the "
			    "current %s limit to %lu", infostr, limit);
			exit(1);
		}
	}

	if (rl.rlim_max > limit) {
		rl.rlim_max = limit;

		if (setrlimit(resource, &rl) == -1) {
			logwarn("setrlimit error when trying to lower the "
			    "maximum %s limit to %lu", infostr, limit);
			exit(1);
		}
	}
}

/*
 * Convert a string representation of a host and/or service name into a socket
 * address structure.
 *
 * Return 0 on success, or a number for gai_strerror(3) on error.
 */
int
strtoaddr(struct sockaddr_storage *r, const char *name, const char *serv,
    int ai_flags)
{
	struct addrinfo hints, *res;
	int e;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = ai_flags;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	e = getaddrinfo(name, serv, &hints, &res);
	if (e)
		return e;

	memcpy(r, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	return 0;
}

/*
 * Convert a datalink address to a string representation.
 *
 * Note: If "out" is at least one byte then nul termination is guaranteed.
 *
 * Return 0 on success, or -1 on error, i.e. if outsize was not big enough. On
 * error a descriptive string is written to "out".
 */
int
dltostr(char *out, size_t outsize, const struct sockaddr_dl *sdl)
{
	const uint8_t *cp;

	if (out == NULL || outsize == 0)
		return -1;

	out[0] = '\0';

	if (sdl == NULL || sdl->sdl_family != AF_LINK) {
		snprintf(out, outsize, "sdl may not by null and must be of type"
		    " AF_LINK");
		return -1;
	}

	/* try to append ethernet address */
	if (sdl->sdl_type == IFT_ETHER) {
		cp = (uint8_t *)&sdl->sdl_data[sdl->sdl_nlen];
		if ((size_t)snprintf(out, outsize,
		    "%.*s%%%d %02x:%02x:%02x:%02x:%02x:%02x",
		    sdl->sdl_nlen, sdl->sdl_data, sdl->sdl_index,
		    *cp, *(cp + 1), *(cp + 2), *(cp + 3), *(cp + 4), *(cp + 5))
		    >= outsize) {
			snprintf(out, outsize, "out too small");
			return -1;
		}
	} else {
		if ((size_t)snprintf(out, outsize, "%.*s%%%d", sdl->sdl_nlen,
		    sdl->sdl_data, sdl->sdl_index) >= outsize) {
			snprintf(out, outsize, "out too small");
			return -1;
		}
	}

	return 0;
}

/*
 * Convert an ip address to a string representation.
 *
 * Note: If "out" is at least one byte then nul termination is guaranteed.
 * Note2: if "outsize" >= MAXIPSTR than any succesfully resolved ip-address will
 * always fit.
 *
 * Return 0 on success, or -1 on error, i.e. if outsize was not big enough. On
 * error a descriptive string is written to "out".
 */
int
inettostr(char *out, size_t outsize, const struct sockaddr *sa, int noport)
{
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	const char *fmt;
	int e;

	if (out == NULL || outsize == 0)
		return -1;

	out[0] = '\0';

	if (sa == NULL) {
		snprintf(out, outsize, "sa may not by null");
		return -1;
	}

	e = getnameinfo(sa, sa->sa_len, host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST | NI_NUMERICSERV);

	if (e) {
		snprintf(out, outsize, "%s", gai_strerror(e));
		return -1;
	}

	if (sa->sa_family == AF_INET6) {
		if (noport) {
			fmt = "[%s]";
		} else {
			fmt = "[%s]:%s";
		}
	} else {
		if (noport) {
			fmt = "%s";
		} else {
			fmt = "%s:%s";
		}
	}

	if (noport) {
		if ((size_t)snprintf(out, outsize, fmt, host) >= outsize) {
			snprintf(out, outsize, "out too small");
			return -1;
		}
	} else {
		if ((size_t)snprintf(out, outsize, fmt, host, serv)
		    >= outsize) {
			snprintf(out, outsize, "out too small");
			return -1;
		}
	}

	return 0;
}

/*
 * Convert a hardware or ip address to a string representation.
 *
 * Note: If "out" is at least one byte then nul termination is guaranteed.
 * Note2: if "outsize" >= MAXADDRSTR than any succesfully resolved address will
 * always fit.
 *
 * Return 0 on success, or -1 on error, i.e. if outsize was not big enough. On
 * error a descriptive string is written to "out".
 */
int
addrtostr(char *out, size_t outsize, const struct sockaddr *sa, int noport)
{
	if (sa == NULL) {
		snprintf(out, outsize, "sa may not by null");
		return -1;
	}

	switch (sa->sa_family) {
	case AF_LINK:
		return dltostr(out, outsize, (struct sockaddr_dl *)sa);
	case AF_INET6:
	case AF_INET:
		return inettostr(out, outsize, sa, noport);
	default:
		snprintf(out, outsize, "unsupported address family %d",
		    sa->sa_family);
		return -1;
	}
}

void
printopenfds(FILE *fp, int maxfd)
{
	int i, n;

	for (n = 0, i = 0; i <= maxfd; i++)
		if (isopenfd(i)) {
			fprintf(fp, "%d ", i);
			n++;
		}

	if (n > 0)
		fprintf(fp, "\n");

	fprintf(fp, "%d fds open", n);
}

/*
 * Write data to a file.
 */
int
data2file(const char *path, const void *data, size_t datasize)
{
	int d;

	if ((d = open(path, O_WRONLY)) == -1)
		return -1;

	if (writen(d, data, datasize) == -1) {
		close(d);
		return -1;
	}

	assert(close(d) == -1);

	return 0;
}

/*
 * Write data to a file.
 *
 * Return 0 on success, or the number of bytes written on error.
 */
ssize_t
writen(int d, const void *buf, size_t bufsize)
{
	ssize_t r, left;
	const uint8_t *data;

	data = buf;
	left = bufsize;
	while (left) {
		r = write(d, &data[bufsize - left], left);
		if (r == -1)
			return left;
		left -= r;
	}

	return 0;
}

/*
 * Extract the port from a socket address in host byte order.
 *
 * Return the port on success, -1 on error.
 */
int
getport(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET6) {
		return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
	} else if (sa->sa_family == AF_INET) {
		return ntohs(((struct sockaddr_in *)sa)->sin_port);
	} else {
		return -1;
	}
}

/*
 * Resolve a user and primary group id. Supports the name as a string, a decimal
 * number, hexadecimal or octal number (precedence of names over ids is based on
 * chown(1) and POSIX).
 *
 * Return 0 on success, -1 on failure with errno set.
 */
int
resolveuser(uid_t *uid, gid_t *gid, const char *userstr)
{
	struct passwd *pwd;
	intmax_t tmpid;
	char *errchr;

	if (uid == NULL || gid == NULL || userstr == NULL) {
		errno = EINVAL;
		return -1;
	}

	pwd = getpwnam(userstr);

	if (pwd == NULL) {
		/* Maybe it's a uid. */

		tmpid = strtoimax(userstr, &errchr, 0);
		if (tmpid < 0 || tmpid > MAXUID || *errchr != '\0')
			return -1;

		pwd = getpwuid(tmpid);

		if (pwd == NULL) {
			/*
			 * uid is not set in passwd, but thats
			 * ok. Use the same id for the group.
			 */

			*uid = tmpid;
			*gid = tmpid;
		} else {
			/* Use the configured primary group. */
			*uid = pwd->pw_uid;
			*gid = pwd->pw_gid;
		}
	} else {
		*uid = pwd->pw_uid;
		*gid = pwd->pw_gid;
	}

	return 0;
}

/*
 * Resolve a group id. Supports the name as a string, a decimal number,
 * hexadecimal or octal number (precedence of names over ids is based on
 * chown(1) and POSIX).
 *
 * Return 0 on success, -1 on failure with errno set.
 */
int
resolvegroup(gid_t *gid, const char *groupstr)
{
	struct group *grp;
	intmax_t tmpid;
	char *errchr;

	if (gid == NULL || groupstr == NULL) {
		errno = EINVAL;
		return -1;
	}

	grp = getgrnam(groupstr);

	if (grp == NULL) {
		/* Maybe it's a gid. */

		tmpid = strtoimax(groupstr, &errchr, 0);
		if (tmpid < 0 || tmpid > MAXGID || *errchr != '\0')
			return -1;

		grp = getgrgid(tmpid);

		if (grp == NULL) {
			/*
			 * gid is not set in passwd, but thats
			 * ok. Use the same id for the group.
			 */

			*gid = tmpid;
		} else {
			*gid = grp->gr_gid;
		}
	} else {
		*gid = grp->gr_gid;
	}

	return 0;
}

/*
 * Input must be a nul terminated string containing a facility from
 * syslog.conf(5).
 *
 * Return 0 if "logfacility" is set, or -1 if "facility" is not recognized.
 */
int
facilitystrtoint(int *logfacility, const char *facility)
{
	if (strcmp(facility, "auth") == 0) {
		*logfacility = LOG_AUTH;
	} else if (strcmp(facility, "authpriv") == 0) {
		*logfacility = LOG_AUTHPRIV;
	} else if (strcmp(facility, "cron") == 0) {
		*logfacility = LOG_CRON;
	} else if (strcmp(facility, "daemon") == 0) {
		*logfacility = LOG_DAEMON;
	} else if (strcmp(facility, "ftp") == 0) {
		*logfacility = LOG_FTP;
	} else if (strcmp(facility, "kern") == 0) {
		*logfacility = LOG_KERN;
	} else if (strcmp(facility, "lpr") == 0) {
		*logfacility = LOG_LPR;
	} else if (strcmp(facility, "mail") == 0) {
		*logfacility = LOG_MAIL;
	} else if (strcmp(facility, "news") == 0) {
		*logfacility = LOG_NEWS;
	} else if (strcmp(facility, "syslog") == 0) {
		*logfacility = LOG_SYSLOG;
	} else if (strcmp(facility, "user") == 0) {
		*logfacility = LOG_USER;
	} else if (strcmp(facility, "uucp") == 0) {
		*logfacility = LOG_UUCP;
	} else if (strcmp(facility, "local0") == 0) {
		*logfacility = LOG_LOCAL0;
	} else if (strcmp(facility, "local1") == 0) {
		*logfacility = LOG_LOCAL1;
	} else if (strcmp(facility, "local2") == 0) {
		*logfacility = LOG_LOCAL2;
	} else if (strcmp(facility, "local3") == 0) {
		*logfacility = LOG_LOCAL3;
	} else if (strcmp(facility, "local4") == 0) {
		*logfacility = LOG_LOCAL4;
	} else if (strcmp(facility, "local5") == 0) {
		*logfacility = LOG_LOCAL5;
	} else if (strcmp(facility, "local6") == 0) {
		*logfacility = LOG_LOCAL6;
	} else if (strcmp(facility, "local7") == 0) {
		*logfacility = LOG_LOCAL7;
	} else {
		return -1;
	}

	return 0;
}

/*
 * Daemonize.
 *
 * umask 007
 * fork and exit parent to ensure we're not a process group leader
 * setsid to create a new session and disassociate from controlling terminal
 * fork again to ensure we can't aquire a controlling terminal
 * chdir /
 * close all open descriptors
 * reopen 0, 1 and 2 to /dev/null
 *
 * Return 0 on success, -1 on error with errno set.
 */
int
daemonize(void)
{
	int i;

	umask(07);

	/* fork and exit parent */
	if (fork() != 0)
		exit(0);

	if (setsid() == -1)
		return -1;

	/*
	 * Fork again to ensure we're not a session leader and so we're not able
	 * to ever open a controlling terminal.
	 */
	if (fork() != 0)
		exit(0);

	if (chdir("/") == -1)
		return -1;

	/* close all open descriptors */
	for (i = 0; getdtablecount() > 0; i++)
		if (close(i) == -1 && errno != EBADF)
			return -1;

	/* open stdin, stdout, stderr */
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_WRONLY);
	open("/dev/null", O_WRONLY);

	return 0;
}

/*
 * Init logging and if running in the background, arrange logging via syslog.
 *
 * Expects the global int "background" to be 0 or 1.
 *
 * If running in the "background", open syslog with "facility", otherwise
 * "facility" is ignored.
 *
 * Return 0 on success, -1 otherwise.
 */
int
initlog(const char *facility)
{
	int logfacility;

	logfacility = 0;
	if (facility && strlen(facility))
		if (facilitystrtoint(&logfacility, facility) == -1)
			return -1;

	if (background)
		openlog(NULL, LOG_NDELAY | LOG_PID, logfacility);

	return 0;
}

void
logexit(int code, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_ERR, msg, ap);
		syslog(LOG_ERR, "%m");
		exit(code);
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		if (msg) {
			vfprintf(stderr, msg, ap);
			fprintf(stderr, ": %s\n", strerror(errno));
		} else {
			fprintf(stderr, "%s\n", strerror(errno));
		}
		exit(code);
	}
	va_end(ap);
}

void
logexitx(int code, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_ERR, msg, ap);
		exit(code);
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		vfprintf(stderr, msg, ap);
		fprintf(stderr, "\n");
		exit(code);
	}
	va_end(ap);
}

/*
 * These and the other log functions expect the global integers "background" and
 * "verbose" to be set.
 *
 * "verbose" must be a number between -2 and 2:
 * -2 = err
 * -1 = lower + warn
 *  0 = lower + notice
 *  1 = lower + info
 *  2 = lower + debug
 */
void
logwarn(const char *msg, ...)
{
	va_list ap;
	int saved_errno = errno;

	if (verbose < -1)
		return;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_WARNING, msg, ap);
		syslog(LOG_WARNING, "%m");
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		if (msg) {
			vfprintf(stderr, msg, ap);
			fprintf(stderr, ": %s\n", strerror(errno));
		} else {
			fprintf(stderr, "%s\n", strerror(errno));
		}
	}
	va_end(ap);

	errno = saved_errno;
}

void
logwarnx(const char *msg, ...)
{
	va_list ap;
	int saved_errno = errno;

	if (verbose < -1)
		return;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_WARNING, msg, ap);
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		vfprintf(stderr, msg, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);

	errno = saved_errno;
}

void
lognotice(const char *msg, ...)
{
	va_list ap;
	int saved_errno = errno;

	if (verbose < 0)
		return;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_NOTICE, msg, ap);
		syslog(LOG_NOTICE, "%m");
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		if (msg) {
			vfprintf(stderr, msg, ap);
			fprintf(stderr, ": %s\n", strerror(errno));
		} else {
			fprintf(stderr, "%s\n", strerror(errno));
		}
	}
	va_end(ap);

	errno = saved_errno;
}

void
lognoticex(const char *msg, ...)
{
	va_list ap;
	int saved_errno = errno;

	if (verbose < 0)
		return;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_NOTICE, msg, ap);
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		vfprintf(stderr, msg, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);

	errno = saved_errno;
}

void
loginfo(const char *msg, ...)
{
	va_list ap;
	int saved_errno = errno;

	if (verbose < 1)
		return;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_INFO, msg, ap);
		syslog(LOG_INFO, "%m");
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		if (msg) {
			vfprintf(stderr, msg, ap);
			fprintf(stderr, ": %s\n", strerror(errno));
		} else {
			fprintf(stderr, "%s\n", strerror(errno));
		}
	}
	va_end(ap);

	errno = saved_errno;
}

void
loginfox(const char *msg, ...)
{
	va_list ap;
	int saved_errno = errno;

	if (verbose < 1)
		return;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_INFO, msg, ap);
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		vfprintf(stderr, msg, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);

	errno = saved_errno;
}

void
logdebug(const char *msg, ...)
{
	va_list ap;
	int saved_errno = errno;

	if (verbose < 2)
		return;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_DEBUG, msg, ap);
		syslog(LOG_DEBUG, "%m");
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		if (msg) {
			vfprintf(stderr, msg, ap);
			fprintf(stderr, ": %s\n", strerror(errno));
		} else {
			fprintf(stderr, "%s\n", strerror(errno));
		}
	}
	va_end(ap);

	errno = saved_errno;
}

void
logdebugx(const char *msg, ...)
{
	va_list ap;
	int saved_errno = errno;

	if (verbose < 2)
		return;

	va_start(ap, msg);
	if (background) {
		vsyslog(LOG_DEBUG, msg, ap);
	} else {
		fprintf(stderr, "%s[%d]: ", getprogname(), getpid());
		vfprintf(stderr, msg, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);

	errno = saved_errno;
}

/*
 * Make sure the given file descriptor belongs to a regular file, that it is
 * owned by the superuser and that the permissions are a subset of
 * "allowedpermissions".
 *
 * Return 1 if the fd is safe, 0 otherwise.
 */
int
isfdsafe(int fd, mode_t allowedpermissions)
{
	struct stat st;

	if (fstat(fd, &st) == -1)
		return 0;

	if (st.st_uid != 0)
		return 0;

	if (!S_ISREG(st.st_mode))
		return 0;

	allowedpermissions += S_IFREG;

	if ((st.st_mode & ~allowedpermissions) != 0)
		return 0;

	return 1;
}
