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

#include <sys/socket.h>
#include <sys/wait.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "util.h"
#include "wireprot.h"

#include "parseconfig.h"

#ifndef VERSION_MAJOR
#define VERSION_MAJOR 0
#define VERSION_MINOR 0
#define VERSION_PATCH 0
#endif

#define DEFAULTCONFIG "/etc/wiresep/wiresep.conf"

typedef int chan[2];

void enclave_init(int masterport);
void proxy_init(int masterport);
void ifn_init(int masterport);
void enclave_serv(void);
void proxy_serv(void);
void ifn_serv(void);

void master_printinfo(FILE *);

/* these are used by the other modules as well */
int background, verbose, doterm;

/* global settings */
static char *configfile;
static uid_t guid;
static gid_t ggid;

static struct cfgifn **ifnv;
static size_t ifnvsize;

static union smsg smsg;

/* communication channels */
int mastwithencl, enclwithmast, mastwithprox, proxwithmast, enclwithprox,
    proxwithencl;

static void
handlesig(int signo)
{
	switch (signo) {
	case SIGTERM:
		doterm = 1;
		break;
	default:
		logwarnx("master unexpected signal %d %s", signo,
		    strsignal(signo));
		break;
	}
}

void
printdescriptors(void)
{
	size_t n;

	logdebugx("master enclave %d:%d", mastwithencl, enclwithmast);
	logdebugx("master proxy %d:%d", mastwithprox, proxwithmast);

	for (n = 0; n < ifnvsize; n++) {
		logdebugx("master %s master %d:%d, enclave %d:%d, proxy %d:%d",
		    ifnv[n]->ifname,
		    ifnv[n]->mastwithifn,
		    ifnv[n]->ifnwithmast,
		    ifnv[n]->enclwithifn,
		    ifnv[n]->ifnwithencl,
		    ifnv[n]->proxwithifn,
		    ifnv[n]->ifnwithprox);
	}
}

void
printversion(int d)
{
	dprintf(d, "WireSep v%d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR,
	    VERSION_PATCH);
}

void
printusage(int d)
{
	dprintf(d, "usage: %s [-dnqVv] [-f file]\n", getprogname());
}

/*
 * Bootstrap the application:
 *   0. read configuration
 *   1. determine public key, mac1key and cookie key of each interface
 *   2. setup communication ports and fork each IFN, the PROXY and the ENCLAVE
 *   3. send startup info to processes
 *   4. reexec and idle
 */
int
main(int argc, char **argv)
{
	struct sigaction sa;
	/* descriptors for all communication channels */
	chan *ifchan, mastmast, tmpchan;
	size_t n, m;
	int configtest, foreground, stdopen, masterport, stat;
	pid_t pid;
	const char *errstr;
	char c, *eargs[4], *eenv[1], *logfacilitystr, *oldprogname;

	/* should endup in a configure script */
	if (sizeof(struct msgwginit) != 148)
		errx(1, "sizeof(struct msgwginit != 148: %zu",
		    sizeof(struct msgwginit));

	if (sizeof(struct msgwgresp) != 92)
		errx(1, "sizeof(struct msgwgresp) != 92: %zu",
		    sizeof(struct msgwgresp));

	if (sizeof(struct msgwgcook) != 64)
		errx(1, "sizeof(struct msgwgcook) != 64: %zu",
		    sizeof(struct msgwgcook));

	if (sizeof(struct msgwgdatahdr) != 16)
		errx(1, "sizeof(struct msgwgdatahdr) != 16: %zu",
		    sizeof(struct msgwgdatahdr));

	configtest = 0;
	foreground = 0;
	while ((c = getopt(argc, argv, "E:I:M:P:Vdf:hnqv")) != -1)
		switch(c) {
		case 'E':
			masterport = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid enclave/master fd: %s %s",
				    errstr, optarg);
			setproctitle("enclave");
			enclave_init(masterport);
			enclave_serv();
			errx(1, "enclave[%d]: unexpected return", getpid());
		case 'I':
			masterport = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid ifn/master fd: %s %s",
				    errstr, optarg);
			setproctitle("ifn"); /* overridden by ifn process */
			ifn_init(masterport);
			ifn_serv();
			errx(1, "ifn[%d]: unexpected return", getpid());
		case 'P':
			masterport = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid proxy/master fd: %s %s",
				    errstr, optarg);
			setproctitle("proxy");
			proxy_init(masterport);
			proxy_serv();
			errx(1, "proxy[%d]: unexpected return", getpid());
		case 'M':
			mastmast[1] = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid mastermaster descriptor: %s "
				    "%s", errstr, optarg);
			setproctitle("master");

			if (chroot(EMPTYDIR) == -1 || chdir("/") == -1)
				err(1, "chroot %s", EMPTYDIR);
			if (pledge("stdio", "") == -1)
				err(1, "%s: pledge", __func__);

			if (read(mastmast[1], &mastwithencl, sizeof(int))
			    != sizeof(int))
				err(1, "could not read enclave descriptor in "
				    "new master");
			if (read(mastmast[1], &mastwithprox, sizeof(int))
			    != sizeof(int))
				err(1, "could not read proxy descriptor in new "
				    "master");
			if (read(mastmast[1], &ifnvsize, sizeof(ifnvsize))
			    != sizeof(ifnvsize))
				err(1, "could not read ifnvsize in new master");
			if ((ifchan = calloc(ifnvsize, sizeof(*ifchan)))
			    == NULL)
				err(1, "calloc ifchan");
			for (n = 0; n < ifnvsize; n++) {
				if (read(mastmast[1], &ifchan[n][0],
				    sizeof(int)) != sizeof(int))
					err(1, "could not read ifn descriptor "
					    "in new master");
			}
			close(mastmast[1]);

			/*
			 * Ignore SIGUSR1 and catch SIGTERM.
			 */

			sa.sa_flags = 0;
			if (sigemptyset(&sa.sa_mask) == -1)
				err(1, "sigemptyset");

			sa.sa_handler = SIG_IGN;
			if (sigaction(SIGUSR1, &sa, NULL) == -1)
				err(1, "sigaction SIGUSR1");

			sa.sa_handler = handlesig;
			if (sigaction(SIGTERM, &sa, NULL) == -1)
				err(1, "sigaction SIGTERM");

			/*
			 * Signal that we are ready and each process may proceed
			 * and start processing untrusted input.
			 */
			signal_eos(smsg, mastwithencl);
			signal_eos(smsg, mastwithprox);
			for (n = 0; n < ifnvsize; n++)
				signal_eos(smsg, ifchan[n][0]);

			/*
			 * Wait for first child to die or when a SIGTERM is
			 * received.
			 */
			if ((pid = waitpid(WAIT_ANY, &stat, 0)) == -1) {
				if (errno != EINTR)
					err(1, "waitpid");

				if (!doterm)
					errx(1, "return from unexpected "
					    "signal");

				warnx("received TERM, shutting down");
			} else {
				if (WIFEXITED(stat)) {
					warnx("child %d normal exit %d", pid,
					    WEXITSTATUS(stat));
				} else if (WIFSIGNALED(stat)) {
					warnx("child %d exit by signal %d %s%s",
					    pid, WTERMSIG(stat),
					    strsignal(WTERMSIG(stat)),
					    WCOREDUMP(stat) ? " (core)" : "");
				} else
					warnx("unknown termination status");
			}

			/*
			 * It's ok to send TERM to ourselves as our signal
			 * handler only sets the doterm flag.
			 */

			if (killpg(0, SIGTERM) == -1)
				err(1, "killpg");

			exit(0);
		case 'd':
			foreground = 1;
			break;
		case 'f':
			configfile = optarg;
			break;
		case 'h':
			printusage(STDOUT_FILENO);
			exit(0);
		case 'n':
			configtest = 1;
			break;
		case 'q':
			verbose--;
			break;
		case 'V':
			printversion(STDOUT_FILENO);
			exit(0);
		case 'v':
			verbose++;
			break;
		case '?':
			printusage(STDERR_FILENO);
			exit(1);
		}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		printusage(STDERR_FILENO);
		exit(1);
	}

	if (pledge("stdio dns rpath proc exec getpw", NULL) == -1)
		err(1, "%s: pledge", __func__);

	if (geteuid() != 0)
		errx(1, "must run as the superuser");

	/*
	 *   0. read configuration and re-exec later to expunge secrets like
	 *      private keys from memory.
	 */

	if (configfile) {
		xparseconfigfile(configfile, &ifnv, &ifnvsize, &guid, &ggid,
		    &logfacilitystr);
	} else {
		xparseconfigfile(DEFAULTCONFIG, &ifnv, &ifnvsize, &guid, &ggid,
		    &logfacilitystr);
	}

	if (configtest) {
		fprintf(stdout, "configuration OK\n");
		exit(0);
	}

	if (!foreground) {
		background = 1;
		if (daemonize() == -1)
			err(1, "daemonize"); /* might not print to stdout */
	}

	if (initlog(logfacilitystr) == -1) {
		logwarnx("could not init log"); /* not printed if daemon */
		exit(1);
	}

	/*
	 *   1. determine public key, mac1key and cookie key of each interface
	 */

	processconfig();

	stdopen = isopenfd(STDIN_FILENO) + isopenfd(STDOUT_FILENO) +
	    isopenfd(STDERR_FILENO);

	assert(getdtablecount() == stdopen);

	/*
	 *   2. setup communication ports and fork each IFN, the PROXY and the
	 *     ENCLAVE
	 */

	/* don't bother to free before exec */
	if ((oldprogname = strdup(getprogname())) == NULL) {
		logwarn("master strdup getprogname error");
		exit(1);
	}

	eenv[0] = NULL;

	for (n = 0; n < ifnvsize; n++) {
		/*
		 * Open an interface channel with master, enclave and proxy,
		 * respectively.
		 */

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1) {
			logwarn("master socketpair error ifnmast %zu", n);
			exit(1);
		}

		ifnv[n]->mastwithifn = tmpchan[0];
		ifnv[n]->ifnwithmast = tmpchan[1];

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1) {
			logwarn("master socketpair error ifnencl %zu", n);
			exit(1);
		}

		ifnv[n]->enclwithifn = tmpchan[0];
		ifnv[n]->ifnwithencl = tmpchan[1];

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1) {
			logwarn("master socketpair error ifnprox %zu", n);
			exit(1);
		}

		ifnv[n]->proxwithifn = tmpchan[0];
		ifnv[n]->ifnwithprox = tmpchan[1];

		switch (fork()) {
		case -1:
			logwarn("master fork error %s", ifnv[n]->ifname);
			exit(1);
		case 0:
			if (verbose > 2)
				logdebugx("ifn %s %d", ifnv[n]->ifname,
				    getpid());

			for (m = 0; m <= n; m++) {
				close(ifnv[m]->mastwithifn);
				close(ifnv[m]->enclwithifn);
				close(ifnv[m]->proxwithifn);
			}

			assert(getdtablecount() == stdopen + 3);

			eargs[0] = (char *)getprogname();
			eargs[1] = "-I";
			if (asprintf(&eargs[2], "%u", ifnv[n]->ifnwithmast) < 1) {
				logwarnx("master asprintf error ifn");
				exit(1);
			}
			/* don't bother to free before exec */
			eargs[3] = NULL;
			execvpe(oldprogname, eargs, eenv);
			logwarn("master exec error ifn");
			exit(1);
		}

		/* parent */
		close(ifnv[n]->ifnwithmast);
		close(ifnv[n]->ifnwithencl);
		close(ifnv[n]->ifnwithprox);

		assert(getdtablecount() == stdopen + (int)(n + 1) * 3);
	}

	/*
	 * Setup channels between master, proxy and enclave.
	 */

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1) {
		logwarn("master socketpair error enclave");
		exit(1);
	}

	mastwithencl = tmpchan[0];
	enclwithmast = tmpchan[1];

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1) {
		logwarn("master socketpair error proxy");
		exit(1);
	}

	mastwithprox = tmpchan[0];
	proxwithmast = tmpchan[1];

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1) {
		logwarn("master socketpair error enclave/proxy");
		exit(1);
	}

	enclwithprox = tmpchan[0];
	proxwithencl = tmpchan[1];

	assert(getdtablecount() == stdopen + 6 + (int)ifnvsize * 3);

	/* fork enclave */
	switch (fork()) {
	case -1:
		logwarn("master fork error enclave");
		exit(1);
	case 0:
		if (verbose > 2)
			logdebugx("enclave %d", getpid());

		for (n = 0; n < ifnvsize; n++) {
			close(ifnv[n]->mastwithifn);
			close(ifnv[n]->proxwithifn);
		}

		close(mastwithprox);
		close(mastwithencl);
		close(proxwithmast);
		close(proxwithencl);

		assert(getdtablecount() == stdopen + 2 + (int)ifnvsize);

		eargs[0] = (char *)getprogname();
		eargs[1] = "-E";
		if (asprintf(&eargs[2], "%d", enclwithmast) < 1) {
			logwarnx("master asprintf error enclave");
			exit(1);
		}
		/* don't bother to free before exec */
		eargs[3] = NULL;
		execvpe(oldprogname, eargs, eenv);
		logwarn("master exec error enclave");
		exit(1);
	}

	close(enclwithmast);
	close(enclwithprox);

	for (n = 0; n < ifnvsize; n++)
		close(ifnv[n]->enclwithifn);

	assert(getdtablecount() == stdopen + 4 + (int)ifnvsize * 2);

	/* fork proxy  */
	switch (fork()) {
	case -1:
		logwarn("master fork error proxy");
		exit(1);
	case 0:
		if (verbose > 2)
			logdebugx("proxy %d", getpid());

		for (n = 0; n < ifnvsize; n++)
			close(ifnv[n]->mastwithifn);

		close(mastwithencl);
		close(mastwithprox);

		assert(getdtablecount() == stdopen + 2 + (int)ifnvsize);

		eargs[0] = (char *)getprogname();
		eargs[1] = "-P";
		if (asprintf(&eargs[2], "%d", proxwithmast) < 1) {
			logwarnx("master asprintf error proxy");
			exit(1);
		}
		/* don't bother to free before exec */
		eargs[3] = NULL;
		execvpe(oldprogname, eargs, eenv);
		logwarn("master exec error proxy");
		exit(1);
	}

	close(proxwithmast);
	close(proxwithencl);

	for (n = 0; n < ifnvsize; n++)
		close(ifnv[n]->proxwithifn);

	assert(getdtablecount() == stdopen + 2 + (int)ifnvsize);

	if (verbose > 2)
		logdebugx("master %d", getpid());

	if (verbose > 2)
		printdescriptors();

	/*
	 *   3. send startup info to processes
	 */

	sendconfig_enclave(smsg, mastwithencl, enclwithprox);
	sendconfig_proxy(smsg, mastwithprox, proxwithencl);

	for (n = 0; n < ifnvsize; n++)
		sendconfig_ifn(smsg, n);

	/*
	 *   4. reexec and idle
	 */

	/*
	 * Pump config over a stream to our future-self
	 *
	 * wire format:
	 * enclave descriptor
	 * proxy descriptor
	 * number of ifn descriptors
	 * each ifn descriptor
	 * ...
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, mastmast) == -1) {
		logwarn("master socketpair error mastermaster");
		exit(1);
	}
	if (writen(mastmast[0], &mastwithencl, sizeof(int)) != 0) {
		logwarn("could not write enclave descriptor to new master");
		exit(1);
	}
	if (writen(mastmast[0], &mastwithprox, sizeof(int)) != 0) {
		logwarn("could not write proxy descriptor to new master");
		exit(1);
	}
	if (writen(mastmast[0], &ifnvsize, sizeof(ifnvsize)) != 0) {
		logwarn("could not write ifnvsize to new master");
		exit(1);
	}
	for (n = 0; n < ifnvsize; n++) {
		if (writen(mastmast[0], &ifnv[n]->mastwithifn, sizeof(int))
		    != 0) {
			logwarn("could not pass ifn descriptor to new master");
			exit(1);
		}
	}
	close(mastmast[0]);

	eargs[0] = (char *)getprogname();
	eargs[1] = "-M";
	if (asprintf(&eargs[2], "%u", mastmast[1]) < 1) {
		logwarnx("master asprintf error master");
		exit(1);
	}
	/* don't bother to free before exec */
	eargs[3] = NULL;
	execvpe(oldprogname, eargs, eenv);
	logwarn("master exec error master");
	exit(1);
}

void
master_printinfo(FILE *fp)
{
	struct cfgifn *ifn;
	struct cfgpeer *peer;
	size_t n, m;

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];
		fprintf(fp, "ifn %zu\n", n);
		fprintf(fp, "mastwithifn %d\n", ifn->mastwithifn);
		fprintf(fp, "ifnwithmast %d\n", ifn->ifnwithmast);
		fprintf(fp, "enclwithifn %d\n", ifn->enclwithifn);
		fprintf(fp, "ifnwithencl %d\n", ifn->ifnwithencl);
		fprintf(fp, "proxwithifn %d\n", ifn->proxwithifn);
		fprintf(fp, "ifnwithprox %d\n", ifn->ifnwithprox);
		fprintf(fp, "ifname %s\n", ifn->ifname);
		fprintf(fp, "pubkey\n");
		hexdump(fp, ifn->pubkey, sizeof(ifn->pubkey), sizeof(ifn->pubkey));
		fprintf(fp, "pubkeyhash\n");
		hexdump(fp, ifn->pubkeyhash, sizeof(ifn->pubkeyhash), sizeof(ifn->pubkeyhash));
		fprintf(fp, "mac1key\n");
		hexdump(fp, ifn->mac1key, sizeof(ifn->mac1key), sizeof(ifn->mac1key));
		fprintf(fp, "cookiekey\n");
		hexdump(fp, ifn->cookiekey, sizeof(ifn->cookiekey), sizeof(ifn->cookiekey));

		for (m = 0; m < ifn->peerssize; m++) {
			peer = ifn->peers[m];
			fprintf(fp, "peer %zu\n", m);
			fprintf(fp, "pubkey\n");
			hexdump(fp, peer->pubkey, sizeof(peer->pubkey), sizeof(peer->pubkey));
			fprintf(fp, "mac1key\n");
			hexdump(fp, peer->mac1key, sizeof(peer->mac1key), sizeof(peer->mac1key));
		}

	}
}
