/*
 * Copyright (c) 2018, 2019, 2020 Tim Kuijsten
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
#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/curve25519.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "util.h"
#include "wiresep.h"

#include "parseconfig.h"

#define B64KEYLEN 44
#define MAXLISTEN6 40
#define MAXLISTEN4 40

/* global settings */
static char *guser, *ggroup, *gpskfile;
static wskey gpsk;
static uid_t guid;
static gid_t ggid;
static const char *logfacilitystr = "daemon";
static int logfacility;

static const wskey nullkey;
static const wskey basepoint = {9};

static struct cfgifn **ifnv;
static size_t ifnvsize;

/*
 * Create a new "member" of size "membersize" and add it to "arr". Exit on
 * failure.
 */
static void
xaddone(void ***arr, size_t *curmemcount, void **member, size_t membersize)
{
	*arr = recallocarray(*arr, *curmemcount, *curmemcount + 1,
	    sizeof(char *));
	if (*arr == NULL)
		err(1, "%s recallocarray", __func__);
	if ((*member = calloc(1, membersize)) == NULL)
		err(1, "%s calloc", __func__);
	(*arr)[*curmemcount] = *member;
	(*curmemcount)++;
}

/*
 * Parse an IPv4 or IPv6 address with port.
 *
 * Return 0 on success, -1 on error.
 */
static int
parseaddrport(struct sockaddr_storage *addr, const char *str)
{
	char *a, *colon, *s;

	if ((s = strdup(str)) == NULL)
		err(1, "%s strdup", __func__);

	if ((colon = strrchr(s, ':')) == NULL)
		goto err;

	*colon = '\0';

	if (strcmp(s, "*") == 0) {
		a = NULL;
	} else {
		a = s;
	}

	/* remove brackets */
	if (a && *a == '[') {
		if (*(colon - 1) != ']')
			goto err;

		a++;
		*(colon - 1) = '\0';
	}

	if (strtoaddr(addr, a, colon + 1, AI_PASSIVE) != 0)
		goto err;

	free(s);
	s = NULL;
	return 0;

err:
	free(s);
	s = NULL;
	return -1;
}

/*
 * Parse an IPv4 or IPv6 address in CIDR notation.
 *
 * Return 0 on success, -1 on error.
 */
static int
parseipcidr(struct sockaddr_storage *ip, size_t *prefixlen, const char *str)
{
	const char *errstr;
	char *slash, *s;

	if ((s = strdup(str)) == NULL)
		err(1, "%s strdup", __func__);

	slash = strchr(s, '/');
	if (slash) {
		*slash = '\0';
		*prefixlen = strtonum(slash + 1, 0, 128, &errstr);
		if (errstr != NULL)
			goto err;
	}

	if (strtoaddr(ip, s, NULL, AI_NUMERICHOST | AI_PASSIVE) != 0)
		goto err;

	if (!slash) {
		/* use default prefixlen */
		if (ip->ss_family == AF_INET6) {
			*prefixlen = 128;
		} else if (ip->ss_family == AF_INET) {
			*prefixlen = 32;
		} else
			goto err;
	}

	free(s);
	s = NULL;
	return 0;

err:
	free(s);
	s = NULL;
	return -1;
}

/*
 * Parse "path" for a base64 key and place it in "key".
 *
 * Empty lines or lines starting with a hash '#' are ignored. Also any text
 * after a key is ignored.
 *
 * Returns 1 if a key is set, 0 if no key is found and -1 on error with errno
 * set.
 */
static int
parsekeyfile(wskey key, const char *path)
{
	char *line;
	size_t len, lineno, s;
	int rc;
	FILE *fp;

	s = 0;
	rc = 0;
	lineno = 0;
	line = NULL;

	if ((fp = fopen(path, "re")) == NULL) {
		/* errno set */
		warn("%s", path);
		return -1;
	}

	if (!isfdsafe(fileno(fp), 0600)) {
		errno = EPERM;
		warn("%s: must be owned by the superuser and may not be "
		    "readable or writable by the group or others", path);
		rc = -1;
		goto cleanup;
	}

	while (getline(&line, &s, fp) > 0) {
		lineno++;

		len = strcspn(line, "\n");
		if (len == 0)
			continue;

		if (line[0] == '#')
			continue;

		line[len] = '\0';

		if (len < B64KEYLEN) {
			warnx("%s error on line %zu: illegal key", path,
			    lineno);
			errno = EINVAL;
			rc = -1;
			goto cleanup;
		}

		if (len > B64KEYLEN && !isblank(line[B64KEYLEN])) {
			warnx("%s error on line %zu: keys and comments must be "
			    "separated by a space or tab", path, lineno);
			errno = EINVAL;
			rc = -1;
			goto cleanup;
		}

		/* ignore everything following the key */
		line[B64KEYLEN] = '\0';

		if (base64_pton(line, key, KEYLEN) == -1) {
			errno = EINVAL;
			rc = -1;
			goto cleanup;
		}

		rc = 1;
		goto cleanup;
	}

cleanup:

	free(line);
	if (ferror(fp)) {
		warn("error reading %s", path);
		rc = -1;
	}

	if (fclose(fp) == EOF) {
		warn("error closing %s", path);
		rc = -1;
	}

	return rc;
}

/*
 * Input must be a nul terminated Base64 or hexadecimal string containing a 256
 * bit key.
 *
 * Return -1 on error.
 */
static int
parsekey(wskey dst, const char *src, size_t srcsize)
{
	if (srcsize == 64) {
		if (readhexnomem(dst, KEYLEN, src, 64) == -1)
			return -1;
	} else if (srcsize == 44) {
		if (base64_pton(src, dst, KEYLEN) == -1)
			return -1;
	} else
		return -1;

	return 0;
}

/*
 * Try to load a private or pre-shared key from a default path.
 *
 * If both "ifname" and "peername" are not NULL an interface bound peer specific
 * per-shared key is tried.
 * If "ifname" and "peername" are both NULL the default path for a global pre-
 * shared key is tried.
 * If "ifname" is NULL and "peername" is not NULL a peer specific pre-shared key
 * is tried.
 * If "peername" is NULL and "ifname" is not NULL an interface key path is
 * tried. In this case "ext" indicates whether to try a private key or a pre-
 * shared key by being either "key" or "psk", respectively.
 *
 * Returns 1 if a key was found and parsed into "out".
 * Returns 0 if the default path existed and had no syntax errors, but alsno no
 * key.
 * Returns -1 if an error occurred while opening the default path, errno will be
 * set to any error that open(2) can set.
 * Returns -2 if parsekeyfile() returned an error, in this case errno will *not*
 * be set.
 * Returns -3 if "ext" is not one of NULL, "psk" or "key".
 *
 * Exits on asprintf(3) error.
 */
static int
xtrydefaultkey(wskey out, const char *ifname, const char *peername,
    const char *ext)
{
	char *defaultkeypath;
	int d, rc;

	if (ifname && peername) {
		if (asprintf(&defaultkeypath, "/etc/wiresep/%s.%s.psk", ifname,
		    peername) < 0)
			errx(1, "could not allocate default interface bound "
			    "peer specific key path");
	} else if (ifname) {
		if (ext == NULL)
			return -3;

		if (strcmp(ext, "psk") != 0 && strcmp(ext, "key") != 0)
			return -3;

		if (asprintf(&defaultkeypath, "/etc/wiresep/%s.%s", ifname, ext)
		    < 0)
			errx(1, "could not allocate default interface specific "
			    "key path");
	} else if (peername) {
		if (asprintf(&defaultkeypath, "/etc/wiresep/%s.psk", peername)
		    < 0)
			errx(1, "could not allocate default peer specific key "
			    "path");
	} else {
		if (asprintf(&defaultkeypath, "/etc/wiresep/global.psk") < 0)
			errx(1, "could not allocate default peer specific key "
			    "path");
	}

	d = open(defaultkeypath, O_RDONLY);

	if (d == -1) {
		/* errno set */
		free(defaultkeypath);
		return -1;
	} else {
		close(d);
		rc = parsekeyfile(out, defaultkeypath);
		free(defaultkeypath);

		if (rc == -1)
			return -2;

		return rc;
	}
}

/*
 * Get the number of the name of a tunnel interface.
 *
 * Returns the number of the tunnel interface on success, or -1 on failure.
 */
static int
gettunnum(const char *name)
{
	int tunnum;
	char c;

	if (sscanf(name, "tun%d%c", &tunnum, &c) != 1)
		return -1;

	return tunnum;
}

/*
 * Make sure the interface name is in the form tunDDD where DDD is one to three
 * digits.
 *
 * Return 1 if valid, 0 if invalid.
 */
static int
validinterfacename(const char *name)
{
	if (gettunnum(name) == -1)
		return 0;

	return 1;
}

/*
 * Make sure the peer name contains no non-graphical characters, no '/' and
 * does not constitute an interface name or the word "global".
 *
 * Return 1 if valid, 0 if invalid.
 */
static int
validpeername(const char *name)
{
	size_t i, len;

	len = strlen(name);

	if (len == 0)
		return 0;

	if (strcasecmp(name, "global") == 0)
		return 0;

	if (validinterfacename(name))
		return 0;

	/* no path separators */
	if (strchr(name, '/') != NULL)
		return 0;

	for (i = 0; i < len; i++)
		if (!isgraph(name[i]))
			return 0;

	return 1;
}

/*
 * Parse a peer config.
 *
 * Return 0 on success, -1 on error.
 */
static int
parsepeerconfig(struct cfgpeer *peer, const struct scfge *cfg, int peernumber,
    const struct cfgifn *ifn)
{
	struct cfgcidraddr *allowedip;
	struct scfge *subcfg;
	const char *key, *peerid;
	size_t i, j;
	int e, rc, explicitpeername;

	if (cfg == NULL || cfg->strvsize < 1)
		return -1;
	if (strcasecmp("peer", cfg->strv[0]) != 0)
		return -1;

	explicitpeername = 0;

	/*
	 * Use optional peer name or a default until the public key is
	 * encountered.
	 */
	if (cfg->strvsize >= 2) {
		if (validpeername(cfg->strv[1])) {
			strlcpy(peer->name, cfg->strv[1], sizeof(peer->name));
			explicitpeername = 1;
		} else {
			warnx("%s: invalid peer name. Peer name may not be the "
			    "word \"global\", be an interface name, contain a "
			    "'/' or any non-graphical character", peer->name);
			e = 1;
		}
	} else {
		snprintf(peer->name, sizeof(peer->name), "peer%d", peernumber);
	}

	peerid = peer->name;

	e = 0;
	for (i = 0; i < cfg->entryvsize; i++) {
		subcfg = cfg->entryv[i];

		if (subcfg->strvsize < 1) {
			assert(subcfg->entryvsize > 0);
			warnx("%s: no blocks allowed in a peer block",
			    peerid);
			e = 1;
			continue;
		}

		key = subcfg->strv[0];

		if (key == NULL) {
			assert(subcfg->entryvsize > 0);
			warnx("%s: peer block may not contain another "
			    "block", peerid);
			e = 1;
			continue;
		}

		if (subcfg->entryvsize > 0) {
			warnx("%s: %s may not have a block associated",
			    peerid, key);
			e = 1;
			/* check other keywords */
		}

		if (strcasecmp("pubkey", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("%s: %s missing public key", peerid,
				    key);
				e = 1;
				continue;
			}
			if (parsekey(peer->pubkey, subcfg->strv[1],
			    strlen(subcfg->strv[1])) == -1) {
				warnx("peer public key must be Base64 or "
				    "hexadecimal");
				return -1;
			}
			if (cfg->strvsize < 2) {
				/* Use public key as peer name since the user
				 * did not provide a name
				 */
				strlcpy(peer->name, subcfg->strv[1],
				    sizeof(peer->name));
			}
		} else if (strcasecmp("endpoint", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("%s: %s must have an address and port "
				    "separated by a colon", peerid, key);
				e = 1;
				continue;
			}
			if (parseaddrport(&peer->fsa, subcfg->strv[1]) == -1) {
				warnx("%s: %s parse error: %s. Make sure the "
				    "address and port are separated by a colon"
				    , peerid, key, subcfg->strv[1]);
				e = 1;
				continue;
			}
		} else if (strcasecmp("allowedips", key) == 0) {
			if (subcfg->strvsize < 2) {
				warnx("%s: %s must contain at least one "
				    "ip/mask", peerid, key);
				e = 1;
				continue;
			}
			for (j = 1; j < subcfg->strvsize; j++) {
				if (strcmp(subcfg->strv[j], "*") == 0) {
					xaddone((void ***)&peer->allowedips,
					    &peer->allowedipssize,
					    (void **)&allowedip,
					    sizeof(*allowedip));

					if (parseipcidr(&allowedip->addr,
					    &allowedip->prefixlen, "0.0.0.0/0")
					    == -1)
						abort();

					xaddone((void ***)&peer->allowedips,
					    &peer->allowedipssize,
					    (void **)&allowedip,
					    sizeof(*allowedip));

					if (parseipcidr(&allowedip->addr,
					    &allowedip->prefixlen, "::/0")
					    == -1)
						abort();
				} else {
					xaddone((void ***)&peer->allowedips,
					    &peer->allowedipssize,
					    (void **)&allowedip,
					    sizeof(*allowedip));

					if (parseipcidr(&allowedip->addr,
					    &allowedip->prefixlen,
					    subcfg->strv[j]) == -1) {
						warnx("%s: %s could not parse "
						    "ip: %s", peerid, key,
						    subcfg->strv[j]);
						e = 1;
						continue;
					}
				}
			}
		} else if (strcasecmp("psk", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("%s: %s must have a value", peerid,
				    key);
				e = 1;
				continue;
			}
			if (parsekey(peer->psk, subcfg->strv[1],
			    strlen(subcfg->strv[1])) == -1) {
				warnx("%s: %s could not parse pre-sharedkey",
				    peerid, key);
				e = 1;
				continue;
			}
		} else if (strcasecmp("pskfile", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("%s: %s path missing", peerid, key);
				e = 1;
				continue;
			}
			if ((peer->pskfile = strdup(subcfg->strv[1])) == NULL)
				err(1, "strdup peer pskfile");
		} else {
			warnx("%s: %s invalid keyword in peer scope", peerid,
			    key);
			e = 1;
		}
	}

	/*
	 * Ensure defaults.
	 */

	if (memcmp(peer->psk, nullkey, sizeof(wskey)) == 0) {
		if (peer->pskfile != NULL) {
			rc = parsekeyfile(peer->psk, peer->pskfile);
			if (rc == -1) {
				warnx("%s: could not parse peer pskfile: %s",
				    peerid, peer->pskfile);
				e = 1;
			} else if (rc == 0) {
				warnx("%s: could not find a key in peer pskfile"
				    ": %s", peerid, peer->pskfile);
				e = 1;
			}
		} else if (explicitpeername) {
			/*
			 * Look for an interface bound peer specific pre-shared
			 * key.
			 */
			rc = xtrydefaultkey(peer->psk, ifn->ifname, peer->name,
			    NULL);

			if (rc == 1) {
				/* key loaded! */
			} else if ((rc == -1 && errno == ENOENT) || rc == 0) {
				/*
				 * No key found, try a global peer specific key.
				 */
				rc = xtrydefaultkey(peer->psk, NULL, peer->name,
				    NULL);

				if (rc == 1) {
					/* key loaded! */
				} else if (rc == 0) {
					/* no key found, be silent */
				} else if (rc == -1 && errno == ENOENT) {
					/* no key found, be silent */
				} else if (rc == -1) {
					warn("could not load default peer "
					    "specific pre-shared key file: %s",
					    peer->name);
					e = 1;
				} else if (rc == -2) {
					warnx("could not parse default peer "
					    "specific pre-shared key file: %s",
					    peer->name);
					e = 1;
				} else if (rc == -3) {
					warnx("xtrydefaultkey peer pre-shared "
					    "key file error %s", peer->name);
					e = 1;
				}
			} else if (rc == -1 && errno != ENOENT) {
				warn("could not load default interface bound "
				    "peer specific pre-shared key file: %s %s",
				    ifn->ifname, peer->name);
				e = 1;
			} else if (rc == -2) {
				warnx("could not parse default interface bound"
				    " peer specific pre-shared key file: %s %s",
				    ifn->ifname, peer->name);
				e = 1;
			} else if (rc == -3) {
				warnx("%s: xtrydefaultkey peer pre-shared key "
				    "file error %s", ifn->ifname, peer->name);
				e = 1;
			}
		}
	}

	/* if still no pre-shared key, try to use the default one */
	if (memcmp(peer->psk, nullkey, sizeof(wskey)) == 0)
		memcpy(peer->psk, ifn->psk, sizeof(wskey));

	if (peer->allowedipssize == 0) {
		warnx("%s: allowedips missing", peerid);
		e = 1;
	}

	if (memcmp(peer->pubkey, nullkey, sizeof(wskey)) == 0) {
		warnx("%s: pubkey missing", peerid);
		e = 1;
	}

	if (e != 0)
		return -1;

	return 0;
}

/*
 * Parse all interface configs. "ifnv" must be pre-allocated.
 *
 * In a first pass determine all interface settings and in a second pass
 * parse all peer specific settings.
 *
 * Return 0 on success, -1 on error.
 */
static int
parseinterfaceconfigs(void)
{
	struct scfge *subcfg;
	struct cfgifn *ifn;
	struct cfgpeer *peer;
	struct cfgcidraddr *ifaddr;
	struct sockaddr_storage listenaddr;
	struct sockaddr_in6 *laddrs6;
	struct sockaddr_in *laddrs4;
	struct stat st;
	const char *key;
	char tundevpath[29];
	size_t i, j, n;
	int e, rc, tunnum;

	e = 0;
	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];

		if (ifn->scfge->strvsize != 2) {
			warnx("interface keyword must be followed by the"
			    " interface name and then a block");
			e = 1;
			continue;
		}

		assert(strcasecmp("interface", ifn->scfge->strv[0]) == 0);

		tunnum = gettunnum(ifn->scfge->strv[1]);
		if (tunnum == -1) {
			warnx("interface name must be a device name like tun0 "
			    "or tun2: %s", ifn->scfge->strv[1]);
			e = 1;
			continue;
		}

		for (i = 0; i < n; i++) {
			if (ifnv[i]->ifname &&
			    strcmp(ifn->scfge->strv[1], ifnv[i]->ifname) == 0) {
				warnx("interface name is not unique: %s",
				    ifn->scfge->strv[1]);
				e = 1;
				continue;
			}
		}

		if (snprintf(tundevpath, sizeof(tundevpath), "/dev/%s",
		    ifn->scfge->strv[1]) < 9)
			errx(1, "snprintf tundevpath");

		if (stat(tundevpath, &st) == -1) {
			warn("%s", tundevpath);
			e = 1;
			continue;
		}
		if (st.st_uid != 0) {
			warnx("%s: not owned by the superuser", tundevpath);
			e = 1;
			continue;
		}
		if (!S_ISCHR(st.st_mode)) {
			warnx("%s: not a device file", tundevpath);
			e = 1;
			continue;
		}

		if ((ifn->ifname = strdup(ifn->scfge->strv[1])) == NULL)
			err(1, "strdup ifname");

		for (i = 0; i < ifn->scfge->entryvsize; i++) {
			subcfg = ifn->scfge->entryv[i];

			if (subcfg->strvsize < 1) {
				assert(subcfg->entryvsize > 0);
				warnx("%s: blocks within an interface block "
				    "must be prefixed with a peer key",
				    ifn->ifname);
				e = 1;
				continue;
			}

			key = subcfg->strv[0];

			if (strcasecmp("peer", key) != 0) {
				if (subcfg->entryvsize > 0) {
					warnx("%s: %s may not have a block "
					    "associated", ifn->ifname, key);
					e = 1;
					/* check other keywords first */
				}
			}

			if (strcasecmp("user", key) == 0) {
				if (subcfg->strvsize != 2) {
					warnx("%s: %s must contain one name "
					    "or uid",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
				if (resolveuser(&ifn->uid, &ifn->gid,
				    subcfg->strv[1]) == -1) {
					warnx("%s: %s invalid: %s",
					    ifn->ifname, key, subcfg->strv[1]);
					e = 1;
					continue;
				}
			} else if (strcasecmp("group", key) == 0) {
				if (subcfg->strvsize != 2) {
					warnx("%s: %s must contain one name "
					    "or gid",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
				if (resolvegroup(&ifn->gid, subcfg->strv[1])
				    == -1) {
					warnx("%s: %s invalid: %s",
					    ifn->ifname, key, subcfg->strv[1]);
					e = 1;
					continue;
				}
			} else if (strcasecmp("ifaddr", key) == 0) {
				if (subcfg->strvsize < 2) {
					warnx("%s: %s must have at least"
					    " one argument", ifn->ifname, key);
					e = 1;
					continue;
				}
				for (j = 1; j < subcfg->strvsize; j++) {
					xaddone((void ***)&ifn->ifaddrs,
					    &ifn->ifaddrssize, (void **)&ifaddr,
					    sizeof(*ifaddr));

					if (parseipcidr(&ifaddr->addr,
					    &ifaddr->prefixlen,
					    subcfg->strv[j]) == -1) {
						warnx("%s: %s could not "
						    "parse interface address: "
						    "%s", ifn->ifname, key,
						    subcfg->strv[j]);
						e = 1;
						continue;
					}
				}
			} else if (strcasecmp("psk", key) == 0) {
				if (subcfg->strvsize != 2) {
					warnx("%s: %s must have a value",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
				if (parsekey(ifn->psk, subcfg->strv[1],
				    strlen(subcfg->strv[1])) == -1) {
					warnx("%s: %s could not parse the "
					    "interface pre-sharedkey",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
			} else if (strcasecmp("pskfile", key) == 0) {
				if (subcfg->strvsize != 2) {
					warnx("%s: %s path missing",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
				if ((ifn->pskfile = strdup(subcfg->strv[1]))
				    == NULL)
					err(1, "strdup ifn pskfile");
			} else if (strcasecmp("privkey", key) == 0) {
				if (subcfg->strvsize != 2) {
					warnx("%s: %s must have a value",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
				if (parsekey(ifn->privkey, subcfg->strv[1],
				    strlen(subcfg->strv[1])) == -1) {
					warnx("%s: %s could not parse the "
					    "interface private key",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
			} else if (strcasecmp("privkeyfile", key) == 0) {
				if (subcfg->strvsize != 2) {
					warnx("%s: %s path missing",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
				if ((ifn->privkeyfile = strdup(subcfg->strv[1]))
				    == NULL)
					err(1, "strdup ifn privkeyfile");
			} else if (strcasecmp("desc", key) == 0) {
				if (subcfg->strvsize != 2) {
					warnx("%s: %s must have a value",
					    ifn->ifname, key);
					e = 1;
					continue;
				}

				if ((ifn->ifdesc = strdup(subcfg->strv[1]))
				    == NULL)
					err(1, "strdup ifdesc");
			} else if (strcasecmp("listen", key) == 0) {
				if (subcfg->strvsize < 2) {
					warnx("%s: %s must have at least one "
					    "address and port, separated by a "
					    "colon", ifn->ifname, key);
					e = 1;
					continue;
				}
				for (j = 1; j < subcfg->strvsize; j++) {
					if (parseaddrport(&listenaddr,
					    subcfg->strv[j]) == -1) {
						warnx("%s: %s parse error: %s. Make "
						    "sure the address and port are "
						    "separated by a colon", ifn->ifname,
						    key, subcfg->strv[j]);
						e = 1;
						continue;
					}

					if (listenaddr.ss_family == AF_INET6) {
						laddrs6 = reallocarray(ifn->laddrs6,
						    ifn->laddrs6count + 1,
						    sizeof(struct sockaddr_in6));

						if (laddrs6 == NULL) {
							warn("%s: %s "
							    "reallocarray error"
							    " %s", ifn->ifname,
							    key, subcfg->strv[j]);
							e = 1;
							continue;
						}

						memcpy(&laddrs6[ifn->laddrs6count],
						    &listenaddr,
						    sizeof(struct sockaddr_in6));

						ifn->laddrs6 = laddrs6;
						ifn->laddrs6count++;
					} else if (listenaddr.ss_family == AF_INET) {
						laddrs4 = reallocarray(ifn->laddrs4,
						    ifn->laddrs4count + 1,
						    sizeof(struct sockaddr_in));

						if (laddrs4 == NULL) {
							warn("%s: %s "
							    "reallocarray error"
							    " %s", ifn->ifname,
							    key, subcfg->strv[j]);
							e = 1;
							continue;
						}

						memcpy(&laddrs4[ifn->laddrs4count],
						    &listenaddr,
						    sizeof(struct sockaddr_in));

						ifn->laddrs4 = laddrs4;
						ifn->laddrs4count++;
					} else {
						warn("%s: %s "
						    "specify an IPv6 or IPv4 "
						    "address %s", ifn->ifname,
						    key, subcfg->strv[j]);
						e = 1;
						continue;
					}
				}
			} else if (strcasecmp("peer", key) == 0) {
				/*
				 * Skip for now, first process all interface
				 * keywords.
				 */
			} else {
				warnx("%s: %s invalid keyword in interface "
				    "scope", ifn->ifname, key);
				e = 1;
			}
		}

		/*
		 * Ensure defaults.
		 */

		if (memcmp(ifn->psk, nullkey, sizeof(wskey)) == 0) {
			if (ifn->pskfile != NULL) {
				rc = parsekeyfile(ifn->psk, ifn->pskfile);
				if (rc == -1) {
					warnx("%s: could not parse interface "
					    "pskfile", ifn->pskfile);
					e = 1;
				} else if (rc == 0) {
					warnx("%s: could not find a key in "
					    "interface pskfile", ifn->pskfile);
					e = 1;
				}
			} else if (ifn->ifname) {
				/*
				 * Look for an interface pre-shared key.
				 */
				rc = xtrydefaultkey(ifn->psk, ifn->ifname,
				    NULL, "psk");

				if (rc == 1) {
					/* key loaded! */
				} else if (rc == 0) {
					/* no key found, be silent */
				} else if (rc == -1 && errno == ENOENT) {
					/* no key found, be silent */
				} else if (rc == -1) {
					warn("%s: could not load default "
					    "interface pre-shared key file",
					    ifn->ifname);
					e = 1;
				} else if (rc == -2) {
					warnx("%s: could not parse default "
					    "interface pre-shared key file",
					    ifn->ifname);
					e = 1;
				} else if (rc == -3) {
					warnx("%s: xtrydefaultkey pre-shared "
					    "key file error", ifn->ifname);
					e = 1;
				}
			}
		}

		/* if still no pre-shared key, try to use a global one */
		if (memcmp(ifn->psk, nullkey, sizeof(wskey)) == 0)
			memcpy(ifn->psk, gpsk, sizeof(wskey));

		if (memcmp(ifn->privkey, nullkey, sizeof(wskey)) == 0) {
			if (ifn->privkeyfile != NULL) {
				rc = parsekeyfile(ifn->privkey, ifn->privkeyfile);
				if (rc == -1) {
					warnx("%s: could not parse interface "
					    "privkeyfile", ifn->privkeyfile);
					e = 1;
				} else if (rc == 0) {
					warnx("%s: could not find a key in "
					    "interface privkeyfile", ifn->privkeyfile);
					e = 1;
				}
			} else if (ifn->ifname) {
				/*
				 * Look for an interface private key.
				 */
				rc = xtrydefaultkey(ifn->privkey, ifn->ifname,
				    NULL, "key");

				if (rc == 1) {
					/* key loaded! */
				} else if (rc == 0) {
					/* no key found, be silent */
				} else if (rc == -1 && errno == ENOENT) {
					warnx("%s: privkeyfile not set and "
					    "default private key file does not "
					    "exist", ifn->ifname);
					e = 1;
				} else if (rc == -1) {
					warn("%s: could not load default "
					    "interface private key file",
					    ifn->ifname);
					e = 1;
				} else if (rc == -2) {
					warnx("%s: could not parse default "
					    "interface private key file",
					    ifn->ifname);
					e = 1;
				} else if (rc == -3) {
					warnx("%s: xtrydefaultkey private "
					    "key file error", ifn->ifname);
					e = 1;
				}
			}
		}

		if (ifn->uid == 0)
			ifn->uid = guid;

		if (ifn->gid == 0)
			ifn->gid = ggid;

		/*
		 * Check requirements.
		 */

		if (ifn->ifname == NULL) {
			warnx("interface device name missing");
			e = 1;
		}

		if (memcmp(ifn->privkey, nullkey, sizeof(wskey)) == 0) {
			warnx("%s: privkey missing", ifn->ifname);
			e = 1;
		} else {
			/* calculate public key */
			if (X25519(ifn->pubkey, ifn->privkey, basepoint) == 0) {
				warnx("%s: could determine the interface public"
				    " key", ifn->ifname);
				e = 1;
			}
		}

		/* default interface description to the public key */
		if (memcmp(ifn->pubkey, nullkey, sizeof(wskey)) != 0) {
			if (ifn->ifdesc == NULL) {
				if ((ifn->ifdesc = calloc(1, MAXIFNDESC))
				    == NULL)
					err(1, "calloc ifdesc");

				if (base64_ntop(ifn->pubkey, KEYLEN,
				    ifn->ifdesc, MAXIFNDESC) == -1)
					return -1;
			}
		}

		/*
		 * Now that the whole interface is processed, process all peers.
		 */

		for (i = 0; i < ifn->scfge->entryvsize; i++) {
			subcfg = ifn->scfge->entryv[i];

			if (subcfg->strvsize < 1 ||
			    strcasecmp("peer", subcfg->strv[0]) != 0)
				continue;

			if (subcfg->strvsize > 2) {
				warnx("%s: %s extra peer information must be "
				    "grouped in a block \"peer %s %s\"",
				    ifn->ifname, "peer", subcfg->strv[1],
				    subcfg->strv[2]);
				e = 1;
				continue;
			}

			xaddone((void ***)&ifn->peers, &ifn->peerssize,
			    (void **)&peer, sizeof(*peer));

			if (parsepeerconfig(peer, subcfg, ifn->peerssize, ifn)
			    == -1) {
				e = 1;
				continue;
			}
		}

		if (ifn->laddrs6count > MAXLISTEN6 ||
		    ifn->laddrs4count > MAXLISTEN4) {
			warnx("%s: only %d v6 and %d v4 addressess may be "
			    "configured", ifn->ifname, MAXLISTEN6, MAXLISTEN4);
			e = 1;
		}

		if (ifn->peerssize == 0)
			warnx("%s: has no peers configured", ifn->ifname);

		if (e)
			continue;

		/*
		 * TODO if a wildcard is used, resolve all addresses on all
		 * interfaces. For now just print a warning.
		 */
		for (i = 0; i < ifn->laddrs6count; i++) {
			if (memcmp(&ifn->laddrs6[i].sin6_addr,
			    &in6addr_any, sizeof in6addr_any) == 0 &&
			    ntohs(ifn->laddrs6[i].sin6_port) >= IPPORT_RESERVED)
				warnx("using a wildcard address with a non-"
				    "reserved port makes us vulnerable to a DoS"
				    " by a local system user");
		}

		for (i = 0; i < ifn->laddrs4count; i++) {
			if (ifn->laddrs4[i].sin_addr.s_addr == INADDR_ANY &&
			    ntohs(ifn->laddrs4[i].sin_port) >= IPPORT_RESERVED)
				warnx("using a wildcard address with a non-"
				    "reserved port makes us vulnerable to a DoS"
				    " by a local system user");
		}

		/* unlink */
		ifn->scfge = NULL;
	}

	if (e != 0)
		return -1;

	return 0;
}

/*
 * Parse the complete comfig and allocate new ifn structures in "ifnv".
 *
 * In a first pass determine all global settings and in a second pass
 * create interfaces with peer specific settings.
 *
 * Return 0 on success, -1 on error.
 */
static int
parseconfig(const struct scfge *root)
{
	struct scfge *subcfg;
	struct cfgifn *ifn;
	const char *key;
	size_t n;
	int e, rc;

	e = 0;
	for (n = 0; n < root->entryvsize; n++) {
		subcfg = scfg->entryv[n];

		if (subcfg->strvsize < 1) {
			assert(subcfg->entryvsize > 0);
			warnx("each global block must be prefixed with an "
			    "interface name");
			e = 1;
			continue;
		}

		key = subcfg->strv[0];

		if (strcasecmp("interface", key) != 0) {
			if (subcfg->entryvsize > 0) {
				warnx("global %s may not have a block "
				    "associated", key);
				e = 1;
				/* check other keywords first */
			}
		}

		if (strcasecmp("log", key) == 0) {
			if (subcfg->strvsize != 3) {
				warnx("%s: %s must contain one facility or file"
				    " name",
				    "global", key);
				e = 1;
				continue;
			}
			/*
			 * Second level must be a log facility, we might
			 * support "file" in the future.
			 */
			if (strcasecmp(subcfg->strv[1], "facility") == 0) {
				if (facilitystrtoint(&logfacility,
				    subcfg->strv[2]) == -1) {
					warnx("%s: invalid log facility: %s",
					    "global", subcfg->strv[2]);
					e = 1;
					continue;
				}
				if ((logfacilitystr = strdup(subcfg->strv[2]))
				    == NULL)
					err(1, "strdup log facility");
			} else if (strcasecmp(subcfg->strv[1], "file") == 0) {
				/* XXX */
				warnx("%s: %s file not implemented",
				    "global", key);
				e = 1;
				continue;
			} else {
				warnx("%s: %s must define a facility",
				    "global", key);
				e = 1;
				continue;
			}
		} else if (strcasecmp("user", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("%s: %s must contain one name "
				    "or uid",
				    "global", key);
				e = 1;
				continue;
			}
			if (guser) {
				warnx("global user can be set only once");
				e = 1;
				continue;
			}
			guser = subcfg->strv[1];
		} else if (strcasecmp("group", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("%s: %s must contain one name "
				    "or gid",
				    "global", key);
				e = 1;
				continue;
			}
			if (ggroup != NULL) {
				warnx("global group can be set only once");
				e = 1;
				continue;
			}
			ggroup = subcfg->strv[1];
		} else if (strcasecmp("psk", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("psk must have one value");
				e = 1;
				continue;
			}
			if (memcmp(gpsk, nullkey, sizeof(wskey)) != 0) {
				warnx("global psk can be set only once");
				e = 1;
				continue;
			}
			if (parsekey(gpsk, subcfg->strv[1],
			    strlen(subcfg->strv[1])) == -1) {
				warnx("could not parse the global "
				    "pre-sharedkey");
				e = 1;
				continue;
			}
		} else if (strcasecmp("pskfile", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("%s: %s path missing", "global", key);
				e = 1;
				continue;
			}
			if ((gpskfile = strdup(subcfg->strv[1])) == NULL)
				err(1, "strdup global pskfile");
		} else if (strcasecmp("interface", key) == 0) {
			xaddone((void ***)&ifnv, &ifnvsize, (void **)&ifn,
			    sizeof(*ifn));
			ifn->scfge = subcfg;
		} else {
			warnx("invalid keyword in the global scope: %s", key);
			e = 1;
		}
	}

	/*
	 * Ensure defaults.
	 */

	if (memcmp(gpsk, nullkey, sizeof(wskey)) == 0) {
		if (gpskfile != NULL) {
			rc = parsekeyfile(gpsk, gpskfile);
			if (rc == -1) {
				warnx("%s: could not parse global pskfile",
				    gpskfile);
				e = 1;
			} else if (rc == 0) {
				warnx("%s: could not find a key in global "
				    "pskfile", gpskfile);
				e = 1;
			}
		} else {
			/*
			 * Look for a global pre-shared key.
			 */
			rc = xtrydefaultkey(gpsk, NULL, NULL, NULL);

			if (rc == 1) {
				/* key loaded! */
			} else if (rc == 0) {
				/* no key found, be silent */
			} else if (rc == -1 && errno == ENOENT) {
				/* no key found, be silent */
			} else if (rc == -1) {
				warn("could not load default global pre-shared "
				    "key file");
				e = 1;
			} else if (rc == -2) {
				warnx("could not parse default global pre-"
				    "shared key file");
				e = 1;
			} else if (rc == -3) {
				warnx("xtrydefaultkey global pre-shared key "
				    "file error");
				e = 1;
			}
		}
	}

	if (!guser)
		guser = DFLUSER;

	if (resolveuser(&guid, &ggid, guser) == -1) {
		warnx("global: user invalid: %s", guser);
		e = 1;
	}

	/* override the group if it is explicitly set */
	if (ggroup) {
		if (resolvegroup(&ggid, ggroup) == -1) {
			warnx("global: group invalid: %s", ggroup);
			e = 1;
		}
	}

	/*
	 * Check requirements.
	 */

	if (guid == 0) {
		warnx("global user id may not be 0");
		e = 1;
	}
	if (ggid == 0) {
		warnx("global group id may not be 0");
		e = 1;
	}

	if (parseinterfaceconfigs() == -1)
		e = 1;

	if (e != 0)
		return -1;

	return 0;
}

/*
 * Read a config from a file-descriptor and parse it. On success, the result is
 * stored in "rifnv", "rifnvsize", "unprivuid", "unprivgid" and
 * "rlogfacilitystr".
 *
 * yyparse creates a tree of scfg entries.
 *
 * Exit on error.
 */
void
xparseconfigfd(int fd, struct cfgifn ***rifnv, size_t *rifnvsize,
    uid_t *unprivuid, gid_t *unprivgid, char **rlogfacilitystr)
{
	yyd = fd;

	if (yyparse() != 0)
		errx(1, "%s: yyparse", __func__);

	if (parseconfig(scfg) == -1)
		exit(1);

	scfg_clear();

	*rifnv = ifnv;
	*rifnvsize = ifnvsize;
	*unprivuid = guid;
	*unprivgid = ggid;

	if ((*rlogfacilitystr = strdup(logfacilitystr)) == NULL)
		err(1, "%s strdup", __func__);
}

/*
 * Create a list of interfaces plus some global settings. Note that secrets like
 * private keys remain in memory after parsing the configuration so a re-exec(3)
 * is required for safe operation.
 *
 * Exit on error.
 */
void
xparseconfigfile(const char *filename, struct cfgifn ***rifnv,
    size_t *rifnvsize, uid_t *unprivuid, gid_t *unprivgid,
    char **rlogfacilitystr)
{
	int fd;

	if ((fd = open(filename, O_RDONLY|O_CLOEXEC)) == -1)
		err(1, "%s", filename);

	if (!isfdsafe(fd, 0644))
		errx(1, "%s: must be owned by the superuser and may not be"
		    " writable by the group or others", filename);

	xparseconfigfd(fd, rifnv, rifnvsize, unprivuid, unprivgid,
	    rlogfacilitystr);

	if (close(fd) == -1)
		err(1, "close %s", filename);
}

/*
 * Load private keys of all interfaces, determine public key and mac1key.
 */
void
processconfig(void)
{
	struct cfgpeer *peer;
	size_t n, m;

	for (n = 0; n < ifnvsize; n++) {
		if (ws_calcmac1key(ifnv[n]->mac1key, ifnv[n]->pubkey) == -1)
			errx(1, "ws_calcmac1key %zu", n);

		if (ws_calcpubkeyhash(ifnv[n]->pubkeyhash, ifnv[n]->pubkey)
		    == -1)
			errx(1, "ws_calcpubkeyhash %zu", n);

		for (m = 0; m < ifnv[n]->peerssize; m++) {
			peer = ifnv[n]->peers[m];
			if (ws_calcmac1key(peer->mac1key, peer->pubkey) == -1)
				errx(1, "ws_calcmac1key %zu %zu", n, m);
		}
	}
}

/*
 * Send interface info to the proxy.
 *
 * "mast2prox" is used to send the config from this process to the proxy
 * process.
 * "proxwithencl" is the descriptor the proxy process must use to communicate
 * with the enclave.
 *
 * The descriptors the proxy process must use to communicate with
 * each ifn process are in each ifn structure.
 *
 * SINIT
 * SIFN
 *
 * Exit on error.
 */
void
sendconfig_proxy(union smsg smsg, int mast2prox, int proxwithencl)
{
	struct cfgifn *ifn;
	size_t m, n;

	memset(&smsg.init, 0, sizeof(smsg.init));

	smsg.init.background = background;
	smsg.init.verbose = verbose;
	smsg.init.uid = guid;
	smsg.init.gid = ggid;
	smsg.init.enclport = proxwithencl;
	smsg.init.nifns = ifnvsize;

	if (wire_sendmsg(mast2prox, SINIT, &smsg.init, sizeof(smsg.init)) == -1)
		logexitx(1, "%s wire_sendmsg SINIT", __func__);

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];

		memset(&smsg.ifn, 0, sizeof(smsg.ifn));

		smsg.ifn.ifnid = n;
		smsg.ifn.ifnport = ifn->proxwithifn;
		smsg.ifn.laddr6count = ifn->laddrs6count;
		smsg.ifn.laddr4count = ifn->laddrs4count;
		snprintf(smsg.ifn.ifname, sizeof(smsg.ifn.ifname), "%s",
		    ifn->ifname);
		/* don't send interface description to proxy, no public keys in
		 * the proxy process has small benefits because they're
		 * semi-trusted in wireguard.
		 */
		memcpy(smsg.ifn.mac1key, ifn->mac1key,
		    sizeof(smsg.ifn.mac1key));
		memcpy(smsg.ifn.cookiekey, ifn->cookiekey,
		    sizeof(smsg.ifn.cookiekey));
		smsg.ifn.npeers = ifn->peerssize;

		if (wire_sendmsg(mast2prox, SIFN, &smsg.ifn, sizeof(smsg.ifn))
		    == -1)
			logexitx(1, "%s wire_sendmsg SIFN", __func__);

		/* send listen addresses */
		for (m = 0; m < ifn->laddrs6count; m++) {
			memset(&smsg.cidraddr, 0, sizeof smsg.cidraddr);
			smsg.cidraddr.ifnid = n;
			memcpy(&smsg.cidraddr.addr, &ifn->laddrs6[m],
			    sizeof ifn->laddrs6[m]);

			if (wire_sendmsg(mast2prox, SCIDRADDR, &smsg.cidraddr,
			    sizeof smsg.cidraddr) == -1)
				logexitx(1, "%s wire_sendmsg SCIDRADDR",
				    __func__);
		}

		for (m = 0; m < ifn->laddrs4count; m++) {
			memset(&smsg.cidraddr, 0, sizeof smsg.cidraddr);
			smsg.cidraddr.ifnid = n;
			memcpy(&smsg.cidraddr.addr, &ifn->laddrs4[m],
			    sizeof ifn->laddrs4[m]);

			if (wire_sendmsg(mast2prox, SCIDRADDR, &smsg.cidraddr,
			    sizeof smsg.cidraddr) == -1)
				logexitx(1, "%s wire_sendmsg SCIDRADDR",
				    __func__);
		}
	}

	/* wait with end of startup signal */

	explicit_bzero(&smsg, sizeof(smsg));

	loginfox("config sent to proxy %d", mast2prox);
}

/*
 * Send interface info to the enclave.
 *
 * SINIT
 * SIFN
 * SPEER
 *
 * Exit on error.
 */
void
sendconfig_enclave(union smsg smsg, int mast2encl, int enclwithprox)
{
	struct cfgifn *ifn;
	struct cfgpeer *peer;
	size_t n, m;

	memset(&smsg.init, 0, sizeof(smsg.init));

	smsg.init.background = background;
	smsg.init.verbose = verbose;
	smsg.init.uid = guid;
	smsg.init.gid = ggid;
	smsg.init.proxport = enclwithprox;
	smsg.init.nifns = ifnvsize;

	if (wire_sendmsg(mast2encl, SINIT, &smsg.init, sizeof(smsg.init)) == -1)
		logexitx(1, "%s wire_sendmsg SINIT", __func__);

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];

		memset(&smsg.ifn, 0, sizeof(smsg.ifn));

		smsg.ifn.ifnid = n;
		smsg.ifn.ifnport = ifn->enclwithifn;
		snprintf(smsg.ifn.ifname, sizeof(smsg.ifn.ifname), "%s",
		    ifn->ifname);
		if (ifn->ifdesc && strlen(ifn->ifdesc) > 0)
			snprintf(smsg.ifn.ifdesc, sizeof(smsg.ifn.ifdesc), "%s",
			    ifn->ifdesc);
		memcpy(smsg.ifn.privkey, ifn->privkey,
		    sizeof(smsg.ifn.privkey));
		memcpy(smsg.ifn.pubkey, ifn->pubkey, sizeof(smsg.ifn.pubkey));
		memcpy(smsg.ifn.pubkeyhash, ifn->pubkeyhash,
		    sizeof(smsg.ifn.pubkeyhash));
		memcpy(smsg.ifn.mac1key, ifn->mac1key,
		    sizeof(smsg.ifn.mac1key));
		memcpy(smsg.ifn.cookiekey, ifn->cookiekey,
		    sizeof(smsg.ifn.cookiekey));
		smsg.ifn.npeers = ifn->peerssize;

		if (wire_sendmsg(mast2encl, SIFN, &smsg.ifn, sizeof(smsg.ifn))
		    == -1)
			logexitx(1, "%s wire_sendmsg SIFN", __func__);

		for (m = 0; m < ifn->peerssize; m++) {
			peer = ifn->peers[m];

			memset(&smsg.peer, 0, sizeof(smsg.peer));

			smsg.peer.ifnid = n;
			smsg.peer.peerid = m;

			memcpy(smsg.peer.psk, peer->psk, sizeof(smsg.peer.psk));
			memcpy(smsg.peer.peerkey, peer->pubkey,
			    sizeof(smsg.peer.peerkey));
			memcpy(smsg.peer.mac1key, peer->mac1key,
			    sizeof(smsg.peer.mac1key));

			if (wire_sendmsg(mast2encl, SPEER, &smsg.peer,
			    sizeof(smsg.peer)) == -1)
				logexitx(1, "%s wire_sendmsg SPEER %zu",
				    __func__, m);
		}
	}

	/* wait with end of startup signal */

	explicit_bzero(&smsg, sizeof(smsg));

	loginfox("config sent to enclave %d", mast2encl);
}

/*
 * Send interface info to an ifn process.
 *
 * SINIT
 * SIFN
 * SPEER
 * SCIDRADDR
 *
 * Exit on error.
 */
void
sendconfig_ifn(union smsg smsg, int ifnid)
{
	struct cfgcidraddr *allowedip;
	struct cfgcidraddr *ifaddr;
	struct cfgifn *ifn;
	struct cfgpeer *peer;
	size_t m, n;

	if (ifnid < 0)
		logexitx(1, "%s", __func__);
	if ((size_t)ifnid >= ifnvsize)
		logexitx(1, "%s", __func__);

	ifn = ifnv[ifnid];

	memset(&smsg.init, 0, sizeof(smsg.init));

	smsg.init.background = background;
	smsg.init.verbose = verbose;
	smsg.init.uid = ifn->uid;
	smsg.init.gid = ifn->gid;
	smsg.init.enclport = ifn->ifnwithencl;
	smsg.init.proxport = ifn->ifnwithprox;

	if (wire_sendmsg(ifn->mastwithifn, SINIT, &smsg.init, sizeof(smsg.init))
	    == -1)
		logexitx(1, "%s wire_sendmsg SINIT %d", __func__,
		    ifn->mastwithifn);

	memset(&smsg.ifn, 0, sizeof(smsg.ifn));

	smsg.ifn.ifnid = ifnid;
	snprintf(smsg.ifn.ifname, sizeof(smsg.ifn.ifname), "%s", ifn->ifname);
	if (ifn->ifdesc && strlen(ifn->ifdesc) > 0)
		snprintf(smsg.ifn.ifdesc, sizeof(smsg.ifn.ifdesc), "%s",
		    ifn->ifdesc);
	memcpy(smsg.ifn.mac1key, ifn->mac1key, sizeof(smsg.ifn.mac1key));
	memcpy(smsg.ifn.cookiekey, ifn->cookiekey, sizeof(smsg.ifn.cookiekey));
	smsg.ifn.nifaddrs = ifn->ifaddrssize;
	smsg.ifn.laddr6count = ifn->laddrs6count;
	smsg.ifn.laddr4count = ifn->laddrs4count;
	smsg.ifn.npeers = ifn->peerssize;

	if (wire_sendmsg(ifn->mastwithifn, SIFN, &smsg.ifn, sizeof(smsg.ifn))
	    == -1)
		logexitx(1, "%s wire_sendmsg SIFN %s", __func__, ifn->ifname);

	/* first send interface addresses */
	for (n = 0; n < ifn->ifaddrssize; n++) {
		ifaddr = ifn->ifaddrs[n];

		memset(&smsg.cidraddr, 0, sizeof(smsg.cidraddr));

		smsg.cidraddr.ifnid = ifnid;
		smsg.cidraddr.prefixlen = ifaddr->prefixlen;
		memcpy(&smsg.cidraddr.addr, &ifaddr->addr,
		    sizeof(smsg.cidraddr.addr));

		if (wire_sendmsg(ifn->mastwithifn, SCIDRADDR, &smsg.cidraddr,
		    sizeof(smsg.cidraddr)) == -1)
			logexitx(1, "%s wire_sendmsg interface SCIDRADDR",
			    __func__);
	}

	/* then listen addresses */
	for (n = 0; n < ifn->laddrs6count; n++) {
		memset(&smsg.cidraddr, 0, sizeof smsg.cidraddr);

		smsg.cidraddr.ifnid = ifnid;
		memcpy(&smsg.cidraddr.addr, &ifn->laddrs6[n],
		    sizeof ifn->laddrs6[n]);

		if (wire_sendmsg(ifn->mastwithifn, SCIDRADDR, &smsg.cidraddr,
		    sizeof smsg.cidraddr) == -1)
			logexitx(1, "%s wire_sendmsg local addr %d out of %zu",
			    __func__, n, ifn->laddrs6count);
	}

	for (n = 0; n < ifn->laddrs4count; n++) {
		memset(&smsg.cidraddr, 0, sizeof smsg.cidraddr);

		smsg.cidraddr.ifnid = ifnid;
		memcpy(&smsg.cidraddr.addr, &ifn->laddrs4[n],
		    sizeof ifn->laddrs4[n]);

		if (wire_sendmsg(ifn->mastwithifn, SCIDRADDR, &smsg.cidraddr,
		    sizeof smsg.cidraddr) == -1)
			logexitx(1, "%s wire_sendmsg local addr %d SCIDRADDR",
			    __func__, n);
	}

	/* at last send the peers */
	for (m = 0; m < ifn->peerssize; m++) {
		peer = ifn->peers[m];

		memset(&smsg.peer, 0, sizeof(smsg.peer));

		smsg.peer.ifnid = ifnid;
		smsg.peer.peerid = m;
		snprintf(smsg.peer.name, sizeof(smsg.peer.name), "%s",
		    peer->name);
		smsg.peer.nallowedips = peer->allowedipssize;
		memcpy(&smsg.peer.fsa, &peer->fsa, sizeof(smsg.peer.fsa));

		if (wire_sendmsg(ifn->mastwithifn, SPEER, &smsg.peer,
		    sizeof(smsg.peer)) == -1)
			logexitx(1, "%s wire_sendmsg SPEER %zu", __func__, m);

		for (n = 0; n < peer->allowedipssize; n++) {
			allowedip = peer->allowedips[n];

			memset(&smsg.cidraddr, 0, sizeof(smsg.cidraddr));

			smsg.cidraddr.ifnid = ifnid;
			smsg.cidraddr.peerid = m;
			smsg.cidraddr.prefixlen = allowedip->prefixlen;
			memcpy(&smsg.cidraddr.addr, &allowedip->addr,
			    sizeof(smsg.cidraddr.addr));

			if (wire_sendmsg(ifn->mastwithifn, SCIDRADDR,
			    &smsg.cidraddr, sizeof(smsg.cidraddr)) == -1)
				logexitx(1, "%s wire_sendmsg peer %d allowedip"
				    " %d SCIDRADDR", __func__, m, n);
		}
	}

	/* wait with end of startup signal */

	explicit_bzero(&smsg, sizeof(smsg));

	loginfox("config sent to %s %d", ifn->ifname, ifn->mastwithifn);
}

/*
 * Signal end of configuration.
 */
void
signal_eos(union smsg smsg, int mastport)
{
	memset(&smsg, 0, sizeof(smsg));

	if (wire_sendmsg(mastport, SEOS, &smsg.eos, sizeof(smsg.eos)) == -1)
		logexitx(1, "%s wire_sendmsg SEOS %d", __func__, mastport);
}
