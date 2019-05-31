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
#include <sys/stat.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "scfg.h"
#include "util.h"
#include "wiresep.h"

#include "parseconfig.h"

/* global settings */
static char *guser, *ggroup;
static wskey gpsk;
static uid_t guid;
static gid_t ggid;
static const char *logfacilitystr = "daemon";
static int logfacility;

static const wskey nullkey;

static struct ifn **ifnv;
static size_t ifnvsize;

/*
 * Create a new "member" of size "membersize" and add it to "arr". Exit on
 * failure.
 */
static void
addonex(void ***arr, size_t *curmemcount, void **member, size_t membersize)
{
	*arr = recallocarray(*arr, *curmemcount, *curmemcount + 1, sizeof(char *));
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
 * Parse a peer config.
 *
 * Return 0 on success, -1 on error.
 */
static int
parsepeerconfig(struct peer *peer, const struct scfge *cfg, int peernumber)
{
	struct cidraddr *allowedip;
	struct scfge *subcfg;
	const char *key, *peerid;
	size_t i, j;
	int e;

	if (cfg == NULL || cfg->strvsize < 1)
		return -1;
	if (strcasecmp("peer", cfg->strv[0]) != 0)
		return -1;

	/*
	 * Use optional peer name or a default until the public key is
	 * encountered.
	 */
	if (cfg->strvsize >= 2) {
		strlcpy(peer->name, cfg->strv[1], sizeof(peer->name));
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
					addonex((void ***)&peer->allowedips,
					    &peer->allowedipssize,
					    (void **)&allowedip,
					    sizeof(*allowedip));

					if (parseipcidr(&allowedip->addr,
					    &allowedip->prefixlen, "0.0.0.0/0")
					    == -1)
						abort();

					addonex((void ***)&peer->allowedips,
					    &peer->allowedipssize,
					    (void **)&allowedip,
					    sizeof(*allowedip));

					if (parseipcidr(&allowedip->addr,
					    &allowedip->prefixlen, "::/0")
					    == -1)
						abort();
				} else {
					addonex((void ***)&peer->allowedips,
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
		} else {
			warnx("%s: %s invalid keyword in the peer specific "
			    "scope", peerid, key);
			e = 1;
		}
	}

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
 * Return 0 on success, -1 on error.
 */
static int
parseinterfaceconfigs(void)
{
	struct scfge *subcfg;
	struct ifn *ifn;
	struct peer *peer;
	struct cidraddr *ifaddr;
	struct sockaddr_storage *listenaddr;
	struct stat st;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin4;
	const char *key;
	char tundevpath[29];
	size_t i, j, n;
	int e, wildcard, lport, tunnum;

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

		if (sscanf(ifn->scfge->strv[1], "tun%d%c", &tunnum, tundevpath)
		    != 1 || tunnum < 0) {
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
					/* check other keywords */
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
					addonex((void ***)&ifn->ifaddrs,
					    &ifn->ifaddrssize, (void **)&ifaddr,
					    sizeof(*ifaddr));

					if (parseipcidr(&ifaddr->addr,
					    &ifaddr->prefixlen,
					    subcfg->strv[j]) == -1) {
						warnx("%s: %s could not "
						    "parse interface address: %s",
						    ifn->ifname, key, subcfg->strv[j]);
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
			} else if (strcasecmp("pubkey", key) == 0) {
				if (subcfg->strvsize != 2) {
					warnx("%s: %s must have a value",
					    ifn->ifname, key);
					e = 1;
					continue;
				}
				if (parsekey(ifn->pubkey, subcfg->strv[1],
				    strlen(subcfg->strv[1])) == -1) {
					warnx("%s: %s could not parse the "
					    "interface public key", ifn->ifname,
					    key);
					e = 1;
					continue;
				}
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
					addonex((void ***)&ifn->listenaddrs,
					    &ifn->listenaddrssize,
					    (void **)&listenaddr,
					    sizeof(*listenaddr));

					if (parseaddrport(listenaddr,
					    subcfg->strv[j]) == -1) {
						warnx("%s: %s parse error: %s. Make "
						    "sure the address and port are "
						    "separated by a colon", ifn->ifname,
						    key, subcfg->strv[j]);
						e = 1;
						continue;
					}
				}
			} else if (strcasecmp("peer", key) == 0) {
				if (subcfg->strvsize > 2) {
					warnx("%s: %s extra peer information "
					    "must be grouped in a block \"peer "
					    "%s %s\"", ifn->ifname,
					    key, subcfg->strv[1],
					    subcfg->strv[2]);
					e = 1;
					continue;
				}
				addonex((void ***)&ifn->peers, &ifn->peerssize,
				    (void **)&peer, sizeof(*peer));
				if (parsepeerconfig(peer, subcfg,
				    ifn->peerssize) == -1) {
					e = 1;
					continue;
				}
				if (memcmp(peer->psk, nullkey, sizeof(wskey))
				    == 0)
					memcpy(peer->psk, ifnv[n]->psk,
					    sizeof(wskey));
			} else {
				warnx("%s: %s invalid keyword in the interface"
				    " specific scope",
				    ifn->ifname, key);
				e = 1;
			}
		}

		/*
		 * ensure defaults
		 */

		if (memcmp(ifn->psk, nullkey, sizeof(wskey)) == 0)
			memcpy(ifn->psk, gpsk, sizeof(wskey));

		if (ifn->uid == 0)
			ifn->uid = guid;

		if (ifn->gid == 0)
			ifn->gid = ggid;

		/* default interface description to the public key */
		if (ifn->ifdesc == NULL) {
			if ((ifn->ifdesc = calloc(1, MAXIFNDESC)) == NULL)
				err(1, "calloc ifdesc");
			if (base64_ntop(ifn->pubkey, KEYLEN, ifn->ifdesc,
			    MAXIFNDESC) == -1)
				return -1;
		}

		/*
		 * check requirements
		 */

		if (ifn->ifname == NULL) {
			warnx("interface device name missing");
			e = 1;
		}
		if (ifn->listenaddrssize == 0) {
			warnx("%s: listen missing", ifn->ifname);
			e = 1;
		}

		if (memcmp(ifn->privkey, nullkey, sizeof(wskey)) == 0) {
			warnx("%s: privkey missing", ifn->ifname);
			e = 1;
		}
		if (memcmp(ifn->pubkey, nullkey, sizeof(wskey)) == 0) {
			warnx("%s: pubkey missing", ifn->ifname);
			e = 1;
		}

		if (ifn->peerssize == 0)
			warnx("%s: has no peers configured", ifn->ifname);

		if (e)
			continue;

		/*
		 * TODO if a wildcard is used, resolve all addresses on all
		 * interfaces
		 */
		wildcard = 0;
		lport = 0;
		if (ifn->listenaddrs[0]->ss_family == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)ifn->listenaddrs[0];
			lport = ntohs(sin6->sin6_port);
			wildcard = memcmp(&sin6->sin6_addr, &in6addr_any,
			    sizeof(in6addr_any)) == 0;
		} else if (ifn->listenaddrs[0]->ss_family == AF_INET) {
			sin4 = (struct sockaddr_in *)ifn->listenaddrs[0];
			lport = ntohs(sin4->sin_port);
			if (sin4->sin_addr.s_addr == INADDR_ANY)
				wildcard = 1;
		} else {
			errx(1, "unsupported protocol family %d",
			    ifn->listenaddrs[0]->ss_family);
		}

		if (wildcard && lport >= IPPORT_RESERVED)
			warnx("using a wildcard address with a non-reserved "
			    "port makes us vulnerable to a DoS by a local "
			    "system user");

		/* unlink */
		ifn->scfge = NULL;
	}

	if (e != 0)
		return -1;

	return 0;
}

/*
 * Parse global settings and allocate new ifn structures in "ifnv".
 *
 * Return 0 on success, -1 on error.
 */
static int
parseglobalconfig(const struct scfge *root)
{
	struct scfge *subcfg;
	struct ifn *ifn;
	const char *key;
	size_t n;
	int e;

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
				/* check other keywords */
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
			if (resolveuser(&guid, &ggid, subcfg->strv[1]) == -1) {
				warnx("%s: %s invalid: %s",
				    "global", key, subcfg->strv[1]);
				e = 1;
				continue;
			}
		} else if (strcasecmp("group", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("%s: %s must contain one name "
				    "or gid",
				    "global", key);
				e = 1;
				continue;
			}
			if (resolvegroup(&ggid, subcfg->strv[1])
			    == -1) {
				warnx("%s: %s invalid: %s",
				    "global", key, subcfg->strv[1]);
				e = 1;
				continue;
			}
		} else if (strcasecmp("user", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("user must have one name or id");
				e = 1;
				continue;
			}
			if (guser) {
				warnx("global user can be set only once");
				e = 1;
				continue;
			}
			if ((guser = strdup(subcfg->strv[1])) == NULL)
				err(1, "strdup");
		} else if (strcasecmp("group", key) == 0) {
			if (subcfg->strvsize != 2) {
				warnx("group must have one name or id");
				e = 1;
				continue;
			}
			if (ggroup) {
				warnx("global group can be set only once");
				e = 1;
				continue;
			}
			if ((ggroup = strdup(subcfg->strv[1])) == NULL)
				err(1, "strdup");
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
		} else if (strcasecmp("interface", key) == 0) {
			addonex((void ***)&ifnv, &ifnvsize, (void **)&ifn,
			    sizeof(*ifn));
			ifn->scfge = subcfg;
		} else {
			warnx("invalid keyword in the global scope: %s", key);
			e = 1;
		}
	}

	if (guid == 0) {
		warnx("global user id may not be 0");
		e = 1;
	}
	if (ggid == 0) {
		warnx("global group id may not be 0");
		e = 1;
	}

	if (e != 0)
		return -1;

	return 0;
}

/*
 * Create a list of interfaces plus some global settings.
 *
 * yyparse creates a tree of scfg entries.
 *
 * In a first pass determine all global settings and in a second pass
 * create interfaces with peer specific settings.
 *
 * Exit on error.
 */
void
xparseconfigfile(const char *filename, struct ifn ***rifnv, size_t *rifnvsize,
    uid_t *unprivuid, gid_t *unprivgid, char **rlogfacilitystr)
{
	struct stat st;

	if ((yyd = open(filename, O_RDONLY|O_CLOEXEC)) == -1)
		err(1, "%s", filename);

	if (fstat(yyd, &st) == -1)
		err(1, "stat");

	/* owned by the superuser */
	if (st.st_uid != 0)
		errx(1, "%s: not owned by the superuser", filename);

	/* regular file */
	if (!S_ISREG(st.st_mode))
		errx(1, "%s: not a regular file", filename);

	/* may only be accessible by the owner and group */
	if ((st.st_mode & S_IRWXO) != 0)
		errx(1, "%s: readable or writable by others", filename);

	if (yyparse() != 0)
		errx(1, "%s: yyparse", __func__);
	if (close(yyd) == -1)
		err(1, "close %s", filename);

	if (parseglobalconfig(scfg) == -1)
		errx(1, NULL);
	if (parseinterfaceconfigs() == -1)
		errx(1, NULL);

	scfg_clear();

	*rifnv = ifnv;
	*rifnvsize = ifnvsize;
	*unprivuid = guid;
	*unprivgid = ggid;
	if ((*rlogfacilitystr = strdup(logfacilitystr)) == NULL)
		err(1, "%s strdup", __func__);
}

/*
 * Load private keys of all interfaces, determine public key and mac1key.
 */
void
processconfig(void)
{
	struct peer *peer;
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
