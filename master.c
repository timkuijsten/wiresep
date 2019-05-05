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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "scfg.h"
#include "util.h"
#include "wireprot.h"
#include "wiresep.h"

#define DEFAULTCONFIG "/etc/wiresep.conf"
#define MAXIFNDESC 65
#define MAXPEERNAME 8

typedef int chan[2];

void enclave_init(int masterport);
void proxy_init(int masterport);
void ifn_init(int masterport);
void enclave_serv(void);
void proxy_serv(void);
void ifn_serv(void);

void master_printinfo(FILE *);

/* these are used by the other modules as well */
int background, verbose;

/* global settings */
static char *guser, *ggroup, *configfile;
static wskey gpsk;
static uid_t guid;
static gid_t ggid;
static const char *logfacilitystr = "daemon";
static int logfacility;

static const wskey nullkey;

struct cidraddr {
	struct sockaddr_storage addr;
	size_t prefixlen;
};

struct peer {
	wskey psk;
	wskey pubkey;
	wskey mac1key;
	struct sockaddr_storage fsa;	/* rename to endpoint */
	struct cidraddr **allowedips;
	size_t allowedipssize;
	char name[MAXPEERNAME + 1];
};

/*
 * psk	= optional symmetric pre-shared secret, Q
 * pubkey	= Spubm
 * pubkeyhash	= Hash(Hash(Hash(Construction) || Identifier) || Spubm)
 * mac1key	= Hash(Label-Mac1 || Spubm)
 * cookiekey	= Hash(Label-Cookie || Spubm)
 */
struct ifn {
	struct scfge *scfge;	/* original user config data */
	int mastport;
	int enclport;
	int proxport;
	char *ifname; /* nul terminated name of the interface */
	char *ifdesc; /* nul terminated label for the interface */
	struct cidraddr **ifaddrs;
	size_t ifaddrssize;
	struct sockaddr_storage **listenaddrs;
	size_t listenaddrssize;
	wskey psk;
	wskey privkey;
	wskey pubkey;
	wskey pubkeyhash;
	wskey mac1key;
	wskey cookiekey;
	struct peer **peers;
	size_t peerssize;
	uid_t uid;
	gid_t gid;
};

static struct ifn **ifnv;
static size_t ifnvsize;

static union {
	struct sinit init;
	struct sifn ifn;
	struct speer peer;
	struct scidraddr cidraddr;
	struct seos eos;
} smsg;

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
sendconfig_enclave(int mastport, int proxport)
{
	struct ifn *ifn;
	struct peer *peer;
	size_t n, m;

	memset(&smsg.init, 0, sizeof(smsg.init));

	smsg.init.background = background;
	smsg.init.verbose = verbose;
	smsg.init.uid = guid;
	smsg.init.gid = ggid;
	smsg.init.proxport = proxport;
	smsg.init.nifns = ifnvsize;

	if (wire_sendmsg(mastport, SINIT, &smsg.init, sizeof(smsg.init)) == -1)
		logexitx(1, "%s wire_sendmsg SINIT", __func__);

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];

		memset(&smsg.ifn, 0, sizeof(smsg.ifn));

		smsg.ifn.ifnid = n;
		smsg.ifn.ifnport = ifn->enclport;
		snprintf(smsg.ifn.ifname, sizeof(smsg.ifn.ifname), "%s", ifn->ifname);
		if (ifn->ifdesc && strlen(ifn->ifdesc) > 0)
			snprintf(smsg.ifn.ifdesc, sizeof(smsg.ifn.ifdesc), "%s", ifn->ifdesc);
		memcpy(smsg.ifn.privkey, ifn->privkey, sizeof(smsg.ifn.privkey));
		memcpy(smsg.ifn.pubkey, ifn->pubkey, sizeof(smsg.ifn.pubkey));
		memcpy(smsg.ifn.pubkeyhash, ifn->pubkeyhash, sizeof(smsg.ifn.pubkeyhash));
		memcpy(smsg.ifn.mac1key, ifn->mac1key, sizeof(smsg.ifn.mac1key));
		memcpy(smsg.ifn.cookiekey, ifn->cookiekey, sizeof(smsg.ifn.cookiekey));
		smsg.ifn.npeers = ifn->peerssize;

		if (wire_sendmsg(mastport, SIFN, &smsg.ifn, sizeof(smsg.ifn)) == -1)
			logexitx(1, "%s wire_sendmsg SIFN", __func__);

		for (m = 0; m < ifn->peerssize; m++) {
			peer = ifn->peers[m];

			memset(&smsg.peer, 0, sizeof(smsg.peer));

			smsg.peer.ifnid = n;
			smsg.peer.peerid = m;

			if (memcmp(peer->psk, nullkey, sizeof(wskey)) == 0)
				memcpy(peer->psk, ifn->psk, sizeof(wskey));

			memcpy(smsg.peer.psk, peer->psk, sizeof(smsg.peer.psk));
			memcpy(smsg.peer.peerkey, peer->pubkey,
			    sizeof(smsg.peer.peerkey));
			memcpy(smsg.peer.mac1key, peer->mac1key,
			    sizeof(smsg.peer.mac1key));

			if (wire_sendmsg(mastport, SPEER, &smsg.peer,
			    sizeof(smsg.peer)) == -1)
				logexitx(1, "%s wire_sendmsg SPEER", __func__);
		}
	}

	/* wait with end of startup signal */

	explicit_bzero(&smsg, sizeof(smsg));

	loginfox("config sent to enclave %d", mastport);
}

/*
 * Send interface info to the proxy.
 *
 * SINIT
 * SIFN
 *
 * Exit on error.
 */
void
sendconfig_proxy(int mastport, int enclport)
{
	struct ifn *ifn;
	struct sockaddr_storage *listenaddr;
	size_t m, n;

	memset(&smsg.init, 0, sizeof(smsg.init));

	smsg.init.background = background;
	smsg.init.verbose = verbose;
	smsg.init.uid = guid;
	smsg.init.gid = ggid;
	smsg.init.enclport = enclport;
	smsg.init.nifns = ifnvsize;

	if (wire_sendmsg(mastport, SINIT, &smsg.init, sizeof(smsg.init)) == -1)
		logexitx(1, "%s wire_sendmsg SINIT", __func__);

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];

		memset(&smsg.ifn, 0, sizeof(smsg.ifn));

		smsg.ifn.ifnid = n;
		smsg.ifn.ifnport = ifn->proxport;
		smsg.ifn.nlistenaddrs = ifn->listenaddrssize;
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

		if (wire_sendmsg(mastport, SIFN, &smsg.ifn, sizeof(smsg.ifn))
		    == -1)
			logexitx(1, "%s wire_sendmsg SIFN", __func__);

		/* send listen addresses */
		for (m = 0; m < ifn->listenaddrssize; m++) {
			listenaddr = ifn->listenaddrs[m];

			memset(&smsg.cidraddr, 0, sizeof(smsg.cidraddr));

			smsg.cidraddr.ifnid = n;
			memcpy(&smsg.cidraddr.addr, listenaddr,
			    sizeof(smsg.cidraddr.addr));

			if (wire_sendmsg(mastport, SCIDRADDR, &smsg.cidraddr,
			    sizeof(smsg.cidraddr)) == -1)
				logexitx(1, "%s wire_sendmsg SCIDRADDR", __func__);
		}
	}

	/* wait with end of startup signal */

	explicit_bzero(&smsg, sizeof(smsg));

	loginfox("config sent to proxy %d", mastport);
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
sendconfig_ifn(int ifnid, int mastport, int enclport, int proxport)
{
	struct cidraddr *allowedip;
	struct cidraddr *ifaddr;
	struct sockaddr_storage *listenaddr;
	struct ifn *ifn;
	struct peer *peer;
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
	smsg.init.enclport = enclport;
	smsg.init.proxport = proxport;

	if (wire_sendmsg(mastport, SINIT, &smsg.init, sizeof(smsg.init)) == -1)
		logexitx(1, "%s wire_sendmsg SINIT %d", __func__, mastport);

	memset(&smsg.ifn, 0, sizeof(smsg.ifn));

	smsg.ifn.ifnid = ifnid;
	snprintf(smsg.ifn.ifname, sizeof(smsg.ifn.ifname), "%s", ifn->ifname);
	if (ifn->ifdesc && strlen(ifn->ifdesc) > 0)
		snprintf(smsg.ifn.ifdesc, sizeof(smsg.ifn.ifdesc), "%s", ifn->ifdesc);
	memcpy(smsg.ifn.mac1key, ifn->mac1key, sizeof(smsg.ifn.mac1key));
	memcpy(smsg.ifn.cookiekey, ifn->cookiekey, sizeof(smsg.ifn.cookiekey));
	smsg.ifn.nifaddrs = ifn->ifaddrssize;
	smsg.ifn.nlistenaddrs = ifn->listenaddrssize;
	smsg.ifn.npeers = ifn->peerssize;

	if (wire_sendmsg(mastport, SIFN, &smsg.ifn, sizeof(smsg.ifn)) == -1)
		logexitx(1, "%s wire_sendmsg SIFN %s", __func__, ifn->ifname);

	/* first send interface addresses */
	for (n = 0; n < ifn->ifaddrssize; n++) {
		ifaddr = ifn->ifaddrs[n];

		memset(&smsg.cidraddr, 0, sizeof(smsg.cidraddr));

		smsg.cidraddr.ifnid = ifnid;
		smsg.cidraddr.prefixlen = ifaddr->prefixlen;
		memcpy(&smsg.cidraddr.addr, &ifaddr->addr,
		    sizeof(smsg.cidraddr.addr));

		if (wire_sendmsg(mastport, SCIDRADDR, &smsg.cidraddr,
		    sizeof(smsg.cidraddr)) == -1)
			logexitx(1, "%s wire_sendmsg SCIDRADDR", __func__);
	}

	/* then listen addresses */
	for (n = 0; n < ifn->listenaddrssize; n++) {
		listenaddr = ifn->listenaddrs[n];

		memset(&smsg.cidraddr, 0, sizeof(smsg.cidraddr));

		smsg.cidraddr.ifnid = ifnid;
		memcpy(&smsg.cidraddr.addr, listenaddr,
		    sizeof(smsg.cidraddr.addr));

		if (wire_sendmsg(mastport, SCIDRADDR, &smsg.cidraddr,
		    sizeof(smsg.cidraddr)) == -1)
			logexitx(1, "%s wire_sendmsg SCIDRADDR", __func__);
	}

	/* at last send the peers */
	for (m = 0; m < ifn->peerssize; m++) {
		peer = ifn->peers[m];

		memset(&smsg.peer, 0, sizeof(smsg.peer));

		smsg.peer.ifnid = ifnid;
		smsg.peer.peerid = m;
		snprintf(smsg.peer.name, sizeof(smsg.peer.name), "%s", peer->name);
		smsg.peer.nallowedips = peer->allowedipssize;
		memcpy(&smsg.peer.fsa, &peer->fsa, sizeof(smsg.peer.fsa));

		if (wire_sendmsg(mastport, SPEER, &smsg.peer, sizeof(smsg.peer))
		    == -1)
			logexitx(1, "wire_sendmsg SPEER %zu", m);

		for (n = 0; n < peer->allowedipssize; n++) {
			allowedip = peer->allowedips[n];

			memset(&smsg.cidraddr, 0, sizeof(smsg.cidraddr));

			smsg.cidraddr.ifnid = ifnid;
			smsg.cidraddr.peerid = m;
			smsg.cidraddr.prefixlen = allowedip->prefixlen;
			memcpy(&smsg.cidraddr.addr, &allowedip->addr,
			    sizeof(smsg.cidraddr.addr));

			if (wire_sendmsg(mastport, SCIDRADDR, &smsg.cidraddr,
			    sizeof(smsg.cidraddr)) == -1)
				logexitx(1, "wire_sendmsg SCIDRADDR");
		}
	}

	/* wait with end of startup signal */

	explicit_bzero(&smsg, sizeof(smsg));

	loginfox("config sent to %s %d", ifn->ifname, mastport);
}

/*
 * Signal end of configuration.
 */
void
signal_eos(int mastport)
{
	memset(&smsg, 0, sizeof(smsg));

	if (wire_sendmsg(mastport, SEOS, &smsg.eos, sizeof(smsg.eos)) == -1)
		logexitx(1, "%s wire_sendmsg SEOS %d", __func__, mastport);
}

void
printusage(FILE *fp)
{
	fprintf(fp, "usage: %s [-dnqv] [-f file]\n", getprogname());
}

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
 * yyparse creates a tree of scfg entries.
 *
 * In a first pass determine all global settings and in a second pass
 * create interfaces with peer specific settings.
 *
 * Exit on error.
 */
static void
parseconfig(const char *filename)
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
}

/*
 * Load private keys of all interfaces, determine public key and mac1key.
 */
void
processconfig(void)
{
	struct iovec iov[2];
	struct peer *peer;
	size_t n, m;

	for (n = 0; n < ifnvsize; n++) {
		/* Hash(Label-Mac1 || Spubm) */

		iov[0].iov_base = LABELMAC1;
		iov[0].iov_len = strlen(LABELMAC1);
		iov[1].iov_base = ifnv[n]->pubkey;
		iov[1].iov_len = sizeof(ifnv[n]->pubkey);

		ws_hash(ifnv[n]->mac1key, iov, 2);

		/* Hash(Hash(Hash(Construction) || Identifier) || Spubm) */

		if (readhexnomem(ifnv[n]->pubkeyhash,
		    sizeof(ifnv[n]->pubkeyhash), CONSIDHASH,
		    strlen(CONSIDHASH)) == -1)
			abort();
		iov[0].iov_base = ifnv[n]->pubkeyhash;
		iov[0].iov_len = sizeof(ifnv[n]->pubkeyhash);
		iov[1].iov_base = ifnv[n]->pubkey;
		iov[1].iov_len = sizeof(ifnv[n]->pubkey);
		ws_hash(ifnv[n]->pubkeyhash, iov, 2);

		for (m = 0; m < ifnv[n]->peerssize; m++) {
			peer = ifnv[n]->peers[m];
			iov[0].iov_base = LABELMAC1;
			iov[0].iov_len = strlen(LABELMAC1);
			iov[1].iov_base = peer->pubkey;
			iov[1].iov_len = sizeof(peer->pubkey);

			ws_hash(peer->mac1key, iov, 2);
		}
	}
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
	/* descriptors for all communication channels */
	chan mastencl, mastprox, enclprox, *ifchan, mastmast;
	size_t n, m;
	int configtest, foreground, stdopen, masterport, stat;
	pid_t pid;
	const char *errstr;
	char c, *eargs[4], *eenv[1], *oldprogname;

	/* should endup in a configure script */
	if (sizeof(struct msgwginit) != 148)
		errx(1, "sizeof(struct msgwginit != 148: %zu", sizeof(struct msgwginit));
	if (sizeof(struct msgwgresp) != 92)
		errx(1, "sizeof(struct msgwgresp) != 92: %zu", sizeof(struct msgwgresp));
	if (sizeof(struct msgwgcook) != 64)
		errx(1, "sizeof(struct msgwgcook) != 64: %zu", sizeof(struct msgwgcook));
	if (sizeof(struct msgwgdatahdr) != 16)
		errx(1, "sizeof(struct msgwgdatahdr) != 16: %zu", sizeof(struct msgwgdatahdr));

	configtest = 0;
	foreground = 0;
	while ((c = getopt(argc, argv, "E:I:M:P:df:hnqv")) != -1)
		switch(c) {
		case 'E':
			masterport = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid enclave/master fd: %s %s",
				    errstr, optarg);
			setproctitle(NULL);
			enclave_init(masterport);
			enclave_serv();
			errx(1, "enclave[%d]: unexpected return", getpid());
		case 'I':
			masterport = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid ifn/master fd: %s %s",
				    errstr, optarg);
			setproctitle(NULL);
			ifn_init(masterport);
			ifn_serv();
			errx(1, "ifn[%d]: unexpected return", getpid());
		case 'P':
			masterport = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid proxy/master fd: %s %s",
				    errstr, optarg);
			setproctitle(NULL);
			proxy_init(masterport);
			proxy_serv();
			errx(1, "proxy[%d]: unexpected return", getpid());
		case 'M':
			mastmast[1] = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "invalid mastermaster descriptor: %s "
				    "%s", errstr, optarg);
			setproctitle(NULL);

			if (chroot(EMPTYDIR) == -1 || chdir("/") == -1)
				err(1, "chroot %s", EMPTYDIR);
			if (pledge("stdio", "") == -1)
				err(1, "%s: pledge", __func__);

			if (read(mastmast[1], &mastencl[0], sizeof(int))
			    != sizeof(int))
				err(1, "could not read enclave descriptor in "
				    "new master");
			if (read(mastmast[1], &mastprox[0], sizeof(int))
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
			 * Signal that we are ready and each process may proceed
			 * and start processing untrusted input.
			 */
			signal_eos(mastencl[0]);
			signal_eos(mastprox[0]);
			for (n = 0; n < ifnvsize; n++)
				signal_eos(ifchan[n][0]);

			if ((pid = waitpid(WAIT_ANY, &stat, 0)) == -1)
				err(1, "waitpid");

			if (WIFEXITED(stat)) {
				warnx("child %d normal exit %d", pid,
				    WEXITSTATUS(stat));
			} else if (WIFSIGNALED(stat)) {
				warnx("child %d exit by signal %d %s%s", pid,
				    WTERMSIG(stat), strsignal(WTERMSIG(stat)),
				    WCOREDUMP(stat) ? " (core)" : "");
			} else
				warnx("unknown termination status");

			if (killpg(0, SIGTERM) == -1)
				err(1, "killpg");

			/* should never reach */
			exit(3);
		case 'd':
			foreground = 1;
			break;
		case 'f':
			configfile = optarg;
			break;
		case 'h':
			printusage(stdout);
			exit(0);
		case 'n':
			configtest = 1;
			break;
		case 'q':
			verbose--;
			break;
		case 'v':
			verbose++;
			break;
		case '?':
			printusage(stderr);
			exit(1);
		}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		printusage(stderr);
		exit(1);
	}

	if (pledge("stdio dns rpath proc exec getpw", NULL) == -1)
		err(1, "%s: pledge", __func__);

	if (geteuid() != 0)
		errx(1, "must run as the superuser");

	/*
	 *   0. read configuration
	 */

	if (configfile) {
		parseconfig(configfile);
	} else
		parseconfig(DEFAULTCONFIG);

	if (configtest)
		exit(0);

	if (!foreground) {
		background = 1;
		if (daemonize() == -1)
			err(1, "daemonize"); /* might not print to stdout */
	}

	if (initlog(logfacilitystr) == -1)
		logexitx(1, "could not init log"); /* not printed if daemon */

	stdopen = isopenfd(STDIN_FILENO) + isopenfd(STDOUT_FILENO) +
	    isopenfd(STDERR_FILENO);

	/*
	 *   1. determine public key, mac1key and cookie key of each interface
	 */

	processconfig();

	/*
	 *   2. setup communication ports and fork each IFN, the PROXY and the
	 *     ENCLAVE
	 */

	/* don't bother to free before exec */
	if ((oldprogname = strdup(getprogname())) == NULL)
		logexit(1, "strdup getprogname");

	eenv[0] = NULL;

	ifchan = NULL;
	assert(ifnvsize < INT_MAX / 3);
	for (n = 0; n < ifnvsize; n++) {
		if ((ifchan = reallocarray(ifchan, (n + 1) * 3,
		    sizeof(*ifchan))) == NULL)
			logexit(1, "reallocarray %zu", n);

		/* ifchannel with master, enclave and proxy, respectively */
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ifchan[(n * 3) + 0]) == -1)
			logexit(1, "socketpair %zu 0", n * 3);
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ifchan[(n * 3) + 1]) == -1)
			logexit(1, "socketpair %zu 1", n * 3);
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ifchan[(n * 3) + 2]) == -1)
			logexit(1, "socketpair %zu 2", n * 3);

		switch (fork()) {
		case -1:
			logexit(1, "fork %s", ifnv[n]->ifname);
		case 0:
			setprogname(ifnv[n]->ifname);
			if (verbose > 1)
				loginfox("%d", getpid());

			for (m = 0; m <= n; m++) {
				close(ifchan[(m * 3) + 0][0]);
				close(ifchan[(m * 3) + 1][0]);
				close(ifchan[(m * 3) + 2][0]);
			}

			assert(getdtablecount() == stdopen + 3);

			eargs[0] = (char *)getprogname();
			eargs[1] = "-I";
			if (asprintf(&eargs[2], "%u", ifchan[(n * 3) + 0][1])
			    < 1)
				logexitx(1, "asprintf");
			/* don't bother to free before exec */
			eargs[3] = NULL;
			execvpe(oldprogname, eargs, eenv);
			logexit(1, "exec ifn");
		}

		/* parent */
		close(ifchan[(n * 3) + 0][1]);
		close(ifchan[(n * 3) + 1][1]);
		close(ifchan[(n * 3) + 2][1]);

		ifnv[n]->mastport = ifchan[(n * 3) + 0][0];
		ifnv[n]->enclport = ifchan[(n * 3) + 1][0];
		ifnv[n]->proxport = ifchan[(n * 3) + 2][0];
	}

	assert(getdtablecount() == stdopen + 3 * (int)ifnvsize);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, mastencl) == -1)
		logexit(1, "socketpair");
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, mastprox) == -1)
		logexit(1, "socketpair");
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, enclprox) == -1)
		logexit(1, "socketpair");

	/* fork enclave */
	switch (fork()) {
	case -1:
		logexit(1, "fork enclave");
	case 0:
		setprogname("enclave");
		if (verbose > 1)
			loginfox("%d", getpid());

		for (n = 0; n < ifnvsize; n++) {
			close(ifnv[n]->mastport);
			close(ifnv[n]->proxport);
		}

		close(mastprox[0]);
		close(mastprox[1]);

		close(mastencl[0]);
		close(enclprox[0]);

		assert(getdtablecount() == stdopen + 2 + (int)ifnvsize);

		eargs[0] = (char *)getprogname();
		eargs[1] = "-E";
		if (asprintf(&eargs[2], "%d", mastencl[1]) < 1)
			logexitx(1, "asprintf");
		/* don't bother to free before exec */
		eargs[3] = NULL;
		execvpe(oldprogname, eargs, eenv);
		logexit(1, "exec enclave");
	}

	/* fork proxy  */
	switch (fork()) {
	case -1:
		logexit(1, "fork proxy");
	case 0:
		setprogname("proxy");
		if (verbose > 1)
			loginfox("%d", getpid());

		for (n = 0; n < ifnvsize; n++) {
			close(ifnv[n]->mastport);
			close(ifnv[n]->enclport);
		}

		close(mastencl[0]);
		close(mastencl[1]);

		close(mastprox[0]);
		close(enclprox[1]);

		assert(getdtablecount() == stdopen + 2 + (int)ifnvsize);

		eargs[0] = (char *)getprogname();
		eargs[1] = "-P";
		if (asprintf(&eargs[2], "%d", mastprox[1]) < 1)
			logexitx(1, "asprintf");
		/* don't bother to free before exec */
		eargs[3] = NULL;
		execvpe(oldprogname, eargs, eenv);
		logexit(1, "exec proxy");
	}

	setprogname("master");
	if (verbose > 1)
		loginfox("%d", getpid());

	for (n = 0; n < ifnvsize; n++) {
		close(ifnv[n]->enclport);
		close(ifnv[n]->proxport);
	}

	close(mastencl[1]);
	close(mastprox[1]);
	close(enclprox[0]);
	close(enclprox[1]);

	assert(getdtablecount() == stdopen + 2 + (int)ifnvsize);

	if (verbose > 1) {
		loginfox("enclave %d:%d", mastencl[0], mastencl[1]);
		loginfox("proxy %d:%d", mastprox[0], mastprox[1]);

		for (n = 0; n < ifnvsize; n++) {
			loginfox("%s %d %d %d, %d %d %d", ifnv[n]->ifname,
			    ifnv[n]->mastport,
			    ifnv[n]->enclport,
			    ifnv[n]->proxport,
			    ifchan[(n * 3) + 0][1],
			    ifchan[(n * 3) + 1][1],
			    ifchan[(n * 3) + 2][1]);
		}
	}

	/*
	 *   3. send startup info to processes
	 */

	sendconfig_enclave(mastencl[0], enclprox[1]);
	sendconfig_proxy(mastprox[0], enclprox[0]);

	for (n = 0; n < ifnvsize; n++) {
		sendconfig_ifn(n,
		    ifnv[n]->mastport,
		    ifchan[(n * 3) + 1][1],
		    ifchan[(n * 3) + 2][1]);
	}

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
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, mastmast) == -1)
		logexit(1, "socketpair mastermaster");
	if (writen(mastmast[0], &mastencl[0], sizeof(int)) != 0)
		logexit(1, "could not write enclave descriptor to new master");
	if (writen(mastmast[0], &mastprox[0], sizeof(int)) != 0)
		logexit(1, "could not write proxy descriptor to new master");
	if (writen(mastmast[0], &ifnvsize, sizeof(ifnvsize)) != 0)
		logexit(1, "could not write ifnvsize to new master");
	for (n = 0; n < ifnvsize; n++) {
		if (writen(mastmast[0], &ifchan[(n * 3) + 0][0], sizeof(int))
		    != 0)
			logexit(1, "could not ifn descriptor to new master");
	}
	close(mastmast[0]);

	eargs[0] = (char *)getprogname();
	eargs[1] = "-M";
	if (asprintf(&eargs[2], "%u", mastmast[1]) < 1)
		logexitx(1, "asprintf");
	/* don't bother to free before exec */
	eargs[3] = NULL;
	execvpe(oldprogname, eargs, eenv);
	logexit(1, "exec master");
}

void
master_printinfo(FILE *fp)
{
	struct ifn *ifn;
	struct peer *peer;
	size_t n, m;

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];
		fprintf(fp, "ifn %zu\n", n);
		fprintf(fp, "enclport %d\n", ifn->enclport);
		fprintf(fp, "proxport %d\n", ifn->proxport);
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
