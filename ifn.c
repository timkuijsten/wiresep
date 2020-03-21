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
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "antireplay.h"
#include "util.h"
#include "wiresep.h"
#include "wireprot.h"

#define ND6_INFINITE_LIFETIME 0xffffffff

/* Times in microseconds */
#define REJECT_AFTER_MESSAGES (((uint64_t) 2<<60) - 1)
#define REJECT_AFTER_TIME 180000000
#define REKEY_AFTER_MESSAGES (((uint64_t) 2<<48) - 1)
#define REKEY_AFTER_TIME 120000000
#define REKEY_ATTEMPT_TIME 90000000
#define REKEY_TIMEOUT 5000000
#define KEEPALIVE_TIMEOUT 10000000

#define MINIP6HDR 40
#define MINIP4HDR 20
#define MINIPHDR 20
#define MAXIPHDR 40	/* ip6 header without options */
#define TUNHDRSIZ 4
#define wsTUNMTU 1420
#define TAGLEN 16
#define DATAHEADERLEN 16

#define MAXQUEUEPACKETS 50
#define MAXQUEUEPACKETSDATASZ ((size_t)(MAXSCRATCH * MAXQUEUEPACKETS))
#define MINDATA  (1 << 21) /* minimum dynamic memory without peers / packets */
#define MAXSTACK (1 << 15) /* 32 KB should be enough */
#define MAXCONNRETRY 10

#ifdef DEBUG
#define MAXCORE MAXQUEUEPACKETSDATASZ
#else
#define MAXCORE 0
#endif

/*
 * 64-bit integer that represents microseconds.
 */
typedef uint64_t utime_t;

extern int background, verbose;

union inet_addr {
	struct in6_addr addr6;
	struct in_addr  addr4;
};

/*
 * Used when we have data to send to a peer but no active current session. A
 * rekey timer will be set until rekey-attempt-time or a session is established.
 */
struct sesstent {
	enum { STINACTIVE, INITREQ, INITSENT, RESPRECVD } state;
	int64_t id;
	utime_t lastreq;
};

/*
 * Used when a peer started negotiating a new session.
 */
struct sessnext {
	enum { SNINACTIVE, GOTKEYS, RESPSENT } state;
	utime_t lastvrfyinit;
	utime_t start;
	int64_t id;
	int64_t peerid;
	EVP_AEAD_CTX sendctx;
	EVP_AEAD_CTX recvctx;
};

/*
 * The "start" field indicates when a session is started after the handshake
 * completes. While the handshake is still in progress it signifies the moment
 * the first handshake init was sent.
 * Note: an "id" of 0 is a valid, although unlikely, session id.
 */
struct session {
	struct antireplay arrecv;	/* receive counter bitmap */
	EVP_AEAD_CTX sendctx;
	EVP_AEAD_CTX recvctx;
	struct peer *peer;
	utime_t start;	/* whenever handshake completes (or first hs while still
			 * tentative) */
	utime_t expack; /* time before either data or a keepalive is expected
			 * from the peer */
	uint64_t nextnonce; /* next number for the next packet to send */
	uint32_t id;
	uint32_t peerid;
	char initiator;
	char kaset;	/* is the keepalive timer set? */
};

struct cidraddr {
	union sockaddr_inet addr;
	struct in6_addr v6addrmasked;
	struct in6_addr v6mask;
	struct in_addr v4addrmasked;
	struct in_addr v4mask;
	size_t prefixlen;
};

/* queued packet */
struct qpacket {
	uint8_t *data;
	size_t datasize;
	SIMPLEQ_ENTRY(qpacket) qpackets;
};

/*
 * A connected socket plus its local port.
 */
struct portsock {
	int s;	/* socket */
	in_port_t p;	/* transport layer port in network byte order */
};

struct peer {
	char *name;
	uint32_t id; /* peer id */
	int sock; /* active socket */
	int sockisv6;
	size_t prefixlen;
	union sockaddr_inet fsa;
	struct sesstent sesstent;
	struct sessnext sessnext;
	struct session *scurr;
	struct session *sprev;
	SIMPLEQ_HEAD(, qpacket) qpacketlist;
	size_t qpackets;
	size_t qpacketsdatasz;
	struct cidraddr **allowedips;
	size_t allowedipssize;
	struct portsock *portsock6;
	size_t portsock6count;
	struct portsock *portsock4;
	size_t portsock4count;
};

struct ifn {
	uint32_t id;
	char *ifname;
	char *ifdesc;
	struct cidraddr **ifaddrs;
	size_t ifaddrssize;
	struct sockaddr_in6 *laddr6; /* local IPv6 address to port mapping */
	size_t laddr6count;
	struct sockaddr_in *laddr4;  /* local IPv4 address to port mapping */
	size_t laddr4count;
	wskey mac1key;
	wskey cookiekey;
	struct peer **peers;
	size_t peerssize;
};

static uid_t uid;
static gid_t gid;

/* stats */
static struct {
	size_t devin; size_t devinerr; size_t devout; size_t devouterr;
	    size_t devinsz; size_t devoutsz;
	size_t queuein; size_t queueinerr; size_t queueout; size_t queueouterr;
	    size_t queueinsz; size_t queueoutsz;
	size_t sockin; size_t sockinerr; size_t sockout; size_t sockouterr;
	    size_t sockinsz; size_t sockoutsz;
	size_t initin; size_t initinerr; size_t initout; size_t initouterr;
	size_t respin; size_t respinerr; size_t respout; size_t respouterr;
	size_t proxin; size_t proxinerr; size_t proxout; size_t proxouterr;
	size_t enclin; size_t enclinerr; size_t enclout; size_t enclouterr;
	size_t corrupted;
	size_t invalidmac;
	size_t invalidpeer;
} stats;

static int kq, tund, pport, eport, doterm, logstats;
static struct ifn *ifn;
static uint8_t msg[MAXSCRATCH];
static utime_t now;
static uint8_t nonce[12] = { 0 };
static size_t sesscounter;

static const EVP_AEAD *aead;

static void
handlesig(int signo)
{
	switch (signo) {
	case SIGUSR1:
		logstats = 1;
		break;
	case SIGTERM:
		doterm = 1;
		break;
	default:
		logwarnx("unexpected signal %d %s", signo, strsignal(signo));
		break;
	}
}

static void
logsessinfo(const char *pre, const struct session *sess)
{
	if (sess == NULL) {
		logwarnx("%s NULL", pre ? pre : "");
		return;
	}

	logwarnx("%s %c %08x:%08x %llu/%llu %lld %lld %s",
	    pre ? pre : "",
	    sess->initiator ? 'I' : 'R',
	    sess->id,
	    sess->peerid,
	    sess->arrecv.maxseqnum,
	    sess->nextnonce,
	    sess->start,
	    sess->expack,
	    sess->kaset ? "keepalive" : "");
}

static void
logpeerinfo(const struct peer *peer)
{
	char addrstr[MAXADDRSTR];
	size_t n;

	logwarnx("peer %u %s", peer->id, peer->name);
	logwarnx("  sock %d", peer->sock);

	if (addrtostr(addrstr, sizeof(addrstr), (struct sockaddr *)&peer->fsa,
	    0) != -1)
		logwarnx("  fsa %s", addrstr);

	logwarnx("  allowed ips %zu", peer->allowedipssize);
	for (n = 0; n < peer->allowedipssize; n++) {
		if (addrtostr(addrstr, sizeof(addrstr),
		    (struct sockaddr *)&peer->allowedips[n]->addr, 1) != -1) {
			logwarnx("  %s/%zu", addrstr,
			    peer->allowedips[n]->prefixlen);
		}
	}

	logwarnx("  queue %zu %zu bytes", peer->qpackets, peer->qpacketsdatasz);

	logsessinfo("  sess curr", peer->scurr);
	logsessinfo("  sess prev", peer->sprev);
}

static void
ifn_loginfo(void)
{
	char addrstr[MAXADDRSTR];
	size_t n;

	logwarnx("id %u %s", ifn->id, ifn->ifname);
	for (n = 0; n < ifn->ifaddrssize; n++) {
		if (addrtostr(addrstr, sizeof(addrstr),
		    (struct sockaddr *)&ifn->ifaddrs[n]->addr, 1) != -1) {
			logwarnx("ifaddr %s/%zu", addrstr,
			    ifn->ifaddrs[n]->prefixlen);
		}
	}

	for (n = 0; n < ifn->laddr6count; n++) {
		if (addrtostr(addrstr, sizeof(addrstr),
		    (struct sockaddr *)&ifn->laddr6[n], 0) != -1) {
			logwarnx("local ip6 %s", addrstr);
		}
	}

	for (n = 0; n < ifn->laddr4count; n++) {
		if (addrtostr(addrstr, sizeof(addrstr),
		    (struct sockaddr *)&ifn->laddr4[n], 0) != -1) {
			logwarnx("local ip4 %s", addrstr);
		}
	}

	for (n = 0; n < ifn->peerssize; n++)
		logpeerinfo(ifn->peers[n]);

	logwarnx("stats packets in/out (errors in/out) [bytes in/out]");
	logwarnx("  dev   %zu/%zu (%zu/%zu) %zu/%zu", stats.devin, stats.devout,
	    stats.devinerr, stats.devouterr, stats.devinsz, stats.devoutsz);
	logwarnx("  queue %zu/%zu (%zu/%zu) %zu/%zu", stats.queuein,
	    stats.queueout, stats.queueinerr, stats.queueouterr,
	    stats.queueinsz, stats.queueoutsz);
	logwarnx("  sock  %zu/%zu (%zu/%zu) %zu/%zu", stats.sockin,
	    stats.sockout, stats.sockinerr, stats.sockouterr, stats.sockinsz,
	    stats.sockoutsz);
	logwarnx("  init  %zu/%zu (%zu/%zu)", stats.initin, stats.initout,
	    stats.initinerr, stats.initouterr);
	logwarnx("  resp  %zu/%zu (%zu/%zu)", stats.respin, stats.respout,
	    stats.respinerr, stats.respouterr);
	logwarnx("  encl  %zu/%zu (%zu/%zu)", stats.enclin, stats.enclout,
	    stats.enclinerr, stats.enclouterr);
	logwarnx("  prox  %zu/%zu (%zu/%zu)", stats.proxin, stats.proxout,
	    stats.proxinerr, stats.proxouterr);
	logwarnx("  total corrupted/invalid mac/invalid peer %zu/%zu/%zu",
	    stats.corrupted, stats.invalidmac, stats.invalidpeer);
}

/*
 * Set the primary address and destination address of an interface.
 *
 * Return 0 on success and -1 on failure with errno set.
 */
static int
assignaddr6(const char *ifname, const struct cidraddr *ca)
{
	struct in6_aliasreq	addreq;
	struct sockaddr_in6 mask;
	int s;

	if (ifname == NULL || ca == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(&addreq, 0, sizeof(addreq));

	if (strlcpy(addreq.ifra_name, ifname, sizeof(addreq.ifra_name)) >=
	    sizeof(addreq.ifra_name)) {
		errno = EINVAL;
		return -1;
	}

	addreq.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	addreq.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;

	memset(&mask, 0, sizeof(mask));
	mask.sin6_len = sizeof(mask);
	mask.sin6_family = AF_INET6;
	mask.sin6_addr = ca->v6mask;

	memcpy(&addreq.ifra_addr, &ca->addr,
	    MIN(sizeof addreq.ifra_addr, sizeof ca->addr));
	memcpy(&addreq.ifra_prefixmask, &mask,
	    MIN(sizeof addreq.ifra_prefixmask, sizeof mask));

	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
		logexitx(1, "%s socket", __func__);
	if (ioctl(s, SIOCAIFADDR_IN6, &addreq) == -1)
		logexit(1, "%s ioctl", __func__);
	if (close(s) == -1)
		logexit(1, "%s close", __func__);

	return 0;
}

/*
 * Set the primary address and destination address of an interface.
 *
 * Return 0 on success and -1 on failure with errno set.
 */
static int
assignaddr4(const char *ifname, const struct cidraddr *ca)
{
	struct ifaliasreq addreq;
	struct sockaddr_in mask;
	int s;

	if (ifname == NULL || ca == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(&addreq, 0, sizeof(addreq));

	if (strlcpy(addreq.ifra_name, ifname, sizeof(addreq.ifra_name)) >=
	    sizeof(addreq.ifra_name)) {
		errno = EINVAL;
		return -1;
	}

	memset(&mask, 0, sizeof(mask));
	mask.sin_len = sizeof(mask);
	mask.sin_family = AF_INET;
	mask.sin_addr = ca->v4mask;

	memcpy(&addreq.ifra_addr, &ca->addr,
	    MIN(sizeof addreq.ifra_addr, sizeof ca->addr));
	memcpy(&addreq.ifra_mask, &mask,
	    MIN(sizeof addreq.ifra_mask, sizeof mask));

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		logexitx(1, "%s socket", __func__);
	if (ioctl(s, SIOCAIFADDR, &addreq) == -1)
		logexit(1, "%s ioctl", __func__);
	if (close(s) == -1)
		logexit(1, "%s close", __func__);

	return 0;
}

/*
 * Assign a v4 or v6 address to an interface.
 *
 * Return 0 on success or -1 on failure with errno set.
 */
static int
assignaddr(const char *ifname, const struct cidraddr *ca)
{
	if (ifname == NULL || ca == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (ca->addr.h.family == AF_INET6) {
		return assignaddr6(ifname, ca);
	} else if (ca->addr.h.family == AF_INET) {
		return assignaddr4(ifname, ca);
	} else {
		errno = EINVAL;
		return -1;
	}
}

/*
 * Find a peer by "sessid". Return 1 if found and updates "peer" to point to it.
 * 0 if not found.
 *
 * XXX log(n)
 */
static int
findpeerbysessid(uint32_t sessid, struct peer **peer)
{
	struct peer *p;
	size_t n;

	for (n = 0; n < ifn->peerssize; n++) {
		p = ifn->peers[n];
		if (p->sesstent.id >= 0 && sessid == p->sesstent.id) {
			*peer = p;
			return 1;
		}
		if (p->sessnext.id >= 0 && sessid == p->sessnext.id) {
			*peer = p;
			return 1;
		}
		if (p->scurr && sessid == p->scurr->id) {
			*peer = p;
			return 1;
		}
		if (p->sprev && sessid == p->sprev->id) {
			*peer = p;
			return 1;
		}
	}

	return 0;
}

/*
 * Locate the start and length of the payload of a transport data message.
 *
 * "mwdhdr" must be a pointer to the start of the received packet. "mwdsize"
 * must be the complete packet size including the size of "mwdhdr".
 *
 * Updates "payload" to point to the start of the payload that follows after
 * "mwdhdr".
 * "payloadsize" is updated to contain the length of the payload including the
 * authentication tag.
 *
 * Return 0 on success, -1 on failure.
 *
 * XXX might merge into decryptpacket()
 */
static int
payloadoffset(uint8_t **payload, size_t *payloadsize,
    const struct msgwgdatahdr *mwdhdr, size_t mwdsize)
{
	assert(sizeof(*mwdhdr) == DATAHEADERLEN);

	if (mwdsize < DATAHEADERLEN)
		return -1;

	/*
	 * At the very least expect an empty packet which contains only an
	 * authentication tag (keepalive).
	 */
	if (mwdsize - DATAHEADERLEN < TAGLEN)
		return -1;

	*payload = (uint8_t *)mwdhdr + DATAHEADERLEN;
	*payloadsize = mwdsize - DATAHEADERLEN;

	return 0;
}

/*
 * Find a socket by port.
 *
 * Return the socket if found or -1 if not found.
 *
 * XXX logn
 */
static int
findsockbyport(const struct peer *peer, in_port_t port, int isv6)
{
	struct portsock *psp;
	size_t n, pspcount;

	if (isv6) {
		psp = peer->portsock6;
		pspcount = peer->portsock6count;
	} else {
		psp = peer->portsock4;
		pspcount = peer->portsock4count;
	}

	for (n = 0; n < pspcount; n++) {
		if (psp[n].p == port)
			return psp[n].s;
	}

	return -1;
}

/*
 * Find a peer by id. Return 1 if found and updates "p" to point to it. 0 if not
 * found and updates "p" to NULL.
 */
static int
findpeer(uint32_t peerid, struct peer **p)
{
	*p = NULL;

	if (peerid >= ifn->peerssize)
		return 0;

	*p = ifn->peers[peerid];
	return 1;
}

/*
 * Mask ip6 address "in" to "prefixlen" and write the result in "out".
 *
 * "zero" is a boolean to indicate whether trailing bytes should be zeroed.
 */
static void
maskip6(struct in6_addr *out, const struct in6_addr *in, size_t prefixlen,
    int zero)
{
	size_t cut;
	uint8_t *op, *ip;

	assert(prefixlen <= 128);

	cut = prefixlen / 8;

	memmove(out, in, cut);

	if (prefixlen == 128)
		return;

	ip = (uint8_t *)in;
	op = (uint8_t *)out;

	op[cut] = ip[cut] & (0xff << (8 - (prefixlen - cut * 8)));

	if (zero && cut < 15)
		memset(&op[cut + 1], 0, 15 - cut);
}

/*
 * Find a peer with most specific "allowedips" by a remote address. "fa" must
 * be a pointer to the foreign address. If multiple allowedips match the same
 * mask or prefix length, the last one is choosen.
 *
 * Return 1 if a peer with a matching route is found and updates "peer" to point
 * to it as well as "addr" to the addr that matched. Returns 0 if no peer is
 * found and updates "peer" and "addr" to NULL.
 *
 * XXX log(n)
 */
static int
peerbyroute6(struct peer **peer, struct cidraddr **addr,
    const struct in6_addr *fa)
{
	struct cidraddr *allowedip;
	struct in6_addr famasked;
	struct peer *p;
	size_t maxprefixlen;

	size_t n, o;

	maxprefixlen = 0;
	*peer = NULL;
	*addr = NULL;

	for (n = 0; n < ifn->peerssize; n++) {
		p = ifn->peers[n];

		for (o = 0; o < p->allowedipssize; o++) {
			allowedip = p->allowedips[o];

			if (allowedip->addr.h.family != AF_INET6)
				continue;

			/* XXX once it works, don't zero out postfix */
			maskip6(&famasked, fa, allowedip->prefixlen, 1);

			if (memcmp(&famasked, &allowedip->v6addrmasked, 16) == 0
			    && allowedip->prefixlen >= maxprefixlen) {
				*peer = p;
				*addr = allowedip;
				maxprefixlen = allowedip->prefixlen;
			}
		}
	}

	if (*peer != NULL)
		return 1;

	return 0;
}

/*
 * Find a peer based on its allowed ips and the address "fa". "fa" must be in
 * network byte order. The first most-specific match is returned.
 *
 * Return 1 if a peer with a matching route is found and updates "peer" to point
 * to it as well as "addr" to the addr that matched. Returns 0 if no peer is
 * found and updates "peer" and "addr" to NULL.
 *
 * XXX log(n)
 */
static int
peerbyroute4(struct peer **peer, struct cidraddr **addr,
    const struct in_addr *fa)
{
	struct cidraddr *allowedip;
	struct peer *p;
	size_t maxprefixlen;

	size_t n, o;

	maxprefixlen = 0;
	*peer = NULL;
	*addr = NULL;

	for (n = 0; n < ifn->peerssize; n++) {
		p = ifn->peers[n];

		for (o = 0; o < p->allowedipssize; o++) {
			allowedip = p->allowedips[o];

			if (allowedip->addr.h.family != AF_INET)
				continue;

			if ((fa->s_addr & allowedip->v4mask.s_addr) ==
			    allowedip->v4addrmasked.s_addr &&
			    allowedip->prefixlen >= maxprefixlen) {
				*peer = p;
				*addr = allowedip;
				maxprefixlen = allowedip->prefixlen;
			}
		}
	}

	if (*peer != NULL)
		return 1;

	return 0;
}

/*
 * Fill in an IPv6 socket addresss structure.
 *
 * "port" must be in network byte order. If "addr" is NULL the wildcard address
 * is used. If "port" is 0 the wildcard port is used.
 */
static void
setsockaddr6(struct sockaddr_in6 *out, const struct in6_addr *addr,
    in_port_t port)
{
	memset(out, 0, sizeof(*out));
	out->sin6_len = sizeof(*out);
	out->sin6_family = AF_INET6;
	out->sin6_port = port;
	if (addr == NULL) {
		out->sin6_addr = in6addr_any;
	} else {
		out->sin6_addr = *(struct in6_addr *)addr;
	}
}

/*
 * Fill in an IPv4 socket addresss structure.
 *
 * "port" must be in network byte order. If "addr" is NULL the wildcard address
 * is used. If "port" is 0 the wildcard port is used.
 */
static void
setsockaddr4(struct sockaddr_in *out, const struct in_addr *addr,
    in_port_t port)
{
	memset(out, 0, sizeof(*out));
	out->sin_len = sizeof(*out);
	out->sin_family = AF_INET;
	out->sin_port = port;
	if (addr == NULL) {
		out->sin_addr.s_addr = INADDR_ANY;
	} else {
		out->sin_addr = *(struct in_addr *)addr;
	}
}

/*
 * Fill in a socket address structure.
 *
 * "ip" must be an in6_addr or in_addr structure, and "ipisv6" a boolean to
 * indicate which one of the two. "port" must be in network byte order. If "ip"
 * is NULL the wildcard address is used. If "port" is 0 the wildcard port is
 * used.
 */
static void
setsockaddr(struct sockaddr *out, const void *ip, int ipisv6, in_port_t port)
{
	if (ipisv6) {
		setsockaddr6((struct sockaddr_in6 *)out, ip, port);
	} else {
		setsockaddr4((struct sockaddr_in *)out, ip, port);
	}
}

/*
 * Check which port should have be used for a given an address. The address must
 * match while the porthint is only used to keep searching as long as only an
 * address is matched.
 *
 * "porthint" must be in network byte order.
 *
 * Return which port should have been used, or 0 if none found for the given
 * address.
 */
static in_port_t
addrtoport(const struct sockaddr *addr, int isv6, in_port_t porthint)
{
	const struct sockaddr_in6 *src6;
	const struct sockaddr_in *src4;
	struct sockaddr_in6 *laddr6;
	struct sockaddr_in *laddr4;
	size_t n;
	int score, advport;

	/*
	 * Find the local address with best match:
	 *   wildcard address match = 1
	 *       if porthint is given and matches = 2
	 *   exact address match = 3
	 *       if porthint is given and matches = 4
	 */

	score = advport = 0;
	if (isv6) {
		src6 = (struct sockaddr_in6 *)addr;
		for (n = 0; n < ifn->laddr6count; n++) {
			laddr6 = &ifn->laddr6[n];
			if (memcmp(&laddr6->sin6_addr, &in6addr_any,
			    sizeof(in6addr_any)) == 0) {
				/* wildcard address match */
				if (score < 1) {
					score = 1;
					advport = laddr6->sin6_port;
				}

				if (score < 2) {
					if (porthint > 0 &&
					    porthint == laddr6->sin6_port) {
						score = 2;
						advport = laddr6->sin6_port;
					}
				}
			} else if (memcmp(&laddr6->sin6_addr, &src6->sin6_addr,
			    sizeof(src6->sin6_addr)) == 0) {
				/* exact address match */
				if (score < 3) {
					score = 3;
					advport = laddr6->sin6_port;
				}

				if (score < 4) {
					if (porthint > 0 &&
					    porthint == laddr6->sin6_port) {
						score = 4;
						advport = laddr6->sin6_port;
					}
				}
			}
		}
	} else {
		src4 = (struct sockaddr_in *)addr;
		for (n = 0; n < ifn->laddr4count; n++) {
			laddr4 = &ifn->laddr4[n];
			if (laddr4->sin_addr.s_addr == INADDR_ANY) {
				/* wildcard address match */
				if (score < 1) {
					score = 1;
					advport = laddr4->sin_port;
				}

				if (score < 2) {
					if (porthint > 0 &&
					    porthint == laddr4->sin_port) {
						score = 2;
						advport = laddr4->sin_port;
					}
				}
			} else if (laddr4->sin_addr.s_addr ==
			    src4->sin_addr.s_addr) {
				/* exact address match */
				if (score < 3) {
					score = 3;
					advport = laddr4->sin_port;
				}

				if (score < 4) {
					if (porthint > 0 &&
					    porthint == laddr4->sin_port) {
						score = 4;
						advport = laddr4->sin_port;
					}
				}
			}
		}
	}

	return advport;
}

/*
 * Disconnect and deregister the active socket of a peer by connecting it to a
 * reserved port on the localhost so that it can be used later to connect to a
 * new address, and stop listening for any events that might happen (triggered
 * by a /rogue/ local process).
 *
 * Return 0 on success, -1 on failure with errno set.
 */
static int
peerpark(struct peer *peer)
{
	char addrstr1[MAXADDRSTR], addrstr2[MAXADDRSTR];
	union sockaddr_inet si;
	union inet_addr addr;
	struct kevent ev;
	int retries;
	socklen_t len;
	in_port_t rport;

	if (peer->sock == -1) {
		errno = ENOTSOCK;
		return -1;
	}

	/*
	 * Stop listening for anything that might be sent to this
	 * socket. If no read filter was set (yet) on a descriptor EBADF is
	 * returned by kevent(), ignore this.
	 */
	EV_SET(&ev, peer->sock, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1 && errno != EBADF)
		logwarn("%s kevent error", __func__);

	if (peer->sockisv6) {
		if (inet_pton(AF_INET6, "::1", &addr.addr6) != 1)
			logwarn("inet_pton ::1");
	} else {
		if (inet_pton(AF_INET, "127.0.0.1", &addr.addr4) != 1)
			logwarn("inet_pton 127.0.0.1");
	}

	retries = 0;
retry:
	rport = arc4random_uniform(IPPORT_RESERVED - 1) + 1;
	setsockaddr((struct sockaddr *)&si, &addr, peer->sockisv6, rport);

	if (connect(peer->sock, (struct sockaddr *)&si, si.h.len) == -1) {
		if (errno == EINTR)
			goto retry;

		if (errno == EADDRINUSE) {
			if (retries < MAXCONNRETRY) {
				lognoticex("%s can't connect to localhost port "
				    "%d, retrying... (%d)", rport, retries + 1);

				sleep(1);
				retries++;
				goto retry;
			}

			logwarn("%s can't connect to localhost port %d, giving "
			    "up", rport);
		}

		peer->sock = -1;
		peer->sockisv6 = 0;

		logwarn("%s %s error", peer->name, __func__);

		return -1;
	}

	len = sizeof si;
	if (getsockname(peer->sock, (struct sockaddr *)&si, &len) == -1) {
		logwarn("%s getsockname error", __func__);
		peerpark(peer);
		return -1;
	}
	addrtostr(addrstr1, sizeof(addrstr1), (struct sockaddr *)&si, 0);

	len = sizeof si;
	if (getpeername(peer->sock, (struct sockaddr *)&si, &len) == -1) {
		logwarn("%s getsockname error", __func__);
		peerpark(peer);
		return -1;
	}
	addrtostr(addrstr2, sizeof(addrstr2), (struct sockaddr *)&si, 0);

	loginfox("parked %s -> %s", addrstr1, addrstr2);

	peer->sock = -1;
	peer->sockisv6 = 0;

	return 0;
}

/*
 * Connect to remote address "faddr". Try to connect from a port that matches
 * one of the configured local addresses. Since the decision for the local
 * address depends on the routing table (and will always be an interfaces
 * primary address, never an alias) our methods to control the outgoing address
 * are limited and might not match the address that a peer would have choosen.
 *
 * Return 0 on success, -1 on failure.
 */
static int
peerconnect(struct peer *peer, const struct sockaddr *faddr)
{
	char addrstr1[MAXADDRSTR], addrstr2[MAXADDRSTR];
	struct kevent ev;
	union sockaddr_inet si;
	in_port_t lport, port;
	int isv6, s;
	socklen_t len;

	/* ensure existing sockets are parked first */
	if (peer->sock > -1)
		if (peerpark(peer) == -1)
			return -1;

	/*
	 * Use the first socket (with whatever port) to connect to the remote.
	 * See which address was choosen by the routing table and make sure we
	 * should not connect from a different port (and socket) for the choosen
	 * address.
	 */

	if (faddr->sa_family == AF_INET6) {
		peer->sock = peer->portsock6[0].s;
		peer->sockisv6 = 1;
		lport =  peer->portsock6[0].p;
		isv6 = 1;
	} else {
		peer->sock = peer->portsock4[0].s;
		peer->sockisv6 = 0;
		lport =  peer->portsock4[0].p;
		isv6 = 0;
	}

	/*
	 * Connect and listen for events (overwrites if already set).
	 */

	if (connect(peer->sock, faddr, faddr->sa_len) == -1) {
		logwarn("connect to remote endpoint failed");
		return -1;
	}

	len = sizeof si;
	if (getsockname(peer->sock, (struct sockaddr *)&si, &len) == -1) {
		logwarn("%s getsockname error", __func__);
		peerpark(peer);
		return -1;
	}

	port = addrtoport((struct sockaddr *)&si, isv6, lport);
	if (port != 0 && port != lport) {
		loginfox("reconnect from the socket with the right port");

		if (peerpark(peer) == -1)
			return -1;

		s = findsockbyport(peer, port, isv6);
		if (s == -1) {
			logwarnx("%s suggested socket for port %d not found",
			    __func__, ntohs(port));
			return -1;
		}

		if (connect(s, faddr, faddr->sa_len) == -1) {
			logwarn("reconnect to remote endpoint failed");
			return -1;
		}

		peer->sock = s;
		peer->sockisv6 = isv6;
	} else if (port == 0 && lport != 0) {
		logwarnx("could not find a suitable local port to connect to "
		    "remote endpoint, using %d", ntohs(lport));
	}

	len = sizeof si;
	if (getsockname(peer->sock, (struct sockaddr *)&si, &len) == -1) {
		logwarn("%s getsockname error", __func__);
		peerpark(peer);
		return -1;
	}
	addrtostr(addrstr1, sizeof addrstr1, (struct sockaddr *)&si, 0);

	len = sizeof si;
	if (getpeername(peer->sock, (struct sockaddr *)&si, &len) == -1) {
		logwarn("%s getsockname error", __func__);
		peerpark(peer);
		return -1;
	}
	addrtostr(addrstr2, sizeof addrstr2, (struct sockaddr *)faddr, 0);

	loginfox("connected %s -> %s", addrstr1, addrstr2);

	EV_SET(&ev, peer->sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1)
		logexit(1, "%s kevent error", __func__);

	return 0;
}

/*
 * Schedule a one-shot timer.
 *
 * Note that if a timer with the same id is already set, this call has no
 * effect. The existing timer will *not* be updated and a new timer will not be
 * added.
 */
static void
settimer(unsigned int id, utime_t usec)
{
	struct kevent ev;

	EV_SET(&ev, id, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, usec / 1000,
	    NULL);

	assert(kevent(kq, &ev, 1, NULL, 0, NULL) != -1);

	if (verbose > 1)
		loginfox("timer %x set to %llu milliseconds", id, usec / 1000);
}

/*
 * Clear a rekey or keepalive timer.
 *
 * Return 0 on success, -1 on error with errno set.
 */
static int
cleartimer(unsigned int id)
{
	struct kevent ev;

	EV_SET(&ev, id, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);

	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1 && errno != ENOENT)
		return -1;

	if (verbose > 1)
		loginfox("timer %x cleared", id);

	return 0;
}

/*
 * Notify the proxy of a new session id or invalidate an existing session id.
 *
 * Return 0 on success, -1 on error.
 */
static int
notifyproxy(uint32_t peerid, uint32_t sessid, enum sessidtype type)
{
	struct msgsessid msi;

	msi.sessid = sessid;
	msi.type = type;

	if (wire_sendpeeridmsg(pport, peerid, MSGSESSID, &msi, sizeof(msi))
	    == -1) {
		stats.proxouterr++;
		return -1;
	}

	stats.proxout++;
	return 0;
}

/*
 * Wipe and securely free a current or previous session. Destroys keys, timers
 * and notifies the proxy of the invalidated session id.
 *
 * Call this function whenever a session reaches the time or number of messages
 * limit.
 */
static void
sessdestroy(struct session *sess)
{
	uint32_t sessid, peerid;

	sessid = sess->id;
	peerid = sess->peer->id;

	EVP_AEAD_CTX_cleanup(&sess->recvctx);
	EVP_AEAD_CTX_cleanup(&sess->sendctx);

	/*
	 * The timer won't be set if it was a reject-timeout that triggered the
	 * calling of this function.
	 */
	if (sess->kaset && cleartimer(sess->id) == -1)
		logwarn("%s cleartimer %x", __func__, sess->id);

	if (verbose > 1)
		loginfox("%s %x %zu", __func__, sess->id, sesscounter);

	freezero(sess, sizeof(struct session));
	sesscounter--;

	if (notifyproxy(peerid, sessid, SESSIDDESTROY) == -1)
		logwarnx("proxy notification of destroyed session id failed");
}

/*
 * Request a new handshake init message from the enclave.
 */
static void
sendreqhsinit(struct peer *peer)
{
	struct msgreqwginit mri;

	if (makemsgreqwginit(&mri) == -1)
		logexitx(1, "%s makemsgreqwginit", __func__);

	if (wire_sendpeeridmsg(eport, peer->id, MSGREQWGINIT, &mri, sizeof(mri))
	    == -1)
		logexitx(1, "error sending MSGREQWGINIT to enclave");

	/*
	 * Since the rekey timer is set by session id, we need one even though
	 * the session id will be overwritten by one from the enclave later on.
	 */
	peer->sesstent.id = arc4random();
	settimer(peer->sesstent.id, REKEY_TIMEOUT);

	peer->sesstent.state = INITREQ;
}

/*
 * Request a new handshake init message from the enclave if none is currently
 * pending.
 */
static void
ensurehs(struct peer *peer)
{
	if (peer->sesstent.state == STINACTIVE)
		sendreqhsinit(peer);

	peer->sesstent.lastreq = now;
}

/*
 * Determine if a current or previous session can be used for sending or
 * receiving data. There are time based and message based limits, as well as
 * an expected keepalive from our peer within the next 15 seconds after we've
 * sent data.
 *
 * Return 1 if the session is still active, 0 if not.
 */
static int
sessactive(const struct session *sess)
{
	if (!sess) {
		if (verbose > 1)
			loginfox("%s no sess", __func__);

		return 0;
	}

	if (sess->expack > 0 && sess->expack < now) {
		if (verbose > 1)
			loginfox("%s expected ack too late %llu < %llu",
			    __func__, sess->expack, now);

		return 0;
	}

	if (REJECT_AFTER_TIME < now - sess->start) {
		if (verbose > 1)
			loginfox("%s REJECT_AFTER_TIME %llu", __func__,
			    now - sess->start);

		return 0;
	}

	if (REJECT_AFTER_MESSAGES < sess->nextnonce) {
		if (verbose > 1)
			loginfox("%s REJECT_AFTER_MESSAGES %llu", __func__,
			    sess->nextnonce);

		return 0;
	}

	return 1;
}

/*
 * Clear the tentative session.
 */
static void
sesstentclear(struct peer *peer, int timerset)
{
	if (timerset && cleartimer(peer->sesstent.id) == -1)
		logwarn("%s error %x", __func__, peer->sesstent.id);

	peer->sesstent.state = STINACTIVE;
	peer->sesstent.id = -1;
	peer->sesstent.lastreq = 0;
}

static void
sessnextclear(struct peer *peer, int keysset)
{
	if (keysset) {
		EVP_AEAD_CTX_cleanup(&peer->sessnext.sendctx);
		EVP_AEAD_CTX_cleanup(&peer->sessnext.recvctx);
	}

	peer->sessnext.state = SNINACTIVE;
	peer->sessnext.id = -1;
	peer->sessnext.peerid = -1;
	peer->sessnext.lastvrfyinit = 0;
	peer->sessnext.start = 0;
}

/*
 * Initialize a newly allocated current slot based on the "peer"s next session.
 * If a current session already exists, roll it into prev, if a previous session
 * exists, destroy and free it.
 *
 * Allocate new memory to randomize the position on the heap.
 *
 * Return 0 on success and -1 on error with errno set.
 */
static int
rollcurrsess(struct peer *peer)
{
	if (peer->sprev) {
		sessdestroy(peer->sprev);
		peer->sprev = NULL;
	}

	peer->sprev = peer->scurr;

	if ((peer->scurr = malloc(sizeof(struct session))) == NULL)
		return -1;

	return 0;
}

/*
 * Initialize a newly allocated current slot based on the "peer"s tent session.
 * If a current session already exists, roll it into prev, if a previous session
 * exists, destroy and free it. Also notify the proxy of the new current
 * session.
 *
 * Return 0 on success, -1 on failure.
 */
static int
maketentcurr(struct peer *peer, const struct msgsesskeys *msk)
{
	if (rollcurrsess(peer) == -1)
		return -1;

	peer->scurr->initiator = 1;
	peer->scurr->id = peer->sesstent.id;
	peer->scurr->peerid = le32toh(msk->peersessid);
	peer->scurr->start = now;
	peer->scurr->peer = peer;
	peer->scurr->kaset = 0;
	peer->scurr->expack = 0;
	peer->scurr->nextnonce = 0;
	memset(&peer->scurr->arrecv, 0, sizeof(peer->scurr->arrecv));

	if (EVP_AEAD_CTX_init(&peer->scurr->sendctx, aead,
	    msk->sendkey, KEYLEN, TAGLEN, NULL) == 0)
		return -1;

	if (EVP_AEAD_CTX_init(&peer->scurr->recvctx, aead,
	    msk->recvkey, KEYLEN, TAGLEN, NULL) == 0)
		return -1;

	sesstentclear(peer, 1);

	return 0;
}

/*
 * Initialize a newly allocated current slot based on the "peer"s next session.
 * If a current session already exists, roll it into prev, if a previous session
 * exists, destroy and free it. Also notify the proxy of the new current
 * session.
 *
 * Return 0 on success, -1 on failure.
 */
static int
makenextcurr(struct peer *peer)
{
	if (rollcurrsess(peer) == -1)
		return -1;

	peer->scurr->initiator = 0;
	peer->scurr->id = peer->sessnext.id;
	peer->scurr->peerid = peer->sessnext.peerid;
	peer->scurr->start = peer->sessnext.start;
	peer->scurr->peer = peer;
	peer->scurr->kaset = 0;
	peer->scurr->expack = 0;
	peer->scurr->nextnonce = 0;
	memset(&peer->scurr->arrecv, 0, sizeof(peer->scurr->arrecv));
	memcpy(&peer->scurr->sendctx, &peer->sessnext.sendctx,
	    MIN(sizeof peer->scurr->sendctx, sizeof peer->sessnext.sendctx));
	memcpy(&peer->scurr->recvctx, &peer->sessnext.recvctx,
	    MIN(sizeof peer->scurr->recvctx, sizeof peer->sessnext.recvctx));

	explicit_bzero(&peer->sessnext, sizeof(peer->sessnext));
	peer->sessnext.id = -1;
	peer->sessnext.peerid = -1;

	return 0;
}

/*
 * Send a MSGWGDATA message. The caller is responsible for encrypting "packet".
 *
 * Output format: WireGuard Transport Data Message
 *
 * Return 0 on success, -1 on error.
 */
static int
sendwgdatamsg(int s, uint32_t receiver, uint64_t counter, const uint8_t *packet,
    size_t packetsize)
{
	static struct iovec iov[4];
	static uint64_t lecounter;
	static uint32_t mtcode, lereceiver;
	ssize_t rc;

	lecounter = htole64(counter);
	lereceiver = htole32(receiver);
	mtcode = htole32(4);

	/* empty data packets still have a 16 byte authentication tag */
	if (packetsize < 16)
		return -1;

	iov[0].iov_base = &mtcode;
	iov[0].iov_len = sizeof(mtcode);

	iov[1].iov_base = &lereceiver;
	iov[1].iov_len = sizeof(lereceiver);

	iov[2].iov_base = &lecounter;
	iov[2].iov_len = sizeof(lecounter);

	iov[3].iov_base = (uint8_t *)packet;
	iov[3].iov_len = packetsize;

	rc = writev(s, iov, 4);
	if (rc < DATAHEADERLEN) {
		logwarn("error sending data to %x", receiver);
		return -1;
	}

	if ((size_t)rc - DATAHEADERLEN != packetsize)
		return -1;

	return 0;
}

/*
 * Encrypt data, send on connected socket and update session.
 *
 * Return 0 on success, -1 on failure.
 */
static int
encryptandsend(void *out, size_t outsize, const void *in, size_t insize,
    struct session *sess)
{
	size_t padlen;

	if (insize == 0) {
		/* keepalive */
		padlen = 0;
	} else {
		padlen = ((insize + 15) / 16) * 16;
	}

	if (verbose > 2)
		logdebugx("packet size %zu padded %zu", insize, padlen);

	if (padlen > outsize) {
		logwarnx("truncating padded %zu to %zu", padlen, outsize);
		padlen = outsize;
	}

	*(uint64_t *)&nonce[4] = htole64(sess->nextnonce);
	if (EVP_AEAD_CTX_seal(&sess->sendctx, out, &outsize, outsize, nonce,
	    sizeof(nonce), in, padlen, NULL, 0) == 0) {
		stats.sockouterr++;
		return -1;
	}

	if (sendwgdatamsg(sess->peer->sock, sess->peerid, sess->nextnonce, out,
	    outsize) == -1) {
		logwarnx("error sending data to %s", sess->peer->name);
		return -1;
	}

	stats.sockout++;
	stats.sockoutsz += outsize;

	sess->nextnonce++;

	if (sess->kaset) {
		if (cleartimer(sess->id) == -1)
			return -1;

		sess->kaset = 0;
	}

	if (insize > 0 && sess->expack == 0)
		sess->expack = now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;

	if (verbose > 1)
		loginfox("encapsulated %zu bytes into %zu for %s", padlen,
		    outsize, sess->peer->name);

	/*
	 * Handle session limits.
	 */

	if (sess->nextnonce == REKEY_AFTER_MESSAGES) {
		ensurehs(sess->peer);
		return 0;
	}

	if (sess->initiator && sess->start <= now - REKEY_AFTER_TIME &&
	    sess == sess->peer->scurr) {
		ensurehs(sess->peer);
		return 0;
	}

	return 0;
}

/*
 * Decrypt a WGDATA message into "out".
 *
 * Returns the payload size of the packet on success, -1 otherwise.
 */
static ssize_t
decryptpacket(uint8_t *out, size_t outsize, struct msgwgdatahdr *mwdhdr,
    size_t mwdsize, EVP_AEAD_CTX *key, uint32_t peersessid)
{
	uint8_t *payload;
	size_t payloadsize;

	if (outsize < mwdsize)
		return -1;

	if (payloadoffset(&payload, &payloadsize, mwdhdr, mwdsize) == -1) {
		stats.corrupted++;
		return -1;
	}

	/* prepend a tunnel header */
	*(uint64_t *)&nonce[4] = mwdhdr->counter;
	if (EVP_AEAD_CTX_open(key, out, &outsize, outsize, nonce,
	    sizeof(nonce), payload, payloadsize, NULL, 0) == 0) {
		logwarnx("unauthenticated data received, UDP data: %zu, WG "
		    "data: %zu, peer session id: counter: %llu", mwdsize,
		    payloadsize, peersessid, le64toh(mwdhdr->counter));
		stats.corrupted++;
		return -1;
	}

	return outsize;
}

/*
 * Find a peer based on the source of an ip4 or ip6 packet.
 *
 * Return 1 if a peer with a matching route is found and updates "peer" to point
 * to it as well as "addr" to the addr that matched. Returns 0 if no peer is
 * found. Return -1 on error.
 */
static int
ipsrc2peer(struct peer **peer, struct cidraddr **addr, const uint8_t *packet,
    size_t packetsize)
{
	struct ip6_hdr *ip6hdr;
	struct ip *ip4hdr;

	/* ip version is in the first four bits of the packet */
	switch(packet[0] >> 4) {
	case 6:
		if (packetsize < MINIP6HDR)
			return -1;

		ip6hdr = (struct ip6_hdr *)packet;
		return peerbyroute6(peer, addr, &ip6hdr->ip6_src);
	case 4:
		if (packetsize < MINIP4HDR)
			return -1;

		ip4hdr = (struct ip *)packet;
		return peerbyroute4(peer, addr, &ip4hdr->ip_src);
	}

	return 0;
}

/*
 * Send "frame" to the tunnel device. It is expected that "frame" consists of
 * TUNHDRSIZ bytes that can be used for the tunnel header, followed by the
 * actual ip packet.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
forward2tun(uint8_t *frame, size_t framesize, const struct peer *peer)
{
	struct peer *routedpeer;
	struct cidraddr *addr;
	uint8_t *ippacket;
	size_t ippacketsize;
	int rc;

	if (framesize < TUNHDRSIZ + MINIPHDR) {
		stats.corrupted++;
		return -1;
	}

	ippacket = &frame[TUNHDRSIZ];
	ippacketsize = framesize - TUNHDRSIZ;
	rc = ipsrc2peer(&routedpeer, &addr, ippacket, ippacketsize);

	if (rc == -1) {
		logwarnx("decrypted packet from %s contains invalid ip packet",
		    peer->name);

		stats.corrupted++;
		return -1;
	}

	if (rc == 0) {
		logwarnx("ip packet from %s could not be routed", peer->name);

		stats.invalidpeer++;
		return -1;
	}

	if (routedpeer->id != peer->id) {
		logwarnx("ip packet from %s with a source address of %s "
		    "received", peer->name, routedpeer->name);

		stats.invalidpeer++;
		return -1;
	}

	*(uint32_t *)frame = htonl(addr->addr.h.family);

	if (writen(tund, frame, framesize) != 0) {
		logwarn("writen tund");
		stats.devouterr++;
		return -1;
	}

	stats.devout++;
	stats.devoutsz += ippacketsize;

	return 0;
}

/*
 * Handle the first packet of a next session. Decrypt data, forward to tunnel
 * and rotate session to current.
 *
 * Return 0 on success, -1 on failure.
 */
static int
handlenextdata(uint8_t *out, size_t outsize, struct msgwgdatahdr *mwdhdr,
    size_t mwdsize, struct peer *peer)
{
	ssize_t payloadsize;

	if (peer->sessnext.start < now - REJECT_AFTER_TIME) {
		if (verbose > -1)
			logwarnx("first packet for next session arrived too "
			    "late", peer->name);

		if (notifyproxy(peer->id, peer->sessnext.id, SESSIDDESTROY)
		    == -1)
			logwarnx("proxy notification that the next session is "
			    "dead failed");

		sessnextclear(peer, 1);

		stats.sockinerr++;
		return -1;
	}

	/* leave room in "out" for the tunnel header */
	payloadsize = decryptpacket(&out[TUNHDRSIZ], outsize - TUNHDRSIZ,
	    mwdhdr, mwdsize, &peer->sessnext.recvctx, peer->sessnext.peerid);

	if (payloadsize < 0)
		return -1;

	/*
	 * Write authenticated and decrypted packet to the tunnel device if it's
	 * an ip4 or ip6 packet. Otherwise treat it as a keepalive.
	 */
	if (payloadsize >= MINIPHDR) {
		if (forward2tun(out, TUNHDRSIZ + payloadsize, peer) == -1)
			return -1;
	} else {
		loginfox("%s unexpected keepalive at start of next sesssion, "
		    "payload size %zd", __func__, payloadsize);
	}

	/* 4. handlewgdatafrompeer part 2/2 */
	if (makenextcurr(peer) == -1) {
		if (verbose > -1)
			logwarnx("could not make next session of %s "
			    "current", peer->name);

		stats.invalidpeer++;
		return -1;
	}

	if (notifyproxy(peer->id, peer->scurr->id, SESSIDCURR) == -1)
		logwarnx("proxy notification that the next session is now the "
		    "current session failed");

	if (verbose > 1)
		loginfox("%s: %x %zu bytes", peer->name, peer->scurr->id,
		    payloadsize);

	return 0;
}

/*
 * Handle data of an established session (either curr or prev).
 * Decrypt data, forward to tunnel and update session.
 *
 * Return 0 on success, -1 on failure.
 */
static int
handlesessdata(uint8_t *out, size_t outsize, struct msgwgdatahdr *mwdhdr,
    size_t mwdsize, struct session *sess)
{
	uint64_t counter;
	ssize_t payloadsize;

	if (!sessactive(sess)) {
		logwarnx("data for unusable session received %x",
		    le32toh(mwdhdr->receiver));
		stats.sockinerr++;
		return -1;
	}

	counter = le64toh(mwdhdr->counter);

	if (!antireplay_isnew(&sess->arrecv, counter)) {
		if (verbose > -1)
			logwarnx("data replayed %llu %llu", counter,
			    sess->arrecv.maxseqnum);

		stats.corrupted++;
		return -1;
	}

	/* leave room in "out" for the tunnel header */
	payloadsize = decryptpacket(&out[TUNHDRSIZ], outsize - TUNHDRSIZ,
	    mwdhdr, mwdsize, &sess->recvctx, sess->peerid);

	if (payloadsize < 0)
		return -1;

	sess->expack = 0;

	if (antireplay_update(&sess->arrecv, counter) == -1) {
		logwarnx("antireplay_update %llu", counter);
		return -1;
	}

	/*
	 * Write authenticated and decrypted packet to the tunnel device if it's
	 * an ip4 or ip6 packet. Otherwise treat it as a keepalive.
	 */
	if (payloadsize >= MINIPHDR) {
		if (forward2tun(out, TUNHDRSIZ + payloadsize, sess->peer) == -1)
			return -1;

		/*
		 * Schedule a keepalive timeout if this was not already the case
		 * and only if we're not near the end of the session.
		 */
		if (sess->kaset == 0 &&
		    now - sess->start < REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT &&
		    sess->nextnonce < REJECT_AFTER_MESSAGES) {
			settimer(sess->id, KEEPALIVE_TIMEOUT);
			sess->kaset = 1;
		}
	}

	/*
	 * Start a new handshake procedure if this is a current session and we
	 * are the initiator and the end of this session is near.
	 */
	if (sess->initiator && sess == sess->peer->scurr && now - sess->start >=
	    (REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT))
		ensurehs(sess->peer);

	if (verbose > 1)
		loginfox("%s: %x %zd bytes", sess->peer->name, sess->id,
		    payloadsize);

	return 0;
}

/*
 * Receive and handle one of the messages from the enclave.
 *
 * MSGWGINIT
 *   make session id tentative and write to socket
 * MSGWGRESP
 *   initialize next session as responder and write to socket
 * MSGCONNREQ
 *   connect a peer
 * MSGSESSKEYS
 *   new session established, must match "tent" if we are the initiator, or
 *   "next" if we are the responder. If "tent", rotate to "curr".
 *
 * Return 0 on success, -1 on error.
 */
static int
handleenclavemsg(void)
{
	struct qpacket *qp;
	struct msgconnreq *mcr;
	struct msgwginit *mwi;
	struct msgwgresp *mwr;
	struct msgsesskeys *msk;
	struct peer *p;
	uint32_t peerid;
	size_t msgsize;
	ssize_t rc;
	unsigned char mtcode;

	msgsize = sizeof(msg);
	if (wire_recvpeeridmsg(eport, &peerid, &mtcode, msg, &msgsize)
	    == -1)
		logexitx(1, "wire_recvpeeridmsg eport");

	stats.enclin++;

	if (!findpeer(peerid, &p))
		logexit(1, "%s invalid peer id from enclave", __func__);

	switch (mtcode) {
	case MSGWGINIT:
		/* 1. handlewginitfromenclave */
		mwi = (struct msgwginit *)msg;

		if (p->sesstent.state == INITREQ) {
			/*
			 * Reset timer, set session id to the one from the
			 * enclave, send the message to the peer and if this
			 * succeeds schedule a new timer.
			 */
			if (cleartimer(p->sesstent.id) == -1)
				logwarn("%s rekey timer for %x not set",
				    __func__, p->sesstent.id);

			p->sesstent.id = le32toh(mwi->sender);

			rc = write(p->sock, msg, msgsize);
			if (rc < 0) {
				logwarn("%s write MSGWGINIT", __func__);
				stats.sockouterr++;
				stats.initouterr++;
				return -1;
			}
			if ((size_t)rc != msgsize) {
				logwarnx("%s write MSGWGINIT %zd expected %zu",
				    __func__, rc, msgsize);
				stats.sockouterr++;
				stats.initouterr++;
				return -1;
			}
			stats.initout++;
			stats.sockout++;
			stats.sockoutsz += msgsize;

			p->sesstent.state = INITSENT;

			settimer(p->sesstent.id, REKEY_TIMEOUT);

			if (notifyproxy(p->id, p->sesstent.id, SESSIDTENT)
			    == -1)
				logwarnx("proxy notification of a new tentative"
				    " session failed");
		} else {
			lognoticex("WGINIT from enclave not needed, %d %llx %x",
			    p->sesstent.state, p->sesstent.id,
			    le32toh(mwi->sender));
		}
		break;
	case MSGWGRESP:
		/* 3. handlewgrespfromenclave */

		mwr = (struct msgwgresp *)msg;

		if (p->sessnext.state != GOTKEYS) {
			if (verbose > -1)
				logwarnx("unexpectedly received wgresp message "
				    "from the enclave %d", p->sessnext.state);

			stats.sockouterr++;
			stats.respouterr++;
			return -1;
		}

		if (p->sessnext.peerid != le32toh(mwr->receiver)) {
			if (verbose > -1)
				logwarnx("wgresp message from enclave does not "
				    "match last received authenticated "
				    "response: %llx to %x", p->sessnext.peerid,
				    le32toh(mwr->receiver));

			stats.sockouterr++;
			stats.respouterr++;
			return -1;
		}

		p->sessnext.start = now;
		p->sessnext.state = RESPSENT;

		rc = write(p->sock, msg, msgsize);
		if (rc < 0) {
			logwarn("%s write MSGWGRESP", __func__);
			stats.sockouterr++;
			stats.respouterr++;
			return -1;
		}
		if ((size_t)rc != msgsize) {
			logwarnx("%s write MSGWGRESP %zd expected %zu",
			    __func__, rc, msgsize);
			stats.sockouterr++;
			stats.respouterr++;
			return -1;
		}
		stats.respout++;
		stats.sockout++;
		stats.sockoutsz += msgsize;
		if (verbose > 2)
			logdebugx("written MSGWGRESP %zd bytes", rc);
		break;
	case MSGCONNREQ:
		mcr = (struct msgconnreq *)msg;
		if (peerconnect(p, (struct sockaddr *)&mcr->fsa) == -1) {
			stats.sockouterr++;
			return -1;
		}
		break;
	case MSGSESSKEYS:
		msk = (struct msgsesskeys *)msg;
		if (p->sesstent.id == msk->sessid) {
			/* 3. handlesesskeys */
			if (p->sesstent.state != RESPRECVD) {
				logwarnx("MSGSESSKEYS from enclave for "
				    "initiator role unexpected");
				stats.enclinerr++;
				return -1;
			}

			if (maketentcurr(p, msk) == -1) {
				logwarnx("failed to make tentative session the "
				    "current session");
				stats.sockouterr++;
				return -1;
			}

			if (notifyproxy(p->id, p->scurr->id, SESSIDCURR) == -1)
				logwarnx("proxy notification that the tentative"
				    "session is now the current session "
				    "failed");

			if (verbose > 1)
				loginfox("new initiator session %x with %s %x",
				    p->scurr->id,
				    p->scurr->peer->name,
				    p->scurr->peerid);

			if (p->qpackets > 0) {
				while (!SIMPLEQ_EMPTY(&p->qpacketlist)) {
					qp = SIMPLEQ_FIRST(&p->qpacketlist);
					rc = encryptandsend(msg, sizeof(msg), qp->data,
					    qp->datasize, p->scurr);

					if (rc == -1) {
						stats.sockouterr++;
						stats.queueouterr++;
					} else {
						stats.queueout++;
						stats.queueoutsz += qp->datasize;
					}
					SIMPLEQ_REMOVE_HEAD(&p->qpacketlist,
					    qpackets);
					p->qpackets--;
					p->qpacketsdatasz -= qp->datasize;
					free(qp->data);
					qp->data = NULL;
					qp->datasize = 0;
					free(qp);
				}
			}
		} else {
			/* 2. handlekeysfromenclave */
			if (p->sessnext.state != SNINACTIVE &&
			    p->sessnext.state != RESPSENT) {
				logwarnx("MSGSESSKEYS from enclave for "
				    "responder role unexpected");
				stats.enclinerr++;
				return -1;
			}

			/*
			 * XXX use time submitted when forwarding the
			 * corresponding wgresp message to the enclave instead
			 * of a hardcoded value of 2.
			 */
			p->sessnext.lastvrfyinit = now - 2;
			p->sessnext.id = msk->sessid;
			p->sessnext.peerid = msk->peersessid;
			p->sessnext.state = GOTKEYS;

			if (EVP_AEAD_CTX_init(&p->sessnext.sendctx, aead,
			    msk->sendkey, KEYLEN, TAGLEN, NULL) == 0) {
				stats.enclinerr++;
				return -1;
			}

			if (EVP_AEAD_CTX_init(&p->sessnext.recvctx, aead,
			    msk->recvkey, KEYLEN, TAGLEN, NULL) == 0) {
				stats.enclinerr++;
				return -1;
			}

			if (notifyproxy(p->id, p->sessnext.id, SESSIDNEXT)
			    == -1)
				logwarnx("proxy notification of next session "
				    "id failed");

			/*
			 * Only transmit data using this session as soon as the
			 * peer has sent some data. Only then we are guaranteed
			 * the peer is currently in possession of the private
			 * key. At this time there is still a possibility in
			 * where a man-in-the-middle has our private key, but
			 * not the peers private key.
			 */

			if (verbose > 1)
				loginfox("new responder session %x with %s %x",
				    p->sessnext.id,
				    p->name,
				    p->sessnext.peerid);
		}

		break;
	default:
		logexitx(1, "enclave sent an unexpected message %c", mtcode);
	}

	return 0;
}

/*
 * Receive and handle incoming data from the tunnel descriptor.
 *
 * 1. Decide to which peer.
 * 2. See if the peer is connected
 * 3. See if the peer has a current session that is alive
 *      If not, queue packet and ensure handshake
 * Otherwise write a MSGWGDATA to the connected socket using the current
 * session.
 *
 * Return 0 on success, -1 on error.
 */
static int
handletundmsg(void)
{
	struct cidraddr *addr;
	struct qpacket *qp;
	struct peer *p;
	struct ip6_hdr *ip6hdr;
	struct ip *ip4;
	ssize_t rc;
	size_t msgsize;

	/* Cryptokey Routing */

	msgsize = sizeof(msg);
	rc = read(tund, msg, msgsize);
	if (rc < 0)
		logexitx(1, "%s recvfrom tund", __func__);

	msgsize = rc;

	stats.devin++;
	stats.devinsz += msgsize;

	/* expect at least a tunnel and ip header */
	if (rc < TUNHDRSIZ + MINIPHDR) {
		if (verbose > 1)
			loginfox("%s empty message received", __func__);
		stats.devinerr++;
		return -1;
	}

	p = NULL;
	/* expect 4 byte tunnel header */
	switch(ntohl(*(uint32_t *)msg)) {
	case AF_INET6:
		if (msgsize < TUNHDRSIZ + MINIP6HDR)
			logwarnx("invalid ipv6 packet");
		ip6hdr = (struct ip6_hdr *)&msg[TUNHDRSIZ];
		if (!peerbyroute6(&p, &addr, &ip6hdr->ip6_dst)) {
			if (inet_ntop(AF_INET6, &ip6hdr->ip6_dst, (char *)msg,
			    sizeof msg) == NULL)
				logwarn("%s inet_ntop error", __func__);

			lognoticex("no route to %s", msg);

			errno = EHOSTUNREACH;
			stats.devinerr++;
			return -1;
		}
		break;
	case AF_INET:
		if (msgsize < TUNHDRSIZ + MINIP4HDR)
			logwarnx("invalid ipv4 packet");
		ip4 = (struct ip *)&msg[TUNHDRSIZ];
		if (!peerbyroute4(&p, &addr, &ip4->ip_dst)) {
			lognoticex("no route to %s", inet_ntoa(ip4->ip_dst));


			errno = EHOSTUNREACH;
			stats.devinerr++;
			return -1;
		}
		break;
	default:
		if (verbose > -1)
			logwarnx("invalid message from interface %d %zu",
			    ntohl(*(uint32_t *)msg), msgsize);
		stats.devinerr++;
		return -1;
	}

	if (verbose > 1)
		loginfox("packet for %s, using %x", p->name,
		    p->scurr == NULL ? 0x0 : p->scurr->id);

	if (p->sock == -1) {
		errno = EDESTADDRREQ;
		logwarn("peer not connected");
		stats.sockouterr++;
		return -1;
	}

	if (sessactive(p->scurr)) {
		return encryptandsend(msg, sizeof(msg), &msg[TUNHDRSIZ],
		    msgsize - TUNHDRSIZ, p->scurr);
	} else {
		if (p->qpackets >= MAXQUEUEPACKETS) {
			logwarnx("%s queue full %zu packets", __func__,
			    p->qpackets);
			stats.sockouterr++;
			stats.queueinerr++;
			return -1;
		}

		if ((MAXQUEUEPACKETSDATASZ - (msgsize - TUNHDRSIZ)) <
		    p->qpacketsdatasz) {
			logwarnx("%s queue full %zu bytes", __func__,
			    p->qpacketsdatasz);
			stats.sockouterr++;
			stats.queueinerr++;
			return -1;
		}

		if ((qp = malloc(sizeof(*qp))) == NULL) {
			logwarnx("%s malloc failed %zu", __func__, sizeof(*qp));
			stats.sockouterr++;
			stats.queueinerr++;
			return -1;
		}

		qp->datasize = msgsize - TUNHDRSIZ;

		if ((qp->data = malloc(qp->datasize)) == NULL) {
			logwarnx("%s malloc failed %zu", __func__,
			    qp->datasize);
			free(qp);
			stats.sockouterr++;
			stats.queueinerr++;
			return -1;
		}

		memcpy(qp->data, &msg[TUNHDRSIZ], qp->datasize);
		SIMPLEQ_INSERT_TAIL(&p->qpacketlist, qp, qpackets);

		p->qpackets++;
		p->qpacketsdatasz += qp->datasize;

		stats.queuein++;
		stats.queueinsz += qp->datasize;

		ensurehs(p);

		return -1;
	}
}

/*
 * Handle an incoming WGDATA msg. Find session and try to authenticate and
 * decrypt.
 */
static int
handlewgdata(struct msgwgdatahdr *mwdhdr, size_t msgsize, struct peer *p)
{
	uint32_t receiver;

	receiver = le32toh(mwdhdr->receiver);
	if (receiver == p->sessnext.id) {
		if (p->sessnext.state != RESPSENT) {
			logwarnx("data received for next session while"
			    " in unexpected state %x %d", receiver,
			    p->sessnext.state);
			stats.sockinerr++;
			return -1;
		}

		return handlenextdata(msg, sizeof(msg), mwdhdr, msgsize, p);
	} else if (p->scurr && receiver == p->scurr->id) {
		return handlesessdata(msg, sizeof(msg), mwdhdr, msgsize,
		    p->scurr);
	} else if (p->sprev && receiver == p->sprev->id) {
		return handlesessdata(msg, sizeof(msg), mwdhdr, msgsize,
		    p->sprev);
	}

	logwarnx("data with unknown session received %x", receiver);
	stats.sockinerr++;
	return -1;
}

/*
 * Receive and handle a message from the Internet.
 *
 * MSGWGINIT
 *   forward to enclave
 * MSGWGRESP
 *   forward to enclave
 * MSGWGCOOKIE
 *   TODO handle ourselves
 * MSGWGDATA
 *   authenticate, decrypt and forward to tunnel
 *
 * Return 0 on success, -1 on error.
 */
static int
handlesocketmsg(struct peer *p)
{
	struct msgwginit *mwi;
	struct msgwgresp *mwr;
	ssize_t rc;
	size_t msgsize;
	unsigned char mtcode;

	rc = read(p->sock, msg, sizeof(msg));
	if (rc < 0) {
		logwarn("%s read error", __func__);
		stats.sockinerr++;
		peerpark(p);
		return -1;
	}

	msgsize = rc;

	stats.sockin++;
	stats.sockinsz += msgsize;

	if (rc < 1) {
		if (verbose > 1)
			loginfox("%s empty read", __func__);
		stats.sockinerr++;
		return -1;
	}

	mtcode = msg[0];
	if (mtcode >= MTNCODES) {
		logwarnx("%s unexpected message code got %d",
		    __func__, mtcode);
		stats.sockinerr++;
		return -1;
	}

	if (msgtypes[mtcode].varsize) {
		if (msgsize < msgtypes[mtcode].size) {
			logwarnx("expected at least %zu bytes instead of %zu",
			    msgtypes[mtcode].size, msgsize);
			stats.sockinerr++;
			return -1;
		}
	} else if (msgsize != msgtypes[mtcode].size) {
		logwarnx("%s expected message size %zu, got %zu",
		    __func__, msgtypes[mtcode].size, msgsize);
		stats.sockinerr++;
		return -1;
	}

	switch (msg[0]) {
	case MSGWGINIT:
		/* 1. handlewginitfrompeer */
		stats.initin++;

		if (now - p->sessnext.lastvrfyinit < REKEY_TIMEOUT) {
			logwarnx("%s is flooding us with wginit messages, "
			    "previous wginit only %dms ago", p->name,
			    now - p->sessnext.lastvrfyinit);
			stats.sockinerr++;
			stats.initinerr++;
			return -1;
		}

		mwi = (struct msgwginit *)msg;
		if (!ws_validmac(mwi->mac1, sizeof(mwi->mac1), mwi,
		    MAC1OFFSETINIT, ifn->mac1key)) {
			logwarnx("MSGWGINIT invalid mac1");
			stats.sockinerr++;
			stats.initinerr++;
			stats.invalidmac++;
			return -1;
		}

		/*
		 * XXX prepend current timestamp, to be used later on receiving
		 * the session keys if the packet turns out to be valid.
		 */
		if (wire_sendpeeridmsg(eport, p->id, MSGWGINIT, mwi,
		    sizeof(*mwi)) == -1)
			logexitx(1, "wire_sendpeeridmsg MSGWGINIT");
		break;
	case MSGWGRESP:
		/* 2. handlewgrespfrompeer */
		stats.respin++;

		mwr = (struct msgwgresp *)msg;
		if (p->sesstent.id == le32toh(mwr->receiver) &&
		    (p->sesstent.state == INITSENT ||
		     p->sesstent.state == RESPRECVD)) {
			if (!ws_validmac(mwr->mac1, sizeof(mwr->mac1), mwr,
			    MAC1OFFSETRESP, ifn->mac1key)) {
				logwarnx("MSGWGRESP invalid mac1");
				stats.sockinerr++;
				stats.respinerr++;
				stats.invalidmac++;
				return -1;
			}

			if (wire_sendpeeridmsg(eport, p->id, MSGWGRESP, mwr,
			    sizeof(*mwr)) == -1)
				logexitx(1, "wire_sendpeeridmsg MSGWGRESP");

		     p->sesstent.state = RESPRECVD;
		     return 0;
		}

		lognoticex("wgresp from peer too late or unknown receiver %x",
			    le32toh(mwr->receiver));
			stats.sockinerr++;
			stats.respinerr++;
			return -1;
		break;
	case MSGWGCOOKIE:
		logwarnx("%s cookies are unsupported", __func__);
		break;
	case MSGWGDATA:
		/* 4. handlewgdatafrompeer part 1/2 */
		if (handlewgdata((struct msgwgdatahdr *)msg, msgsize, p) == -1)
			return -1;

		break;
	default:
		logwarnx("received unknown message type %d", msg[0]);
		stats.sockinerr++;
		return -1;
	}

	return 0;
}

/*
 * Receive and handle one of the messages from the proxy.
 *
 * MSGWGDATA
 *   if data authenticates, reconnect the peer and forward data to tund
 *
 * Return 0 on success, -1 on error.
 */
static int
handleproxymsg(void)
{
	union sockaddr_inet fsa, lsa;
	struct msgwgdatahdr *mwdhdr;
	struct peer *p;
	size_t msgsize;
	uint32_t ifnid;
	unsigned char mtcode;

	msgsize = sizeof(msg);
	if (wire_recvproxymsg(pport, &ifnid, &lsa, &fsa, &mtcode, msg,
	    &msgsize) == -1)
		logexitx(1, "wire_recvproxymsg pport");

	stats.proxin++;

	if (ifnid != ifn->id) {
		logwarnx("unknown interface id from proxy: %d", ifnid);
		stats.proxinerr++;
		return -1;
	}

	switch (mtcode) {
	case MSGWGDATA:
		mwdhdr = (struct msgwgdatahdr *)msg;
		if (!findpeerbysessid(le32toh(mwdhdr->receiver), &p)) {
			logwarnx("invalid session id via proxy");
			stats.proxinerr++;
			return -1;
		}

		if (handlewgdata(mwdhdr, msgsize, p) == -1) {
			logwarnx("data for unusable session received via "
			    "proxy");
			stats.proxinerr++;
			return -1;
		}

		if (peerconnect(p, (struct sockaddr *)&fsa) == -1) {
			stats.sockouterr++;
			return -1;
		}

		break;
	default:
		logwarnx("proxy sent unknown message %c", mtcode);
		stats.proxinerr++;
		return -1;
	}

	return 0;
}

/*
 * Convert a timespec to a single 64-bit integer with microsecond precision.
 */
static utime_t
utime(const struct timespec *tp)
{
	utime_t rc;

	rc = tp->tv_sec * 1000000;
	rc += tp->tv_nsec / 1000;

	return rc;
}

/*
 * Handle rekey- and keepalive session timeout.
 */
static void
sesshandletimeout(struct kevent *ev)
{
	struct session *sess;
	struct peer *peer;

	if (verbose > 1)
		loginfox("handling timer event id %lx", ev->ident);

	if (!findpeerbysessid(ev->ident, &peer)) {
		logwarnx("timer with unknown session id went off %lx",
		    ev->ident);
		return;
	}

	if (peer->sesstent.id >= 0 &&
	    ev->ident == (uint32_t)peer->sesstent.id) {
		lognoticex("Rekey-Timeout %x %s", peer->sesstent.id,
		    peer->name);

		/*
		 * This timeout can also happen if the enclave is unresponsive,
		 * in that case the tentative id was not communicated to the
		 * proxy and only used as a rekey timeout timer.
		 */
		if (peer->sesstent.state >= INITSENT) {
			if (notifyproxy(peer->id, peer->sesstent.id,
			    SESSIDDESTROY) == -1)
				logwarnx("proxy notification of destroyed "
				    "tentative session id failed");
		}

		/*
		 * Request a new handshake init message from the enclave as long
		 * as within Rekey-Attempt-Time.
		 */
		if (now - peer->sesstent.lastreq <= REKEY_ATTEMPT_TIME) {
			sendreqhsinit(peer);
		} else {
			sesstentclear(peer, 0);
		}

		return;
	}

	/*
	 * Must be a keepalive on either the current or the previous session.
	 */

	if (peer->scurr && ev->ident == peer->scurr->id) {
		sess = peer->scurr;
	} else if (peer->sprev && ev->ident == peer->sprev->id) {
		sess = peer->sprev;
	} else {
		logwarnx("timer with unknown session id went off %lx",
		    ev->ident);
		return;
	}

	lognoticex("Keepalive-Timeout %x %s", sess->id, sess->peer->name);

	sess->kaset = 0;

	if (encryptandsend(msg, sizeof(msg), NULL, 0, sess) == -1)
		logwarn("%s encryptandsend error", __func__);
}

/*
 * Setup read listeners for:
 *    proxy port
 *    enclave port
 *    tunnel device
 *
 * Handle events.
 *
 * Exit on error.
 *
 * TODO
 *     MSGWGCOOKIE -> csock
 */
void
ifn_serv(void)
{
	struct peer *peer;
	struct kevent *ev;
	struct timespec ts;
	size_t evsize, maxevsize, n;
	int nev, i;

	if ((kq = kqueue()) == -1)
		logexit(1, "kqueue");

	/*
	 * Allocate space for events on eport, pport and tund and future
	 * per-peer events. Each peer has:
	 *    four sessions, one socket and two timers;
	 */
	evsize = 3;
	maxevsize = evsize + ifn->peerssize * (4 + 1 + 2);
	if ((ev = calloc(maxevsize, sizeof(*ev))) == NULL)
		logexit(1, "calloc ev");

	EV_SET(&ev[0], eport, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&ev[1], pport, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&ev[2], tund, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(kq, ev, evsize, NULL, 0, NULL) == -1)
		logexit(1, "kevent");

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		logexit(1, "%s clock_gettime", __func__);
	now = utime(&ts);

	/* Connect to peers with known end-points. */
	for (n = 0; n < ifn->peerssize; n++) {
		peer = ifn->peers[n];
		if ((peer->fsa.h.family == AF_INET6 ||
		    peer->fsa.h.family == AF_INET) &&
		    peerconnect(peer, (struct sockaddr *)&peer->fsa) == -1)
			logwarnx("peerconnect error when connecting to known "
			    "endpoint");
	}

	for (;;) {
		if (logstats) {
			ifn_loginfo();
			logstats = 0;
		}

		if (doterm)
			logexitx(1, "received TERM, shutting down");

		if ((nev = kevent(kq, NULL, 0, ev, maxevsize, NULL)) == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				logexit(1, "kevent");
			}
		}

		if (nev == 0) {
			lognoticex("kevent == 0");
			continue;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
			logexit(1, "%s clock_gettime", __func__);
		now = utime(&ts);

		for (i = 0; i < nev; i++) {
			if (ev[i].filter == EVFILT_TIMER) {
				if (verbose > 1)
					loginfox("timer event");

				/* session timer */
				sesshandletimeout(&ev[i]);
			} else if ((int)ev[i].ident == eport) {
				if (verbose > 1)
					loginfox("enclave event");

				if (handleenclavemsg() == -1)
					logwarnx("enclave error");
			} else if ((int)ev[i].ident == tund) {
				if (verbose > 1)
					loginfox("tun event");

				handletundmsg();
			} else if ((int)ev[i].ident == pport) {
				if (verbose > 1)
					loginfox("proxy event");

				if (handleproxymsg() == -1)
					logwarnx("proxy error");
			} else {
				/* find peer by socket */
				/* XXX log(n) */
				for (peer = NULL, n = 0; n < ifn->peerssize &&
				    peer == NULL; n++) {
					if ((int)ev[i].ident ==
					    ifn->peers[n]->sock) {
						peer = ifn->peers[n];
					}
				}
				if (peer) {
					/* INCOMING DATA */
					if (verbose > 1)
						loginfox("socket event");
					handlesocketmsg(peer);
				} else {
					logwarnx("event undetermined %lx",
					    ev[i].ident);
				}
			}
		}
	}
}

/*
 * Open and bring up a tunnel device.
 *
 * Return a new tunnel descriptor on success, -1 on error with errno set.
 */
static int
opentunnel(const char *ifname, const char *ifdesc, int setflags)
{
	struct ifreq ifr;
	struct tuninfo tuninfo;
	int s, tund;
	char *cp;

	if (asprintf(&cp, "/dev/%s", ifname) < 1)
		return -1;

	tund = open(cp, O_RDWR);
	free(cp);
	cp = NULL;
	if (tund == -1)
		return -1;

	if (setflags) {
		if (verbose > 1)
			loginfox("configuring %s", ifname);

#ifdef TUNSIFHEAD /* FreeBSD */
	const int on = 1;
	if (ioctl(tund, TUNSIFHEAD, &on) == -1) {
		close(tund);
		return -1;
	}
#endif /* TUNSIFHEAD */

		if (ioctl(tund, TUNGIFINFO, &tuninfo) == -1)
			return -1;

		tuninfo.flags &= ~IFF_POINTOPOINT;
		tuninfo.mtu = wsTUNMTU;

		if (ioctl(tund, TUNSIFINFO, &tuninfo) == -1)
			return -1;
	} else {
		if (verbose > 1)
			loginfox("%s is manually configured", ifname);
	}

	if (ifdesc && strlen(ifdesc) > 0) {
		memcpy(ifr.ifr_name, ifname, MIN(sizeof ifr.ifr_name,
		    strlen(ifname) + 1));
		ifr.ifr_data = (caddr_t)ifdesc;
		if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
			logexitx(1, "socket");
		if (ioctl(s, SIOCSIFDESCR, &ifr) == -1)
			logexit(1, "%s ioctl SIOCSIFDESCR", __func__);
		if (close(s) == -1)
			return -1;
	}

	return tund;
}

/*
 * Return a newly allocated peer on success, NULL on failure.
 *
 * The caller should never free the allocated structure.
 */
static struct peer *
peernew(uint32_t id, const char *name, size_t nallowedips,
    const union sockaddr_inet *faddr)
{
	struct peer *peer;

	if ((peer = malloc(sizeof(*peer))) == NULL)
		logexit(1, "%s malloc peer", __func__);

	peer->id = id;
	peer->name = strdup(name);
	peer->sock = -1;
	peer->sockisv6 = 0;
	peer->portsock6 = NULL;
	peer->portsock4 = NULL;
	peer->portsock6count = 0;
	peer->portsock4count = 0;
	peer->prefixlen = 0;
	peer->qpackets = 0;
	peer->qpacketsdatasz = 0;
	SIMPLEQ_INIT(&peer->qpacketlist);
	peer->allowedipssize = nallowedips;

	memcpy(&peer->fsa, faddr, MIN(sizeof peer->fsa, sizeof *faddr));

	peer->allowedips = reallocarray(NULL, peer->allowedipssize,
	    sizeof *peer->allowedips);
	if (peer->allowedips == NULL)
		logexit(1, "reallocarray peer->allowedips error");

	sesstentclear(peer, 0);
	sessnextclear(peer, 0);
	peer->scurr = peer->sprev = NULL;

	return peer;
}

/*
 * Add a new portsock mapping to the peers array of port sock mappings.
 *
 * Creates new parked sockets with the local port set to "port". Unlike the
 * local address, the local port of a socket can not change between multiple
 * calls to connect(2). "port" must be in network byte order.
 *
 * Exit on failure.
 */
static void
xaddportsock(struct peer *peer, in_port_t port, int isv6)
{
	union sockaddr_inet src;
	const int on = 1;
	struct sockaddr *sa;
	struct portsock *ps;
	socklen_t len;

	if (isv6) {
		peer->portsock6count += 1;
		peer->portsock6 = reallocarray(peer->portsock6,
		    peer->portsock6count, sizeof(struct portsock));
		if (peer->portsock6 == NULL)
			logexit(1, "reallocarray of a new portsock failed");

		ps = &peer->portsock6[peer->portsock6count - 1];
		ps->p = port;
		ps->s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (ps->s == -1)
			logexit(1, "%s socket error", __func__);

		sa = (struct sockaddr *)&src.v6;
	} else {
		peer->portsock4count += 1;
		peer->portsock4 = reallocarray(peer->portsock4,
		    peer->portsock4count, sizeof(struct portsock));
		if (peer->portsock4 == NULL)
			logexit(1, "reallocarray of a new portsock failed");

		ps = &peer->portsock4[peer->portsock4count - 1];
		ps->p = port;
		ps->s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (ps->s == -1)
			logexit(1, "%s socket error", __func__);

		sa = (struct sockaddr *)&src.v4;
	}

	setsockaddr(sa, NULL, isv6, port);

	if (setsockopt(ps->s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) == -1)
		logexit(1, "setsockopt reuseaddr error");

	len = MAXRECVBUF;
	if (setsockopt(ps->s, SOL_SOCKET, SO_RCVBUF, &len, sizeof len) == -1)
		logexit(1, "setsockopt rcvbuf error");

	if (bind(ps->s, sa, sa->sa_len) == -1)
		logexit(1, "%s bind on port %u failed", __func__, ntohs(port));

	/* activate so we can park the socket */
	peer->sock = ps->s;
	peer->sockisv6 = isv6;
	if (peerpark(peer) == -1)
		logexit(1, "%s peerpark failed", __func__);
}

/*
 * Receive configuration from the master.
 *
 * SINIT
 * SIFN
 * SPEER
 * SALLOWEDIP
 *
 * Exit on error.
 */
static void
recvconfig(int masterport)
{
	char addrstr[MAXADDRSTR];
	union inet_addr inet_addr;
	static union {
		struct sinit init;
		struct sifn ifn;
		struct speer peer;
		struct scidraddr cidraddr;
		struct seos eos;
	} smsg;
	struct cidraddr *ifaddr, *allowedip, *addr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct peer *peer, *peer2;
	size_t m, msgsize, n, i;
	unsigned char mtcode;
	char addrp[INET6_ADDRSTRLEN];

	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
		logexitx(1, "wire_recvmsg SINIT %d", masterport);
	if (mtcode != SINIT)
		logexitx(1, "mtcode SINIT %d", mtcode);

	background = smsg.init.background;
	verbose = smsg.init.verbose;
	uid = smsg.init.uid;
	gid = smsg.init.gid;
	eport = smsg.init.enclport;
	pport = smsg.init.proxport;

	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
		logexitx(1, "wire_recvmsg SIFN");
	if (mtcode != SIFN)
		logexitx(1, "mtcode SIFN");

	if ((ifn = malloc(sizeof(*ifn))) == NULL)
		logexit(1, "malloc ifn");

	ifn->id = smsg.ifn.ifnid;
	ifn->peerssize = smsg.ifn.npeers;
	ifn->ifname = strdup(smsg.ifn.ifname);
	if (strlen(smsg.ifn.ifdesc) > 0)
		ifn->ifdesc = strdup(smsg.ifn.ifdesc);
	else
		ifn->ifdesc = NULL;

	ifn->ifaddrssize = smsg.ifn.nifaddrs;
	ifn->laddr6count = smsg.ifn.laddr6count;
	ifn->laddr4count = smsg.ifn.laddr4count;
	memcpy(ifn->mac1key, smsg.ifn.mac1key,
	    MIN(sizeof ifn->mac1key, sizeof smsg.ifn.mac1key));
	memcpy(ifn->cookiekey, smsg.ifn.cookiekey,
	    MIN(sizeof ifn->cookiekey, sizeof smsg.ifn.cookiekey));

	ifn->ifaddrs = calloc(ifn->ifaddrssize, sizeof *ifn->ifaddrs);
	if (ifn->ifaddrs == NULL)
		logexit(1, "calloc ifn->ifaddrs");

	ifn->peers = calloc(ifn->peerssize, sizeof *ifn->peers);
	if (ifn->peers == NULL)
		logexit(1, "calloc ifn->peers");

	ifn->laddr6 = calloc(ifn->laddr6count, sizeof *ifn->laddr6);
	if (ifn->laddr6 == NULL)
		logexit(1, "calloc ifn->laddr6");

	ifn->laddr4 = calloc(ifn->laddr4count, sizeof *ifn->laddr4);
	if (ifn->laddr4 == NULL)
		logexit(1, "calloc ifn->laddr4");

	/* first receive all interface addresses */
	for (n = 0; n < ifn->ifaddrssize; n++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "wire_recvmsg SCIDRADDR");
		if (mtcode != SCIDRADDR)
			logexitx(1, "mtcode SCIDRADDR");

		assert(smsg.cidraddr.ifnid == ifn->id);

		if ((ifaddr = malloc(sizeof(*ifaddr))) == NULL)
			logexit(1, "malloc ifaddr");

		ifaddr->prefixlen = smsg.cidraddr.prefixlen;
		memcpy(&ifaddr->addr, &smsg.cidraddr.addr,
		    MIN(sizeof ifaddr->addr, sizeof smsg.cidraddr.addr));

		ifn->ifaddrs[n] = ifaddr;

		/* pre-calculate in masks */
		if (ifaddr->addr.h.family == AF_INET6) {
			memset(&ifaddr->v6mask, 0xff, 16);
			maskip6(&ifaddr->v6mask, &ifaddr->v6mask,
			    ifaddr->prefixlen, 1);

			sin6 = (struct sockaddr_in6 *)&ifaddr->addr;
			maskip6(&ifaddr->v6addrmasked, &sin6->sin6_addr,
			    ifaddr->prefixlen, 1);
		} else if (ifaddr->addr.h.family == AF_INET) {
			assert(ifaddr->prefixlen <= 32);

			ifaddr->v4mask.s_addr = htonl(((1UL << 32) - 1) <<
			    (32 - ifaddr->prefixlen));

			sin = (struct sockaddr_in *)&ifaddr->addr;
			ifaddr->v4addrmasked.s_addr =
			    sin->sin_addr.s_addr & ifaddr->v4mask.s_addr;

			if (verbose > 1)
				loginfox("%s %s/%zu",
				    ifn->ifname,
				    inet_ntoa(sin->sin_addr),
				    ifaddr->prefixlen);
		} else {
			logexitx(1, "illegal address family");
		}
	}

	/* then receive all listen addresses, first v6, then v4 */
	for (n = 0; n < ifn->laddr6count; n++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "wire_recvmsg SCIDRADDR");
		if (mtcode != SCIDRADDR)
			logexitx(1, "mtcode SCIDRADDR");

		assert(smsg.cidraddr.ifnid == ifn->id);

		memcpy(&ifn->laddr6[n], &smsg.cidraddr.addr,
		    MIN(sizeof *ifn->laddr6, sizeof smsg.cidraddr.addr));
	}

	for (n = 0; n < ifn->laddr4count; n++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "wire_recvmsg SCIDRADDR");
		if (mtcode != SCIDRADDR)
			logexitx(1, "mtcode SCIDRADDR");

		assert(smsg.cidraddr.ifnid == ifn->id);

		/* TODO check for dupes */
		memcpy(&ifn->laddr4[n], &smsg.cidraddr.addr,
		    MIN(sizeof *ifn->laddr4, sizeof smsg.cidraddr.addr));
	}

	/* ensure at least one local address */

	if (ifn->laddr6count == 0) {
		ifn->laddr6 = malloc(sizeof *ifn->laddr6);
		if (ifn->laddr6 == NULL)
			logexit(1, "malloc error ifn->laddr6");
		ifn->laddr6count = 1;

		if (inet_pton(AF_INET6, "::1", &inet_addr.addr6) != 1)
			logexit(1, "inet_pton error ::1");

		setsockaddr((struct sockaddr *)ifn->laddr6, &inet_addr, 1, 0);
	}

	if (ifn->laddr4count == 0) {
		ifn->laddr4 = malloc(sizeof *ifn->laddr4);
		if (ifn->laddr4 == NULL)
			logexit(1, "malloc error ifn->laddr4");
		ifn->laddr4count = 1;

		if (inet_pton(AF_INET, "127.0.0.1", &inet_addr.addr4)
		    != 1)
			logexit(1, "inet_pton 127.0.0.1");

		setsockaddr((struct sockaddr *)ifn->laddr4, &inet_addr, 0, 0);
	}

	/* then receive peers */
	for (m = 0; m < ifn->peerssize; m++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "wire_recvmsg SPEER");
		if (mtcode != SPEER)
			logexitx(1, "mtcode SPEER");

		assert(smsg.peer.peerid == m);

		if ((peer = peernew(m, smsg.peer.name, smsg.peer.nallowedips,
		    &smsg.peer.fsa)) == NULL)
			logexit(1, "peernew %zu", m);

		ifn->peers[m] = peer;

		for (n = 0; n < peer->allowedipssize; n++) {
			if ((allowedip = malloc(sizeof(*allowedip))) == NULL)
				logexit(1, "malloc allowedip");

			msgsize = sizeof(smsg);
			if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
				logexitx(1, "wire_recvmsg SCIDRADDR");
			if (mtcode != SCIDRADDR)
				logexitx(1, "mtcode SCIDRADDR");

			assert(smsg.peer.peerid == m);

			allowedip->prefixlen = smsg.cidraddr.prefixlen;
			memcpy(&allowedip->addr, &smsg.cidraddr.addr,
			    MIN(sizeof allowedip->addr, sizeof smsg.cidraddr.addr));

			peer->allowedips[n] = allowedip;

			/* pre-calculate masks */
			if (allowedip->addr.h.family == AF_INET6) {
				sin6 = (struct sockaddr_in6 *)&allowedip->addr;
				maskip6(&allowedip->v6addrmasked, &sin6->sin6_addr,
				    allowedip->prefixlen, 1);

				if (inet_ntop(AF_INET6, &sin6->sin6_addr, addrp,
				    sizeof(addrp)) == NULL)
					logexit(1, "inet_ntop on v6 allowedip "
					    "failed");
			} else if (allowedip->addr.h.family == AF_INET) {
				assert(allowedip->prefixlen <= 32);

				allowedip->v4mask.s_addr =
				    htonl(((1UL << 32) - 1) <<
				    (32 - allowedip->prefixlen));

				sin = (struct sockaddr_in *)&allowedip->addr;
				allowedip->v4addrmasked.s_addr =
				    sin->sin_addr.s_addr &
				    allowedip->v4mask.s_addr;

				if (inet_ntop(AF_INET, &sin->sin_addr, addrp,
				    sizeof(addrp)) == NULL)
					logexit(1, "inet_ntop on v4 allowedip "
					    "failed");
			} else {
				logexitx(1, "%s allowedip unknown address family",
				    peer->name);
			}

			if (verbose > 1)
				loginfox("%s allowedip %s/%zu", peer->name,
				    addrp, allowedip->prefixlen);
		}

		/*
		 * Create one socket per listen port/family combination.
		 */

		for (n = 0; n < ifn->laddr6count; n++) {
			for (i = 0; i < peer->portsock6count; i++) {
				if (ifn->laddr6[n].sin6_port ==
				    peer->portsock6[i].p)
					break;
			}

			if (i < peer->portsock6count)
				continue; /* port already allocated */

			xaddportsock(peer, ifn->laddr6[n].sin6_port, 1);
		}

		for (n = 0; n < ifn->laddr4count; n++) {
			for (i = 0; i < peer->portsock4count; i++) {
				if (ifn->laddr4[n].sin_port ==
				    peer->portsock4[i].p)
					break;
			}

			if (i < peer->portsock4count)
				continue; /* port already allocated */

			xaddportsock(peer, ifn->laddr4[n].sin_port, 0);
		}
	}

	/*
	 * Make sure there is no other peer with exactly
	 * the same allowedip (at least the prefixlen
	 * should differ).
	 */
	for (m = 0; m < ifn->peerssize; m++) {
		peer = ifn->peers[m];
		for (n = 0; n < peer->allowedipssize; n++) {
			allowedip = peer->allowedips[n];
			if (allowedip->addr.h.family == AF_INET6) {
				if (peerbyroute6(&peer2, &addr,
				    &allowedip->v6addrmasked) &&
				    peer != peer2) {
					if (inet_ntop(AF_INET6,
					    &allowedip->v6addrmasked, addrstr,
					    sizeof addrstr) == NULL)
						logexit(1, "%s inet_ntop error",
						    __func__);

					logexitx(1, "%s: %s/%zu\n",
					    "multiple allowedips with the same "
					    "address and prefixlen",
					    addrstr, allowedip->prefixlen);
				}
			}
		}
	}

	/* expect end of startup signal */
	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
		logexitx(1, "%s wire_recvmsg SEOS", ifn->ifname);
	if (mtcode != SEOS)
		logexitx(1, "mtcode SEOS");

	explicit_bzero(&smsg, sizeof(smsg));

	if (verbose > 1)
		loginfox("config received from %d", masterport);
}

/*
 * "masterport" descriptor to communicate with the master process and receive
 * the configuration.
 */
void
ifn_init(int masterport)
{
	struct sigaction sa;
	size_t heapneeded, n, fdcount;

	recvconfig(masterport);

	setproctitle("%s", ifn->ifname);

	/*
	 * Make sure we are not missing any communication channels and that
	 * there is no descriptor leak.
	 */

	fdcount = isopenfd(STDIN_FILENO) + isopenfd(STDOUT_FILENO) +
	    isopenfd(STDERR_FILENO);

	if (!isopenfd(masterport))
		logexitx(1, "masterport %d", masterport);
	if (!isopenfd(eport))
		logexitx(1, "eport %d", eport);
	if (!isopenfd(pport))
		logexitx(1, "pport %d", pport);

	fdcount += 3;

	for (n = 0; n < ifn->peerssize; n++) {
		fdcount += ifn->peers[n]->portsock6count;
		fdcount += ifn->peers[n]->portsock4count;
	}

	if ((size_t)getdtablecount() != fdcount)
		logexitx(1, "descriptor mismatch: %d %d", getdtablecount(),
		    fdcount);

	aead = EVP_aead_chacha20_poly1305();
	assert(EVP_AEAD_nonce_length(aead) == sizeof(nonce));
	assert(EVP_AEAD_max_tag_len(aead) == TAGLEN);

	if ((tund = opentunnel(ifn->ifname, ifn->ifdesc, ifn->ifaddrssize))
	    == -1)
		logexit(1, "opentunnel %s", ifn->ifname);

	/* assign addresses */
	for (n = 0; n < ifn->ifaddrssize; n++) {
		if (assignaddr(ifn->ifname, ifn->ifaddrs[n]) == -1)
			logwarn("assignaddr %d %s", n, ifn->ifname);
	}

	if (verbose > 1)
		loginfox("%s created", ifn->ifname);

	/*
	 * Calculate the amount of dynamic memory we need. Ignore number of
	 * peer allowed addresses. It doesn't have to be perfectly tight.
	 */

	if (ifn->peerssize > MAXPEERS)
		logexit(1, "number of peers exceeds maximum %zu %zu",
		    ifn->peerssize, MAXPEERS);

	heapneeded = MINDATA;
	heapneeded += ifn->peerssize * sizeof(struct session) * 2;
	heapneeded += ifn->peerssize * MAXQUEUEPACKETSDATASZ;
	heapneeded += ifn->peerssize * sizeof(struct peer);
	heapneeded += ifn->peerssize * 8;
	heapneeded += ifn->ifaddrssize * sizeof(struct cidraddr);
	heapneeded += ifn->ifaddrssize * 8;
	heapneeded += ifn->laddr6count * sizeof *ifn->laddr6;
	heapneeded += ifn->laddr4count * sizeof *ifn->laddr4;
	heapneeded += sizeof(struct ifn);
	heapneeded += (ifn->peerssize + 10) * sizeof(struct kevent);

	for (n = 0; n < ifn->peerssize; n++) {
		heapneeded += ifn->peers[n]->portsock6count * sizeof(struct portsock);
		heapneeded += ifn->peers[n]->portsock4count * sizeof(struct portsock);
	}

	if (ensurelimit(RLIMIT_DATA, heapneeded) == -1)
		logexit(1, "ensurelimit data");
	if (ensurelimit(RLIMIT_FSIZE, MAXCORE) == -1)
		logexit(1, "ensurelimit fsize");
	if (ensurelimit(RLIMIT_CORE, MAXCORE) == -1)
		logexit(1, "ensurelimit core");
	if (ensurelimit(RLIMIT_MEMLOCK, 0) == -1)
		logexit(1, "ensurelimit memlock");
	/* kqueue will be opened later */
	if (ensurelimit(RLIMIT_NOFILE, getdtablecount() + 1) == -1)
		logexit(1, "ensurelimit nofile");
	if (ensurelimit(RLIMIT_NPROC, 0) == -1)
		logexit(1, "ensurelimit nproc");
	if (ensurelimit(RLIMIT_STACK, MAXSTACK) == -1)
		logexit(1, "ensurelimit stack");

	/* print statistics on SIGUSR1 and do a graceful exit on SIGTERM */
	sa.sa_handler = handlesig;
	sa.sa_flags = SA_RESTART;
	if (sigemptyset(&sa.sa_mask) == -1)
		logexit(1, "sigemptyset");
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		logexit(1, "sigaction SIGUSR1");
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		logexit(1, "sigaction SIGTERM");

	if (chroot(EMPTYDIR) == -1)
		logexit(1, "chroot %s", EMPTYDIR);
	if (chdir("/") == -1)
		logexit(1, "chdir");

	if (setgroups(1, &gid) ||
	    setresgid(gid, gid, gid) ||
	    setresuid(uid, uid, uid))
		logexit(1, "%s: cannot drop privileges", __func__);

	if (pledge("stdio inet", "") == -1)
		logexit(1, "pledge");

	/* let proxy know we have connected all sockets */
	if (write(pport, &ifn->id, sizeof ifn->id) == -1)
		logexit(1, "write error ifn %u to proxy", ifn->id);
}
