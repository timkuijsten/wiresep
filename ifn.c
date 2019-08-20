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

/*
 * 64-bit integer that represents microseconds.
 */
typedef uint64_t utime_t;

extern int background, verbose;

/*
 * Four scenarios concerning sessions:
 *
 * 1. Send data (packet from tunnel device)
 *	if current session not usable
 *		queue packet
 *		reqhs
 * 	else
 *		send packet
 *		sendnonce++
 *		lastsent = now
 *		if (!deadline)
 *			deadline = now + Keepalive-Timeout + Rekey-Timeout
 *		if (iscurr(sess) && initiator && age(sess) >= Rekey-After-Time)
 *		    || sendnonce >= Rekey-After-Messages
 *			reqhs
 *
 * 2. Receive data (packet from server udp socket)
 *	if session not usable
 *		drop
 *	else
 *		deadline = 0
 *		forward packet to tunnel device
 *		keep-alive-timer = 10
 *		if initiator && age(sess) > 165
 *			reqhs
 *
 * 3. Keep-alive timeout (we are the sender of the last transport data message)
 *	if session not usable
 *		do nothing
 *	else
 *		send keep-alive packet
 *
 * 4. Receive keep-alive packet
 *	if session not usable
 *		do nothing
 *	else
 *		deadline = 0
 *
 * Session initiation:
 *
 * reqhs {
 *	if !tent
 *		tent = newsess
 *	if now - lasthsreq >= 5
 *		lasthsreq = now
 *		reqhsinit
 * }
 *
 * handlerekeytimeout {
 *	if now - start <= 90
 *		reqhsinit
 * }
 *
 * handlehsinitfromenclave {
 *	if lasthsreq > start
 *		clear rekeytimer
 *		start = now
 *
 *	if lastsent >= 5
 *		sendhsinit
 *		lastsent = now
 *
 *	if now - start <= 5
 *		rekeytimer = 5
 *	else if now - start <= 20
 *		rekeytimer = 10
 *	else if now - start <= 70
 *		rekeytimer = 20
 *	else
 *		destroy tent
 * }
 *
 * maketentcurr {
 *	clear rekeytimer
 *	prev = curr
 *	curr = tent
 *	clear tent
 * }
 *
 * initnextsess {
 *	set next session ids
 *	start = now
 * }
 *
 * makenextcurr {
 *	prev = curr
 *	curr = next
 *	clear next
 * }
 *
 * sessusable(sess) {
 *	XXX maybe remove reject after time/message checks and assert they're
 *	destroyed after receiving/sending
 *	if sendnonce >= Reject-After-Messages
 *		return false
 *	if now - start(sess) > Reject-After-Time
 *		return false
 *	if deadline && now > deadline
 *		return false
 *	return true
 * }
 */

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
	utime_t lastsent;
	utime_t deadline;
	utime_t lasthsreq;	/* last handshake message request */
	uint64_t sendnonce;
	uint32_t id;
	uint32_t peerid;
	char initiator;
	char kaset;	/* is the keep-alive timer set? */
	char keysset;	/* whether sendctx and recvctx are set */
};

struct cidraddr {
	struct sockaddr_storage addr;
	in_addr_t v4addrmasked;
	uint32_t v4mask;
	struct in6_addr v6addrmasked;
	struct in6_addr v6mask;
	size_t prefixlen;
};

struct peer {
	enum { UNCONNECTED, CONNECTED } state;
	int s6bound;
	int s4bound;
	char *name;
	uint32_t id; /* peer id */
	int s4; /* inet socket */
	int s6; /* inet6 socket */
	int s; /* active socket */
	size_t prefixlen;
	struct sockaddr_storage lsa; /* local and foreign socket name */
	struct sockaddr_storage fsa;
	struct session *sprev;
	struct session *scurr;
	struct session *snext;
	struct session *stent; /* used during handshake */
	void *qpacket; /* queued packet */
	size_t qpacketsize;
	struct cidraddr **allowedips;
	size_t allowedipssize;
};

struct ifn {
	uint32_t id;
	char *ifname;
	char *ifdesc;
	struct cidraddr **ifaddrs;
	size_t ifaddrssize;
	struct sockaddr_storage **listenaddrs;
	size_t listenaddrssize;
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

	logwarnx("%s %c %07x:%07x %llu/%llu %lld %lld %lld %s",
	    pre ? pre : "",
	    sess->initiator ? 'I' : 'R',
	    sess->id,
	    sess->peerid,
	    sess->arrecv.maxseqnum,
	    sess->sendnonce,
	    sess->start,
	    sess->lastsent,
	    sess->deadline,
	    sess->kaset ? "keep-alive" : "");
}

static void
logpeerinfo(const struct peer *peer)
{
	char addrstr[MAXIPSTR];
	size_t n;

	logwarnx("peer %u %s", peer->id, peer->name);
	logwarnx("  state %d", peer->state);
	logwarnx("  s6bound %d", peer->s6bound);
	logwarnx("  s4bound %d", peer->s4bound);
	if (addrtostr(addrstr, sizeof(addrstr), (struct sockaddr *)&peer->lsa,
	    0) != -1)
		logwarnx("  lsa %s", addrstr);

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

	logsessinfo("  sess tent", peer->stent);
	logsessinfo("  sess next", peer->snext);
	logsessinfo("  sess curr", peer->scurr);
	logsessinfo("  sess prev", peer->sprev);
}

static void
ifn_loginfo(void)
{
	char addrstr[MAXIPSTR];
	size_t n;

	logwarnx("id %u %s", ifn->id, ifn->ifname);
	for (n = 0; n < ifn->ifaddrssize; n++) {
		if (addrtostr(addrstr, sizeof(addrstr),
		    (struct sockaddr *)&ifn->ifaddrs[n]->addr, 1) != -1) {
			logwarnx("ifaddr %s/%zu", addrstr,
			    ifn->ifaddrs[n]->prefixlen);
		}
	}


	for (n = 0; n < ifn->listenaddrssize; n++) {
		if (addrtostr(addrstr, sizeof(addrstr),
		    (struct sockaddr *)&ifn->listenaddrs[n], 0) != -1) {
			logwarnx("listenaddr %s", addrstr);
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

	memcpy(&addreq.ifra_addr, &ca->addr, sizeof(addreq.ifra_addr));
	memcpy(&addreq.ifra_prefixmask, &mask, sizeof(addreq.ifra_prefixmask));

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
	mask.sin_addr.s_addr = ca->v4mask;

	memcpy(&addreq.ifra_addr, &ca->addr, sizeof(addreq.ifra_addr));
	memcpy(&addreq.ifra_mask, &mask, sizeof(addreq.ifra_mask));

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
	int s, rc;

	s = -1;
	rc = -1;

	if (ifname == NULL || ca == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (ca->addr.ss_family == AF_INET6) {
		rc = assignaddr6(ifname, ca);
	} else if (ca->addr.ss_family == AF_INET) {
		rc = assignaddr4(ifname, ca);
	} else {
		errno = EINVAL;
		return -1;
	}

	return rc;
}

/*
 * Return 1 if "peer" has a session with "sessid", otherwise return 0.
 */
static int
peerhassessid(const struct peer *peer, uint32_t sessid)
{
	if (peer->scurr && sessid == peer->scurr->id)
		return 1;

	if (peer->snext && sessid == peer->snext->id)
		return 1;

	if (peer->stent && sessid == peer->stent->id)
		return 1;

	if (peer->sprev && sessid == peer->sprev->id)
		return 1;

	return 0;
}

/*
 * Find a peer by "sessid". Return 1 if found and updates "peer" and "sess" to
 * point to it. 0 if not found and updates "peer" and "sess" to NULL.
 *
 * XXX log(n)
 */
static int
findpeerbysessid(uint32_t sessid, struct peer **peer, struct session **sess)
{
	struct peer *p;
	*peer = NULL;
	*sess = NULL;
	size_t n;

	for (n = 0; n < ifn->peerssize; n++) {
		p = ifn->peers[n];
		if (p->scurr && sessid == p->scurr->id) {
			*peer = p;
			*sess = p->scurr;
			return 1;
		}
		if (p->sprev && sessid == p->sprev->id) {
			*peer = p;
			*sess = p->sprev;
			return 1;
		}
		if (p->snext && sessid == p->snext->id) {
			*peer = p;
			*sess = p->snext;
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
	 * authentication tag (keep-alive).
	 */
	if (mwdsize - DATAHEADERLEN < TAGLEN)
		return -1;

	*payload = (uint8_t *)mwdhdr + DATAHEADERLEN;
	*payloadsize = mwdsize - DATAHEADERLEN;

	return 0;
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
 * to it. Returns 0 if no peer is found and updates "peer" to NULL.
 *
 * XXX log(n)
 */
static int
peerbyroute6(struct peer **peer, const struct in6_addr *fa)
{
	struct cidraddr *allowedip;
	struct in6_addr famasked;
	struct peer *p;
	size_t maxprefixlen;

	size_t n, o;

	maxprefixlen = 0;
	*peer = NULL;

	for (n = 0; n < ifn->peerssize; n++) {
		p = ifn->peers[n];

		for (o = 0; o < p->allowedipssize; o++) {
			allowedip = p->allowedips[o];

			if (allowedip->addr.ss_family != AF_INET6)
				continue;

			/* XXX once it works, don't zero out postfix */
			maskip6(&famasked, fa, allowedip->prefixlen, 1);

			if (memcmp(&famasked, &allowedip->v6addrmasked, 16) == 0
			    && allowedip->prefixlen >= maxprefixlen) {
				*peer = p;
				maxprefixlen = allowedip->prefixlen;
			}
		}
	}

	if (*peer != NULL)
		return 1;

	return 0;
}

/*
 * Find a peer with most specific "allowedips" by a remote address. "fa" must
 * be a pointer to the foreign address. If multiple allowedips match the same
 * mask or prefix length, the last one is choosen.
 *
 * Return 1 if a peer with a matching route is found and updates "peer" to point
 * to it. Returns 0 if no peer is found and updates "peer" to NULL.
 *
 * XXX log(n)
 */
static int
peerbyroute4(struct peer **peer, const struct in_addr *fa)
{
	struct cidraddr *allowedip;
	struct in_addr *fa4;
	struct peer *p;
	size_t maxprefixlen;

	size_t n, o;

	maxprefixlen = 0;
	*peer = NULL;

	for (n = 0; n < ifn->peerssize; n++) {
		p = ifn->peers[n];

		for (o = 0; o < p->allowedipssize; o++) {
			allowedip = p->allowedips[o];

			if (allowedip->addr.ss_family != AF_INET)
				continue;

			fa4 = (struct in_addr *)fa;
			if ((ntohl(fa4->s_addr) & allowedip->v4mask) ==
			    allowedip->v4addrmasked &&
			    allowedip->prefixlen >= maxprefixlen) {
				*peer = p;
				maxprefixlen = allowedip->prefixlen;
			}
		}
	}

	if (*peer != NULL)
		return 1;

	return 0;
}

/*
 * Fill a socket address structure.
 *
 * "out" must be allocated by the caller
 * "family" must be AF_INET6 or AF_INET
 * "ip" must be an struct in6_addr *, or struct in_addr *, depending on family
 * if "ip" is NULL, it will be set to the wildcard address.
 * "port" may be any port
 */
static int
setsockaddr(struct sockaddr_storage *out, int family, void *ip, in_port_t port)
{
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin4;

	if (family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)out;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = family;
		sin6->sin6_port = htons(port);
		if (ip == NULL) {
			sin6->sin6_addr = in6addr_any;
		} else {
			sin6->sin6_addr = *(struct in6_addr *)ip;
		}
	} else if (family == AF_INET) {
		sin4 = (struct sockaddr_in *)out;
		memset(sin4, 0, sizeof(*sin4));
		sin4->sin_len = sizeof(*sin4);
		sin4->sin_family = family;
		sin4->sin_port = htons(port);
		if (ip == NULL) {
			sin4->sin_addr.s_addr = INADDR_ANY;
		} else {
			sin4->sin_addr = *(struct in_addr *)ip;
		}
	} else {
		return -1;
	}

	return 0;
}

/*
 * Connect to remote peer "fsa" and verify our local socket is bound to "lsa".
 * "lsa" may contain the wildcard address but the port must be set (i.e. may not
 * be 0).
 *
 * Return 0 on success, -1 on failure.
 *
 * XXX can bind(2) only once and cannot create a new socket with SO_REUSEADDR
 * when using pledge. So bind once with the right port and hope connect(2) picks
 * the right local address, but notify if this is not the case.
 *
 * XXX support updating the routing table to ensure the right local address..
 */
static int
peerconnect(struct peer *p, const struct sockaddr_storage *lsa,
    const struct sockaddr_storage *fsa)
{
	static struct sockaddr_storage ss;
	struct sockaddr_in6 *src6, *sin6;
	struct sockaddr_in *src4, *sin4;
	struct kevent ev;
	int s;
	socklen_t len;

	if (fsa->ss_family != lsa->ss_family) {
		errno = EAFNOSUPPORT;
		logwarn("%s address family mismatch", __func__);
		return -1;
	}

	if (fsa->ss_family != AF_INET6 && fsa->ss_family != AF_INET) {
		errno = EAFNOSUPPORT;
		logwarn("%s", __func__);
		return -1;
	}

	/*
	 * Determine socket and ensure our local port is bound. We can only bind
	 * a socket once and can not create a new socket with SO_REUSEADDR set
	 * because we're pledged. Don't use the wildcard address in bind because
	 * the proxy might be using it, instead, bind with a localhost address
	 * and connect(2). Then let the second (normal) connect reset the local
	 * address (it can not reset the local port). Never disconnect after
	 * being bound because that would open up a race condition and opens up
	 * a DoS where this socket would pickup packets from other roaming peers
	 * instead of the proxy process (although no content will leak since
	 * this peer won't have the right session keys so packets are simply
	 * dropped).
	 */

	if (fsa->ss_family == AF_INET6) {
		s = p->s6;
		if (!p->s6bound) {
			memcpy(&ss, lsa, lsa->ss_len);
			src6 = (struct sockaddr_in6 *)&ss;
			if (inet_pton(AF_INET6, "::1", &src6->sin6_addr) != 1)
				logexitx(1, "inet_pton ::1");
			if (bind(s, (struct sockaddr *)src6, src6->sin6_len)
			    == -1)
				logexit(1, "%s bind [::1]:%u", __func__,
				    ntohs(src6->sin6_port));

			if (connect(s, (struct sockaddr *)fsa, fsa->ss_len)
			    == -1)
				logexit(1, "%s bind/connect", __func__);
			p->s6bound = 1;
		}
	} else {
		s = p->s4;
		if (!p->s4bound) {
			memcpy(&ss, lsa, lsa->ss_len);
			src4 = (struct sockaddr_in *)&ss;
			if (inet_pton(AF_INET, "127.0.0.1", &src4->sin_addr)
			    != 1)
				logexitx(1, "inet_pton 127.0.0.1");
			if (bind(s, (struct sockaddr *)src4, src4->sin_len)
			    == -1)
				logexit(1, "%s bind 127.0.0.1:%u", __func__,
				    ntohs(src4->sin_port));

			if (connect(s, (struct sockaddr *)fsa, fsa->ss_len)
			    == -1)
				logexit(1, "%s bind/connect", __func__);
			p->s4bound = 1;
		}
	}

	if (connect(s, (struct sockaddr *)fsa, fsa->ss_len) == -1)
		logexit(1, "%s connect", __func__);

	/*
	 * Verify that the locally picked address and port match with what was
	 * requested. Depends on routing table and whether or not we are
	 * listening on more than one port per interface.
	 */

	len = sizeof(ss);
	if (getpeername(s, (struct sockaddr *)&ss, &len) == -1)
		logexit(1, "getpeername");
	memmove(&p->fsa, &ss, sizeof(ss));

	len = sizeof(ss);
	if (getsockname(s, (struct sockaddr *)&ss, &len) == -1)
		logexit(1, "getsockname");
	memmove(&p->lsa, &ss, sizeof(ss));

	if (verbose > -1) {
		printaddr(stderr, (struct sockaddr *)&p->lsa, "connected", NULL);
		printaddr(stderr, (struct sockaddr *)&p->fsa, " ->", "\n");
	}

	if (p->lsa.ss_family == AF_INET6) {
		src6 = (struct sockaddr_in6 *)lsa;
		sin6 = (struct sockaddr_in6 *)&p->lsa;
		if (src6->sin6_port != sin6->sin6_port) {
			logwarnx("wrong local v6 port picked %u instead of %u",
			    ntohs(src6->sin6_port), ntohs(sin6->sin6_port));
			return -1;
		}

		if (memcmp(&src6->sin6_addr, &in6addr_any, sizeof(in6addr_any))
		    != 0 && memcmp(&src6->sin6_addr, &sin6->sin6_addr,
		    sizeof(src6->sin6_addr)) != 0) {
			logwarnx("wrong local v6 address picked, please update "
			    "routing table");
		}
	} else {
		src4 = (struct sockaddr_in *)lsa;
		sin4 = (struct sockaddr_in *)&p->lsa;
		if (src4->sin_port != sin4->sin_port) {
			if (verbose > -1)
				logwarnx("wrong local v4 port picked %u instead of"
				    " %u", ntohs(src4->sin_port),
				    ntohs(sin4->sin_port));
			return -1;
		}

		if (src4->sin_addr.s_addr != INADDR_ANY &&
		    src4->sin_addr.s_addr != sin4->sin_addr.s_addr) {
			if (verbose > -1)
				logwarnx("wrong local v4 address picked, please "
				    "update routing table");
		}
	}

	/*
	 * Overwrite existing filters if the same socket is reconnected. But
	 * keep filters open for both as a peer can be using both v4 and v6 at
	 * the same time.
	 */

	EV_SET(&ev, s, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) == -1)
		logexit(1, "%s kevent", __func__);

	p->s = s;
	p->state = CONNECTED;

	if (verbose > 1)
		loginfox("%s connected", p->name);

	return 0;
}

/*
 * Clear a rekey or keep-alive timer.
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
		loginfox("timer %u cleared", id);

	return 0;
}

/*
 * Return a newly allocated session on success, abort on failure.
 *
 * All fields are initialized, except for id, peerid and start. These should be
 * set by the caller when known.
 *
 * The caller should pass the allocated structure to sessdestroy when done.
 */
static struct session *
sessnew(struct peer *peer, char initiator)
{
	struct session *sess;

	if ((sess = malloc(sizeof(*sess))) == NULL)
		logexit(1, "%s malloc", __func__);

	sesscounter++;

	sess->initiator = initiator;
	sess->peer = peer;
	sess->start = 0;
	sess->kaset = 0;
	sess->keysset = 0;
	sess->deadline = 0;
	sess->lastsent = 0;
	sess->lasthsreq = 0;
	sess->sendnonce = 0;
	memset(&sess->arrecv, 0, sizeof(sess->arrecv));

	return sess;
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

	if (wire_sendpeeridmsg(pport, peerid, MSGSESSID, &msi, sizeof(msi)) ==
	    -1) {
	    stats.proxouterr++;
	    return -1;
	}

	stats.proxout++;
	return 0;
}

/*
 * Destroy and free a session. Also notify the proxy of the invalid session id.
 *
 * Call this function whenever:
 * 1. new next session is created and an old one exists
 * 2. session reaches time limit
 * 3. session reaches number-of-messages limit
 * 4. previous session is rolled out, because of a new tentative session
 * 5. previous session is rolled out, because of a new next session
 * 6. no session established after Rekey-Attempt-Time
 */
static void
sessdestroy(struct session *sess)
{
	uint32_t sessid, peerid;

	if (sess == NULL)
		return;

	sessid = sess->id;
	peerid = sess->peer->id;

	if (sess->keysset) {
		EVP_AEAD_CTX_cleanup(&sess->recvctx);
		EVP_AEAD_CTX_cleanup(&sess->sendctx);
	}

	if (cleartimer(sess->id) == -1)
		logwarn("%s cleartimer %u", __func__, sess->id);

	if (verbose > 1)
		loginfox("%s %u %zu", __func__, sess->id, sesscounter);

	freezero(sess, sizeof(*sess));
	sesscounter--;

	/*
	 * Notify the proxy that this id is no longer valid.
	 */
	if (notifyproxy(peerid, sessid, SESSIDDESTROY) == -1)
		if (verbose > -1)
			logwarnx("could not notify proxy of destroyed session "
			    "id");
}

/*
 * Request a new handshake init message from the enclave if the last request was
 * at least REKEY_TIMEOUT ago.
 */
static void
reqhs(struct peer *peer)
{
	struct msgreqwginit mri;

	if (!peer->stent)
		peer->stent = sessnew(peer, 1);

	if (now - peer->stent->lasthsreq >= REKEY_TIMEOUT) {
		peer->stent->lasthsreq = now;
		if (makemsgreqwginit(&mri) == -1)
			logexitx(1, "%s makemsgreqwginit", __func__);
		if (wire_sendpeeridmsg(eport, peer->id, MSGREQWGINIT, &mri,
		    sizeof(mri)) == -1)
			logexitx(1, "error sending MSGREQWGINIT to enclave");
	}
}

/*
 * Request a new handshake init message from the enclave as long as within
 * REKEY_ATTEMPT_TIME.
 */
static void
handlerekeytimeout(const struct peer *peer)
{
	struct msgreqwginit mri;

	if (now - peer->stent->start <= REKEY_ATTEMPT_TIME) {
		if (makemsgreqwginit(&mri) == -1)
			logexitx(1, "%s makemsgreqwginit", __func__);
		if (wire_sendpeeridmsg(eport, peer->id, MSGREQWGINIT, &mri,
		    sizeof(mri)) == -1)
			logexitx(1, "error sending MSGREQWGINIT to enclave");
	}
}

/*
 * Determine if a session can be used for sending and receiving data. We always
 * should receive something from our peer within the next 15 seconds after we've
 * sent data.
 *
 * Return 1 if the session is usable, 0 if not.
 */
static int
sessusable(const struct session *sess)
{
	if (!sess)
		return 0;

	if (sess->sendnonce >= REJECT_AFTER_MESSAGES)
		return 0;

	if (now - sess->start > REJECT_AFTER_TIME)
		return 0;

	if (sess->deadline > 0 && now > sess->deadline)
		return 0;

	return 1;
}

/*
 * Roll the tentative session into the current slot. If a current session
 * exists, roll it into prev, if a previous session exists, destroy it. Also
 * notify the proxy of the new current session.
 */
static void
maketentcurr(struct peer *peer)
{
	if (verbose > 1)
		loginfox("%s %zu", __func__, peer->stent->id);

	/* clear the handshake rekey-timeout timer */
	if (cleartimer(peer->stent->id) == -1)
		return;

	sessdestroy(peer->sprev);
	peer->sprev = peer->scurr;
	peer->scurr = peer->stent;
	peer->stent = NULL;

	if (notifyproxy(peer->id, peer->scurr->id, SESSIDCURR) == -1)
		if (verbose > -1)
			logwarnx("%s: could not notify proxy", __func__);
}

/*
 * Make the next session the current session and notify the proxy about it.
 */
static void
makenextcurr(struct peer *peer)
{
	if (verbose > 1)
		loginfox("%s %zu", __func__, peer->snext->id);

	sessdestroy(peer->sprev);
	peer->sprev = peer->scurr;
	peer->scurr = peer->snext;
	peer->snext = NULL;

	if (notifyproxy(peer->id, peer->scurr->id, SESSIDCURR) == -1)
		if (verbose > -1)
			logwarnx("%s: could not notify proxy", __func__);
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
		loginfox("timer %u set to %llu milliseconds", id, usec / 1000);
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
	if (rc < DATAHEADERLEN)
		return -1;

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
		/* keep-alive */
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

	*(uint64_t *)&nonce[4] = htole64(sess->sendnonce);
	if (EVP_AEAD_CTX_seal(&sess->sendctx, out, &outsize, outsize, nonce,
	    sizeof(nonce), in, padlen, NULL, 0) == 0) {
		stats.sockouterr++;
		return -1;
	}

	if (sendwgdatamsg(sess->peer->s, sess->peerid, sess->sendnonce, out,
	    outsize) == -1)
		logexitx(1, "error sending data to %s", sess->peer->name);

	stats.sockout++;
	stats.sockoutsz += outsize;

	sess->lastsent = now;
	sess->sendnonce++;

	if (sess->kaset) {
		if (cleartimer(sess->id) == -1)
			return -1;
		sess->kaset = 0;
	}

	if (insize > 0 && sess->deadline == 0)
		sess->deadline = now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;

	if (verbose > 1)
		loginfox("encapsulated %zu bytes into %zu for %s", padlen, outsize,
		    sess->peer->name);

	/*
	 * Handle session limits.
	 */

	if (sess->sendnonce == REJECT_AFTER_MESSAGES) {
		if (verbose > 1)
			loginfox("%s REJECT_AFTER_MESSAGES %lld", __func__,
			    sess->sendnonce);

		/* session reaches number-of-messages limit */
		if (sess->peer->scurr == sess) {
			sess->peer->scurr = NULL;
			sessdestroy(sess);
		} else if (sess->peer->sprev == sess) {
			sess->peer->sprev = NULL;
			sessdestroy(sess);
		} else {
			abort();
		}
		return 0;
	}

	if (sess->start < now - REJECT_AFTER_TIME) {
		if (verbose > 1)
			loginfox("%s REJECT_AFTER_TIME %lld", __func__,
			    sess->start);

		/* session reaches time limit */
		if (sess->peer->scurr == sess) {
			sess->peer->scurr = NULL;
			sessdestroy(sess);
		} else if (sess->peer->sprev == sess) {
			sess->peer->sprev = NULL;
			sessdestroy(sess);
		} else {
			abort();
		}
		return 0;
	}

	if (sess->sendnonce == REKEY_AFTER_MESSAGES) {
		reqhs(sess->peer);
		return 0;
	}

	if (sess->initiator && sess->start <= now - REKEY_AFTER_TIME &&
	    sess == sess->peer->scurr) {
		reqhs(sess->peer);
		return 0;
	}

	return 0;
}

/*
 * Decrypt data, forward to tunnel, update session and rotate to current if
 * next.
 *
 * Return 0 on success, -1 on failure.
 */
static int
decryptandfwd(uint8_t *out, size_t outsize, struct msgwgdatahdr *mwdhdr,
    size_t mwdsize, struct session *sess, int isnext)
{
	struct ip *ip4;
	struct ip6_hdr *ip6hdr;
	uint64_t counter;
	uint8_t *payload;
	size_t payloadsize;
	struct peer *routedpeer;

	if (outsize < TUNHDRSIZ + MAXIPHDR) {
		stats.corrupted++;
		return -1;
	}
	if (outsize < mwdsize) {
		stats.corrupted++;
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

	if (payloadoffset(&payload, &payloadsize, mwdhdr, mwdsize) == -1) {
		stats.corrupted++;
		return -1;
	}

	/* prepend a tunnel header */
	outsize -= TUNHDRSIZ;
	*(uint64_t *)&nonce[4] = mwdhdr->counter;
	if (EVP_AEAD_CTX_open(&sess->recvctx, &out[TUNHDRSIZ], &outsize, outsize,
	    nonce, sizeof(nonce), payload, payloadsize, NULL, 0) == 0) {
		logwarnx("unauthenticated data received, UDP data: %zu, WG "
		    "data: %zu, session id: %u, peer id: %u, counter: %llu",
		    mwdsize, payloadsize, sess->id, sess->peerid,
		    counter);
		stats.corrupted++;
		return -1;
	}

	payloadsize = outsize;
	payload = &out[TUNHDRSIZ];
	outsize += TUNHDRSIZ;

	/*
	 * Write authenticated and decrypted packet to the tunnel device if it's
	 * an ip4 or ip6 packet. Otherwise treat it as a keepalive.
	 */
	if (payloadsize >= MINIPHDR) {
		/* ip version is in the first four bits of the packet */
		switch(payload[0] >> 4) {
		case 6:
			if (payloadsize < MINIP6HDR) {
				if (verbose > -1)
					logwarnx("invalid ip6 packet");
				stats.corrupted++;
				return -1;
			}
			ip6hdr = (struct ip6_hdr *)payload;
			if (!peerbyroute6(&routedpeer, &ip6hdr->ip6_src)) {
				if (verbose > -1) {
					if (snprintv6addr((char *)msg,
					    sizeof(msg), &ip6hdr->ip6_src)
					    == -1) {
						stats.invalidpeer++;
						return -1;
					}
					logwarnx("valid packet from %s with "
					    "an invalid source ip received: %s",
					    sess->peer->name, msg);
				}
				stats.invalidpeer++;
				return -1;
			}
			if (routedpeer->id != sess->peer->id) {
				if (verbose > -1)
					logwarnx("valid packet from %s with a "
					    "source address of %s received",
					    sess->peer->name, routedpeer->name);
				stats.invalidpeer++;
				return -1;
			}

			*(uint32_t *)out = htonl(AF_INET6);
			break;
		case 4:
			if (payloadsize < MINIP4HDR) {
				logwarnx("invalid ip4 packet");
				stats.corrupted++;
				return -1;
			}
			ip4 = (struct ip *)payload;
			if (!peerbyroute4(&routedpeer, &ip4->ip_src)) {
				if (verbose > -1)
					logwarnx("valid packet from %s with an "
					    "invalid source ip received: %s",
					    sess->peer->name,
					    inet_ntoa(ip4->ip_src));
				stats.invalidpeer++;
				return -1;
			}
			if (routedpeer->id != sess->peer->id) {
				if (verbose > -1)
					logwarnx("valid packet from %s with a"
					    " source address of %s received",
					    sess->peer->name, routedpeer->name);
				stats.invalidpeer++;
				return -1;
			}

			*(uint32_t *)out = htonl(AF_INET);
			break;
		default:
			if (verbose > -1)
				logwarnx("invalid ip version received %u",
				    payload[0] >> 4);
			stats.corrupted++;
			return -1;
		}

		if (writen(tund, out, outsize) != 0)
			logwarn("writen tund");

		stats.devout++;
		stats.devoutsz += outsize;

		/*
		 * Since this was not a keepalive packet, ensure a keepalive
		 * timeout is scheduled.
		 */
		if (!sess->kaset) {
			settimer(sess->id, KEEPALIVE_TIMEOUT);
			sess->kaset = 1;
		}
	}

	/* SUCCESS */
	if (verbose > 1)
		loginfox("%s: %u %zu bytes", sess->peer->name, sess->id,
		    payloadsize);

	/*
	 * Update session, rotate keys if this is the next session and handle
	 * limits.
	 */

	if (antireplay_update(&sess->arrecv, counter) == -1) {
		logwarnx("antireplay_update %llu", counter);
		return -1;
	}

	sess->deadline = 0;

	if (isnext)
		makenextcurr(sess->peer);

	if (sess->arrecv.maxseqnum == REJECT_AFTER_MESSAGES) {
		if (verbose > 1)
			loginfox("%s REJECT_AFTER_MESSAGES %lld", __func__,
			    sess->arrecv.maxseqnum);

		/* session reaches number-of-messages limit */
		if (sess->peer->scurr == sess) {
			sess->peer->scurr = NULL;
			sessdestroy(sess);
		} else if (sess->peer->sprev == sess) {
			sess->peer->sprev = NULL;
			sessdestroy(sess);
		} else {
			abort();
		}
		return 0;
	}

	if (sess->start < now - REJECT_AFTER_TIME) {
		if (verbose > 1)
			loginfox("%s REJECT_AFTER_TIME %lld", __func__,
			    sess->start);

		/* session reaches time limit */
		if (sess->peer->scurr == sess) {
			sess->peer->scurr = NULL;
			sessdestroy(sess);
		} else if (sess->peer->sprev == sess) {
			sess->peer->sprev = NULL;
			sessdestroy(sess);
		} else {
			abort();
		}
		return 0;
	}

	if (sess->arrecv.maxseqnum == REKEY_AFTER_MESSAGES) {
		reqhs(sess->peer);
		return 0;
	}

	if (sess->initiator && sess->start < now -
	    (REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT))
		reqhs(sess->peer);

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
 *   new session established, must match "tent" if we are the initiator, or "next"
 *   if we are the responder. If "tent", rotate to "curr".
 *
 * Return 0 on success, -1 on error.
 */
static int
handleenclavemsg(void)
{
	struct session *sess;
	struct msgconnreq *mcr;
	struct msgwginit *mwi;
	struct msgwgresp *mwr;
	struct msgsesskeys *msk;
	struct peer *p;
	uint32_t peerid;
	size_t msgsize;
	ssize_t rc;
	unsigned char mtcode;
	long sincestart;

	msgsize = sizeof(msg);
	if (wire_recvpeeridmsg(eport, &peerid, &mtcode, msg, &msgsize)
	    == -1)
		logexitx(1, "wire_recvpeeridmsg eport");

	stats.enclin++;

	if (!findpeer(peerid, &p))
		logexit(1, "%s invalid peer id from enclave", __func__);

	switch (mtcode) {
	case MSGWGINIT:
		mwi = (struct msgwginit *)msg;

		assert(p->stent);
		sess = p->stent;

		if (sess->lasthsreq > sess->start) {
			sess->start = now;
			sess->lastsent = 0;
		}

		if (now - sess->lastsent >= REKEY_TIMEOUT) {
			rc = write(p->s, msg, msgsize);
			if (rc < 0)
				logexit(1, "%s write MSGWGINIT", __func__);
			if ((size_t)rc != msgsize)
				logexitx(1, "%s write MSGWGINIT %zd", __func__, rc);

			stats.initout++;
			stats.sockout++;
			stats.sockoutsz += msgsize;

			sess->id = le32toh(mwi->sender);
			sess->lastsent = now;

			if (notifyproxy(p->id, sess->id, SESSIDTENT) == -1)
				if (verbose > -1)
					logwarnx("could not notify proxy of tent "
					    "session id");
		}

		/* set timeout */
		sincestart = now - sess->start;

		/* backoff: time:timeout
		 * 0:5 5:5 10:10 20:10 30:19 50:19 70:19 90:done
		 */
		if (sincestart <= REKEY_TIMEOUT) {
			settimer(sess->id, REKEY_TIMEOUT);
		} else if (sincestart <= REKEY_TIMEOUT * 4) {
			settimer(sess->id, REKEY_TIMEOUT * 2);
		} else if (sincestart <= REKEY_TIMEOUT * 15) {
			settimer(sess->id, REKEY_TIMEOUT * 4 - 1000);
		} else {
			if (verbose > 1)
				loginfox("%s REKEY_TIMEOUT %lld", __func__,
				    sincestart);

			/* no session established after Rekey-Attempt-Time */
			sessdestroy(p->stent);
			p->stent = NULL;
		}
		break;
	case MSGWGRESP:
		/*
		 * A peer initiated a handshake. Initialize a new unconfirmed
		 * session in the next slot after destroying a previous "next"
		 * session.
		 * Only transmit data using this session as soon as the peer has
		 * sent some data. Only then we are guaranteed the peer is
		 * currently in possession of the private key. At this time
		 * there is still a possibility in where a man-in-the-middle has
		 * our private key, but not the peers private key.
		 */

		mwr = (struct msgwgresp *)msg;

		if (verbose > 1)
			loginfox("%s received new handshake", __func__);

		sessdestroy(p->snext);
		p->snext = sessnew(p, 0);
		p->snext->id = le32toh(mwr->sender);

		if (notifyproxy(p->id, p->snext->id, SESSIDNEXT) == -1)
			if (verbose > -1)
				logwarnx("could not notify proxy of next session "
				    "id");

		rc = write(p->s, msg, msgsize);
		if (rc < 0) {
			logwarn("%s write MSGWGRESP", __func__);
			stats.sockouterr++;
			stats.respouterr++;
			return -1;
		}
		if ((size_t)rc != msgsize) {
			logwarnx("%s write MSGWGRESP %zd expected %zu", __func__,
			    rc, msgsize);
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
		if (peerconnect(p, &mcr->lsa, &mcr->fsa) == -1) {
			stats.sockouterr++;
			return -1;
		}
		break;
	case MSGSESSKEYS:
		msk = (struct msgsesskeys *)msg;
		sess = NULL;
		if (p->stent && p->stent->id == msk->sessid) {
			sess = p->stent;
			maketentcurr(p);
		} else if (p->snext && p->snext->id == msk->sessid) {
			sess = p->snext;
		} else {
			logexitx(1, "MSGSESSKEYS unknown session id from "
			    "enclave");
		}

		/*
		 * Finalize session.
		 */

		if (EVP_AEAD_CTX_init(&sess->sendctx, aead, msk->sendkey,
		    KEYLEN, TAGLEN, NULL) == 0) {
			stats.enclinerr++;
			return -1;
		}

		if (EVP_AEAD_CTX_init(&sess->recvctx, aead, msk->recvkey,
		    KEYLEN, TAGLEN, NULL) == 0) {
			stats.enclinerr++;
			return -1;
		}

		sess->keysset = 1;
		sess->peerid = le32toh(msk->peersessid);
		sess->start = now;

		if (verbose > 1)
			loginfox("new session %u with %s %s %u",
			    sess->id,
			    sess->initiator ? "responder" : "initiator" ,
			    sess->peer->name,
			    sess->peerid);

		/* Only the initiator may start sending data right away */
		if (sess->initiator && p->qpacket) {
			rc = encryptandsend(msg, sizeof(msg), p->qpacket,
			    p->qpacketsize, sess);
			if (rc == -1) {
				logwarnx("encryptandsend qpacket");
				stats.sockouterr++;
				stats.queueouterr++;
				free(p->qpacket);
				p->qpacket = NULL;
				p->qpacketsize = 0;
				return -1;
			}
			stats.queueout++;
			stats.queueoutsz += p->qpacketsize;
			free(p->qpacket);
			p->qpacket = NULL;
			p->qpacketsize = 0;
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
 *      If not, drop packet and ensure handshake
 * Otherwise write a MSGWGDATA to the connected socket using the current
 * session.
 *
 * TODO implement queue instead of drop.
 *   send back icmp messages
 *
 * Return 0 on success, -1 on error.
 */
static int
handletundmsg(void)
{
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
		if (!peerbyroute6(&p, &ip6hdr->ip6_dst)) {
			if (verbose > 0 && snprintv6addr((char *)msg,
			    sizeof(msg), &ip6hdr->ip6_dst) == 0)
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
		if (!peerbyroute4(&p, &ip4->ip_dst)) {
			if (verbose > 0)
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
		loginfox("packet for %s", p->name);

	if (p->state != CONNECTED) {
		if (p->fsa.ss_family == AF_INET6 ||
		    p->fsa.ss_family == AF_INET) {
			/* TODO, is simply picking first listen address ok? */
			if (peerconnect(p, ifn->listenaddrs[0], &p->fsa)
			    == -1) {
				stats.sockouterr++;
				return -1;
			}
		} else {
			errno = EDESTADDRREQ;
			logwarn("peer endpoint unknown");
			stats.sockouterr++;
			return -1;
		}
	}

	if (!sessusable(p->scurr)) {
		if (p->qpacket) {
			stats.queueouterr++;
			free(p->qpacket);
			p->qpacket = NULL;
			p->qpacketsize = 0;
		}
		p->qpacketsize = rc - TUNHDRSIZ;
		if ((p->qpacket = malloc(p->qpacketsize)) == NULL)
			logexit(1, "%s malloc", __func__);
		memcpy(p->qpacket, &msg[TUNHDRSIZ], p->qpacketsize);
		stats.queuein++;
		stats.queueinsz += p->qpacketsize;
		reqhs(p);
		return -1;
	}

	return encryptandsend(msg, sizeof(msg), &msg[TUNHDRSIZ], msgsize - TUNHDRSIZ,
	    p->scurr);
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
handlesocketmsg(const struct peer *p)
{
	struct msgwginit *mwi;
	struct msgwgresp *mwr;
	struct msgwgdatahdr *mwdhdr;
	struct session *sess;
	ssize_t rc;
	size_t msgsize;
	uint32_t receiver;
	unsigned char mtcode;
	int isnext;

	rc = read(p->s, msg, sizeof(msg));
	if (rc < 0) {
		logwarn("%s read error", __func__);
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
		stats.initin++;

		mwi = (struct msgwginit *)msg;
		if (!ws_validmac(mwi->mac1, sizeof(mwi->mac1), mwi, MAC1OFFSETINIT,
		    ifn->mac1key)) {
			logwarnx("MSGWGINIT invalid mac1");
			stats.sockinerr++;
			stats.initinerr++;
			stats.invalidmac++;
			return -1;
		}

		if (wire_sendpeeridmsg(eport, p->id, MSGWGINIT, mwi,
		    sizeof(*mwi)) == -1)
			logexitx(1, "wire_sendpeeridmsg MSGWGINIT");
		break;
	case MSGWGRESP:
		stats.respin++;

		mwr = (struct msgwgresp *)msg;
		if (!peerhassessid(p, le32toh(mwr->receiver))) {
			logwarnx("MSGWGRESP unknown receiver %u", le32toh(mwr->receiver));
			stats.sockinerr++;
			stats.respinerr++;
			return -1;
		}

		if (!ws_validmac(mwr->mac1, sizeof(mwr->mac1), mwr, MAC1OFFSETRESP,
		    ifn->mac1key)) {
			logwarnx("MSGWGRESP invalid mac1");
			stats.sockinerr++;
			stats.respinerr++;
			stats.invalidmac++;
			return -1;
		}

		if (wire_sendpeeridmsg(eport, p->id, MSGWGRESP, mwr,
		    sizeof(*mwr)) == -1)
			logexitx(1, "wire_sendpeeridmsg MSGWGRESP");
		break;
	case MSGWGCOOKIE:
		logwarnx("%s cookies are unsupported", __func__);
		break;
	case MSGWGDATA:
		mwdhdr = (struct msgwgdatahdr *)msg;

		/*
		 * Find session and try to authenticate and decrypt.
		 */
		sess = NULL;
		receiver = le32toh(mwdhdr->receiver);
		isnext = 0;
		if (p->scurr && receiver == p->scurr->id) {
			sess = p->scurr;
		} else if (p->snext && receiver == p->snext->id) {
			sess = p->snext;
			isnext = 1;
		} else if (p->sprev && receiver == p->sprev->id) {
			sess = p->sprev;
		} else {
			logwarnx("data with unknown session received %u",
			    receiver);
			stats.sockinerr++;
			return -1;
		}
		if (!sessusable(sess)) {
			logwarnx("data for unusable session received %u",
			    receiver);
			stats.sockinerr++;
			return -1;
		}

		if (decryptandfwd(msg, sizeof(msg), mwdhdr, msgsize, sess,
		    isnext) == -1)
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
	struct sockaddr_storage fsa, lsa;
	struct msgwgdatahdr *mwdhdr;
	struct peer *p;
	struct session *sess;
	size_t msgsize;
	uint32_t ifnid;
	unsigned char mtcode;
	int isnext;

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
		if (!findpeerbysessid(le32toh(mwdhdr->receiver), &p, &sess)) {
			logwarnx("invalid session id via proxy");
			stats.proxinerr++;
			return -1;
		}
		if (!sessusable(sess)) {
			logwarnx("data for unusable session %u received via proxy",
			    le32toh(mwdhdr->receiver));
			stats.proxinerr++;
			return -1;
		}

		if (p->snext && p->snext->id == sess->id)
			isnext = 1;
		else
			isnext = 0;

		if (decryptandfwd(msg, sizeof(msg), mwdhdr, msgsize, sess, isnext) == -1)
			return -1;

		if (peerconnect(p, &lsa, &fsa) == -1) {
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
 * Handle rekey- and keep alive timeout.
 */
static void
sesshandletimer(struct kevent *ev)
{
	struct session *sess;
	struct peer *peer;
	size_t n;
	int istent;

	if (verbose > 1)
		loginfox("handling timer event id %lu", ev->ident);

	/* XXX log(n) */
	istent = 0;
	sess = NULL;
	for (n = 0; n < ifn->peerssize; n++) {
		peer = ifn->peers[n];
		if (peer->scurr && ev->ident == peer->scurr->id) {
			sess = peer->scurr;
		} else if (peer->stent && ev->ident == peer->stent->id) {
			sess = peer->stent;
			istent = 1;
		} else if (peer->sprev && ev->ident == peer->sprev->id) {
			sess = peer->sprev;
		}

		if (sess)
			break;
	}

	if (!sess) {
		if (verbose > -1)
			logwarnx("unknown timer went off %lu", ev->ident);
		return;
	}
	if (!sessusable(sess)) {
		if (verbose > -1)
			logwarnx("timer of unusable session went off %lu",
			    ev->ident);
		return;
	}

	if (istent) {
		if (verbose > 0)
			lognoticex("Rekey-Timeout %u %s", sess->id,
			    sess->peer->name);

		handlerekeytimeout(sess->peer);
	} else {
		if (verbose > 0)
			lognoticex("Keepalive-Timeout %u %s", sess->id,
			    sess->peer->name);

		assert(sess->kaset);
		sess->kaset = 0;

		if (encryptandsend(msg, sizeof(msg), NULL, 0, sess) == -1)
			logexit(1, "%s encryptandsend", __func__);
	}
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
	struct sockaddr_storage ss, *listenaddr;
	struct peer *peer;
	struct kevent *ev;
	struct timespec ts;
	size_t evsize, maxevsize, m, n;
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
		/* find source address to use for connect */
		peer = ifn->peers[n];
		for (listenaddr = NULL, m = 0; m < ifn->listenaddrssize &&
		    listenaddr == NULL; m++) {
			if (ifn->listenaddrs[m]->ss_family ==
			    peer->fsa.ss_family)
				listenaddr = ifn->listenaddrs[m];
		}
		if (listenaddr == NULL) {
			printaddr(stderr, (struct sockaddr *)&peer->fsa, "coult not "
			    "find a suitable source address to connect to peer",
			    "\n");
			continue;
		}

		if (setsockaddr(&ss, listenaddr->ss_family, NULL,
		    getport(listenaddr)) == -1)
			logexitx(1, "setsockaddr");

		if (peerconnect(peer, &ss, &peer->fsa) == -1)
			logexitx(1, "peerconnect");
		reqhs(peer);
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
				sesshandletimer(&ev[i]);
			} else if ((int)ev[i].ident == eport) {
				if (verbose > 1)
					loginfox("enclave event");

				if (handleenclavemsg() == -1)
					logexitx(1, "enclave error");
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
					    ifn->peers[n]->s) {
						peer = ifn->peers[n];
					}
				}
				if (peer) {
					/* INCOMING DATA */
					if (verbose > 1)
						loginfox("socket event");
					handlesocketmsg(peer);
				} else {
					logwarnx("event undetermined %lu",
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
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
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
peernew(uint32_t id, const char *name)
{
	struct peer *peer;
	const int on = 1;
	int len;

	if ((peer = malloc(sizeof(*peer))) == NULL)
		logexit(1, "%s malloc peer", __func__);

	peer->id = id;
	peer->name = strdup(name);
	peer->state = UNCONNECTED;
	peer->s = -1;
	peer->s6bound = 0;
	peer->s4bound = 0;
	peer->prefixlen = 0;
	peer->qpacket = NULL;
	peer->qpacketsize = 0;
	peer->allowedips = NULL;
	peer->allowedipssize = 0;
	memset(&peer->lsa, 0, sizeof(peer->lsa));
	memset(&peer->fsa, 0, sizeof(peer->fsa));

	if ((peer->s6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		logexit(1, "%s socket v6", __func__);
	if (setsockopt(peer->s6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))
	    == -1)
		logexit(1, "setsockopt SO_REUSEADDR");

	if ((peer->s4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		logexit(1, "%s socket v4", __func__);
	if (setsockopt(peer->s4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))
	    == -1)
		logexit(1, "setsockopt SO_REUSEADDR");

	len = MAXRECVBUF;
	if (setsockopt(peer->s6, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len))
	    == -1)
		logexit(1, "setsockopt");

	if (len < MAXRECVBUF)
		logexitx(1, "could not maximize udp6 receive buffer: %d", len);

	loginfox("peer udp6 receive buffer: %d", len);

	len = MAXRECVBUF;
	if (setsockopt(peer->s4, SOL_SOCKET, SO_RCVBUF, &len, sizeof(len))
	    == -1)
		logexit(1, "setsockopt");

	if (len < MAXRECVBUF)
		logexitx(1, "could not maximize udp4 receive buffer: %d", len);

	loginfox("peer udp4 receive buffer: %d", len);

	/* mark sessions as unused */
	peer->snext = peer->scurr = peer->sprev = peer->stent = NULL;

	return peer;
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
	static union {
		struct sinit init;
		struct sifn ifn;
		struct speer peer;
		struct scidraddr cidraddr;
		struct seos eos;
	} smsg;
	struct cidraddr *ifaddr, *allowedip;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage *listenaddr;
	struct peer *peer, *peer2;
	size_t m, msgsize, n;
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
	ifn->listenaddrssize = smsg.ifn.nlistenaddrs;
	memcpy(ifn->mac1key, smsg.ifn.mac1key, sizeof(smsg.ifn.mac1key));
	memcpy(ifn->cookiekey, smsg.ifn.cookiekey, sizeof(smsg.ifn.cookiekey));

	if ((ifn->ifaddrs = calloc(ifn->ifaddrssize, sizeof(*ifn->ifaddrs)))
	    == NULL)
		logexit(1, "calloc ifn->ifaddrs");

	if ((ifn->listenaddrs = calloc(ifn->listenaddrssize,
	    sizeof(*ifn->listenaddrs))) == NULL)
		logexit(1, "calloc ifn->listenaddrs");

	if ((ifn->peers = calloc(ifn->peerssize, sizeof(*ifn->peers))) == NULL)
		logexit(1, "calloc ifn->peers");

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
		    sizeof(smsg.cidraddr.addr));

		ifn->ifaddrs[n] = ifaddr;

		/* pre-calculate in masks */
		if (ifaddr->addr.ss_family == AF_INET6) {
			memset(&ifaddr->v6mask, 0xff, 16);
			maskip6(&ifaddr->v6mask, &ifaddr->v6mask,
			    ifaddr->prefixlen, 1);

			sin6 = (struct sockaddr_in6 *)&ifaddr->addr;
			maskip6(&ifaddr->v6addrmasked, &sin6->sin6_addr,
			    ifaddr->prefixlen, 1);
		} else if (ifaddr->addr.ss_family == AF_INET) {
			assert(ifaddr->prefixlen <= 32);

			ifaddr->v4mask = htonl(((1UL << 32) - 1) <<
			    (32 - ifaddr->prefixlen));

			sin = (struct sockaddr_in *)&ifaddr->addr;
			ifaddr->v4addrmasked =
			    htonl(ntohl(sin->sin_addr.s_addr)
			    & ntohl(ifaddr->v4mask));

			if (verbose > 1)
				loginfox("%s %s/%zu",
				    ifn->ifname,
				    inet_ntoa(sin->sin_addr),
				    ifaddr->prefixlen);
		} else {
			logexitx(1, "illegal address family");
		}
	}

	/* then receive all listen addresses */
	for (n = 0; n < ifn->listenaddrssize; n++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "wire_recvmsg SCIDRADDR");
		if (mtcode != SCIDRADDR)
			logexitx(1, "mtcode SCIDRADDR");

		assert(smsg.cidraddr.ifnid == ifn->id);

		if (getport(&smsg.cidraddr.addr) == 0) {
			if (verbose > -1)
				printaddr(stderr,
				    (struct sockaddr *)&smsg.cidraddr.addr,
				    "listenaddr without port", "\n");
			continue;
		}

		if ((listenaddr = malloc(sizeof(*listenaddr))) == NULL)
			logexit(1, "malloc listenaddr");

		memcpy(listenaddr, &smsg.cidraddr.addr,
		    sizeof(smsg.cidraddr.addr));

		ifn->listenaddrs[n] = listenaddr;
	}

	/* then receive peers */
	for (m = 0; m < ifn->peerssize; m++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "wire_recvmsg SPEER");
		if (mtcode != SPEER)
			logexitx(1, "mtcode SPEER");

		assert(smsg.peer.peerid == m);

		if ((peer = peernew(m, smsg.peer.name)) == NULL)
			logexit(1, "peernew %zu", m);

		peer->allowedipssize = smsg.peer.nallowedips;
		if ((peer->allowedips = calloc(peer->allowedipssize,
		    sizeof(*peer->allowedips))) == NULL)
			logexit(1, "calloc peer->allowedips");

		memcpy(&peer->fsa, &smsg.peer.fsa, sizeof(smsg.peer.fsa));

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
			    sizeof(smsg.cidraddr.addr));

			peer->allowedips[n] = allowedip;

			/* pre-calculate masks */
			if (allowedip->addr.ss_family == AF_INET6) {
				sin6 = (struct sockaddr_in6 *)&allowedip->addr;
				maskip6(&allowedip->v6addrmasked, &sin6->sin6_addr,
				    allowedip->prefixlen, 1);

				if (inet_ntop(AF_INET6, &sin6->sin6_addr, addrp,
				    sizeof(addrp)) == NULL)
					logexit(1, "inet_ntop on v6 allowedip "
					    "failed");
			} else if (allowedip->addr.ss_family == AF_INET) {
				assert(allowedip->prefixlen <= 32);

				allowedip->v4mask = ((1UL << 32) - 1) <<
				    (32 - allowedip->prefixlen);

				sin = (struct sockaddr_in *)&allowedip->addr;
				allowedip->v4addrmasked =
				    ntohl(sin->sin_addr.s_addr)
				    & allowedip->v4mask;

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
			if (allowedip->addr.ss_family == AF_INET6) {
				if (peerbyroute6(&peer2, &allowedip->v6addrmasked)
				    && peer != peer2) {
					snprintv6addr((char *)msg, sizeof(msg),
					    &allowedip->v6addrmasked);

					fprintf(stderr, "%s: %s/%zu\n",
					    "multiple allowedips with the same "
					    "address and prefixlen",
					    msg, allowedip->prefixlen);
					exit(1);
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
	size_t n;
	int stdopen;

	recvconfig(masterport);

	/*
	 * Make sure we are not missing any communication channels and that
	 * there is no descriptor leak.
	 */

	stdopen = isopenfd(STDIN_FILENO) + isopenfd(STDOUT_FILENO) +
	    isopenfd(STDERR_FILENO);

	if (!isopenfd(masterport))
		logexitx(1, "masterport %d", masterport);
	if (!isopenfd(eport))
		logexitx(1, "eport %d", eport);
	if (!isopenfd(pport))
		logexitx(1, "pport %d", pport);

	for (n = 0; n < ifn->peerssize; n++) {
		if (!isopenfd(ifn->peers[n]->s4))
			logexitx(1, "peer %zu s4", n);
		if (!isopenfd(ifn->peers[n]->s6))
			logexitx(1, "peer %zu s6", n);
	}

	if ((size_t)getdtablecount() != stdopen + 3 + ifn->peerssize * 2)
		logexitx(1, "descriptor mismatch: %d", getdtablecount());

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
	if (dropuser(uid, gid) == -1)
		logexit(1, "dropuser %d:%d", uid, gid);
	if (chdir("/") == -1)
		logexit(1, "chdir");
	if (pledge("stdio inet", "") == -1)
		logexit(1, "pledge");
}
