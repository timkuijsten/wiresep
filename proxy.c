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
#include <sys/socket.h>
#include <sys/time.h>

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "wireprot.h"
#include "wiresep.h"

#define MINDATA  (1 << 21) /* cap minimum malloc(3) and mmap(2) to 2 MB */
#define MAXSTACK (1 << 15) /* 32 KB should be enough */

#ifdef DEBUG
#define MAXCORE (1024 * 1024 * 10)
#else
#define MAXCORE 0
#endif

void proxy_loginfo(void);

extern int background, verbose;

/*
 * A mapping between a IPC or a server socket. If listenaddr is set this is a
 * server socket, if it is not set this is an IPC socket.
 */
struct sockmap {
	int s;
	struct ifn *ifn;
	union sockaddr_inet *listenaddr;
};

struct sessmap {
	int64_t sessid;
	struct peer *peer;
};

struct peer {
	uint32_t id;
	int64_t sesstent;
	int64_t sessnext;
	int64_t sesscurr;
	int64_t sessprev;
	size_t sent;
	size_t sentsz;
	size_t recv;
	size_t recvsz;
};

struct ifn {
	uint32_t id;
	int port;
	char *ifname;	/* null terminated name of the interface */
	union sockaddr_inet **listenaddrs;
	size_t listenaddrssize;
	wskey mac1key;
	wskey cookiekey;
	struct peer **peers;
	size_t peerssize;
	struct sessmap **sessmapv;
	size_t sessmapvsize;
};

static uid_t uid;
static gid_t gid;

static int eport;

static struct ifn **ifnv;
static size_t ifnvsize;

static uint8_t msg[MAXSCRATCH];
static union sockaddr_inet peeraddr;
/* mapping of server sockets to listenaddr or ifn */
static struct sockmap **sockmapv;
static size_t sockmapvsize;

static size_t totalfwdifn, totalfwdifnsz, totalfwdenc, totalfwdencsz, totalrecv,
    totalrecvsz, corrupted, invalidmac, invalidpeer;

static int logstats, doterm;

static int
sortsessmapv(const void *a, const void *b)
{
	const struct sessmap *x = *(const struct sessmap **)a;
	const struct sessmap *y = *(const struct sessmap **)b;

	if (x->sessid == y->sessid)
		return 0;

	if (x->sessid < y->sessid)
		return -1;

	return 1;
}

static void
sort(struct sessmap **sessmapv, size_t sessmapvsize)
{
	qsort(sessmapv, sessmapvsize, sizeof(*sessmapv), sortsessmapv);
}

/*
 * Return the index of "sessid" in the sorted array "sessmapv" or -1 if not
 * found.
 */
static int
sessmapvsearch(struct sessmap **sessmapv, size_t sessmapvsize, int64_t sessid)
{
	int i, offset;

	offset = 0;

	while (sessmapvsize) {
		/* ceil of middle index */
		i = ((sessmapvsize + 1) / 2) - 1;

		if (sessid == sessmapv[offset + i]->sessid) {
			return offset + i;
		} else if (sessid > sessmapv[offset + i]->sessid) {
			offset = offset + i + 1;
		} else {
			sessmapvsize--;
		}
		/* floor */
		sessmapvsize /= 2;
	}

	return -1;
}

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
		logwarnx("proxy %s unexpected signal %d %s", __func__, signo,
		    strsignal(signo));
		break;
	}
}

/*
 * Find a socket mapping by socket descriptor. Return 1 if found and updates
 * "sockmap" to point to it. 0 if not found and updates "sockmap" to NULL.
 *
 * XXX log(n)
 */
static int
findsockmapbysock(struct sockmap **sockmap, int s)
{
	size_t n;

	*sockmap = NULL;

	for (n = 0; n < sockmapvsize; n++) {
		if (s == sockmapv[n]->s) {
			*sockmap = sockmapv[n];
			return 1;
		}
	}

	return 0;
}

/*
 * Find a peer by id and interface. Return 1 if found and updates "p" to point
 * to it. 0 if not found and updates "p" to NULL.
 */
static int
findpeerbyidandifn(struct peer **p, uint32_t peerid, const struct ifn *ifn)
{
	*p = NULL;

	if (peerid >= ifn->peerssize)
		return 0;

	*p = ifn->peers[peerid];
	return 1;
}

/*
 * Find a session by "sessid". Return 1 if found and updates "peer" to
 * point to it. 0 if not found and updates "peer" to NULL.
 */
static int
findpeerbysessidandifn(struct peer **peer, const struct ifn *ifn,
    int64_t sessid)
{
	int sessidx;

	sessidx = sessmapvsearch(ifn->sessmapv, ifn->sessmapvsize, sessid);
	if (sessidx == -1) {
		*peer = NULL;
		return 0;
	}

	*peer = ifn->sessmapv[sessidx]->peer;
	return 1;
}

/*
 * Replace session id "oid" with "nid".
 *
 * O(log(n) + n * log(n))
 *
 * Return 0 on success, -1 if "oid" does not exist.
 */
static int
sessmapvreplace(const struct ifn *ifn, struct peer *peer, int64_t oid,
    int64_t nid)
{
	int sessidx;

	sessidx = sessmapvsearch(ifn->sessmapv, ifn->sessmapvsize, oid);
	if (sessidx == -1)
		return -1;

	ifn->sessmapv[sessidx]->sessid = nid;
	ifn->sessmapv[sessidx]->peer = peer;

	if (nid == oid) {
		loginfox("proxy %s old sessid equals new sessid %x", __func__, oid);
	} else if (nid > oid) {
		loginfox("proxy %s replaced %x@%d with %x, resort from index %d (%d)",
		    __func__, oid, sessidx, nid, sessidx,
		    ifn->sessmapvsize - sessidx);
		sort(&ifn->sessmapv[sessidx], ifn->sessmapvsize - sessidx);
	} else {
		loginfox("proxy %s replaced %x@%d with %x, resort from index 0 (%d)",
		    __func__, oid, sessidx, nid, sessidx + 1);
		sort(ifn->sessmapv, sessidx + 1);
	}

	return 0;
}

/*
 * Receive and handle a message from an ifn process.
 *
 * SESSID
 *   new session established, register with interface and peer.
 *
 * Return 0 on success, -1 on error.
 */
static int
handleifnmsg(const struct sockmap *sockmap)
{
	struct msgsessid *msi;
	struct ifn *ifn;
	struct peer *peer;
	size_t msgsize;
	unsigned char mtcode;
	uint32_t peerid;
	int64_t *sessid;

	ifn = sockmap->ifn;

	msgsize = sizeof(msg);
	if (wire_recvpeeridmsg(ifn->port, &peerid, &mtcode, msg, &msgsize)
	    == -1) {
		logwarnx("proxy %s wire_recvpeeridmsg %s", __func__, ifn->ifname);
		return -1;
	}

	if (!findpeerbyidandifn(&peer, peerid, ifn)) {
		logwarnx("proxy %s unknown peerid from %s: %u", __func__, ifn->ifname,
		    peerid);
		return -1;
	}

	switch (mtcode) {
	case MSGSESSID:
		msi = (struct msgsessid *)msg;

		if (verbose > 1)
			loginfox("proxy %s received %u %x from %s", __func__,
			    msi->type, msi->sessid, ifn->ifname);

		switch (msi->type) {
		case SESSIDDESTROY:
			if (msi->sessid == peer->sesstent) {
				sessid = &peer->sesstent;
			} else if (msi->sessid == peer->sessnext) {
				sessid = &peer->sessnext;
			} else if (msi->sessid == peer->sesscurr) {
				sessid = &peer->sesscurr;
			} else if (msi->sessid == peer->sessprev) {
				sessid = &peer->sessprev;
			} else {
				logwarnx("proxy %s %s: could not destroy session for "
				    "peer %u, session id not found: %x",
				    __func__, ifn->ifname, peer->id,
				    msi->sessid);
				break;
			}
			if (sessmapvreplace(ifn, peer, msi->sessid, -1) == -1)
				logwarn("proxy %s could not remove session id: %x",
				    __func__, msi->sessid);
			*sessid = -1;
			break;
		case SESSIDTENT:
			if (sessmapvreplace(ifn, peer, peer->sesstent,
			    msi->sessid) == -1)
				logwarn("proxy %s could not find tent session id: "
				    "%llx", __func__, peer->sesstent);
			peer->sesstent = msi->sessid;
			break;
		case SESSIDNEXT:
			if (sessmapvreplace(ifn, peer, peer->sessnext,
			    msi->sessid) == -1)
				logwarn("proxy %s could not find next session id: "
				    "%llx", __func__, peer->sessnext);
			peer->sessnext = msi->sessid;
			break;
		case SESSIDCURR:
			if (msi->sessid == peer->sesstent) {
				sessid = &peer->sesstent;
			} else if (msi->sessid == peer->sessnext) {
				sessid = &peer->sessnext;
			} else {
				logwarnx("proxy %s %s: current session for peer %u "
				    "was not tentative or next: %x", __func__,
				    ifn->ifname, peer->id, msi->sessid);
				break;
			}

			/*
			 * if prev, destroy
			 * if curr, rotate to prev
			 * if new == tent
			 *    curr = tent
			 *    tent = -1
			 * if new == next
			 *    curr = next
			 *    next = -1
			 * curr = new
			 */

			if (peer->sessprev != -1)
				if (sessmapvreplace(ifn, peer, peer->sessprev,
				    -1) == -1)
					logwarn("proxy %s could not find prev session"
					    " id: %llx", __func__,
					    peer->sessprev);

			if (peer->sesscurr != -1)
				peer->sessprev = peer->sesscurr;

			peer->sesscurr = msi->sessid;
			*sessid = -1;
			break;
		}
		break;
	default:
		logwarnx("proxy %s unexpected message from %s: %u", __func__,
		    ifn->ifname, mtcode);
		return -1;
	}

	return 0;
}

/*
 * Receive and handle a message from the Internet.
 *
 * MSGWGINIT
 *   If mac1 OK, forward to enclave
 * MSGWGRESP
 *   If mac1 OK and session exists, forward to enclave
 * MSGWGCOOKIE
 *   If mac1 OK and session exists, forward to enclave
 * MSGWGDATA
 *   If mac1 OK and session exists, forward to interface process
 *
 * TODO handle EWOULDBLOCK / create cookies
 *
 * Return 0 on success, -1 on error.
 */
static int
handlesockmsg(const struct sockmap *sockmap)
{
	struct msgwginit *mwi;
	struct msgwgresp *mwr;
	struct msgwgdatahdr *mwdhdr;
	struct ifn *ifn;
	struct peer *peer;
	ssize_t rc;
	size_t msgsize;
	unsigned char mtcode;
	socklen_t peeraddrsize;

	ifn = sockmap->ifn;

	peeraddrsize = sizeof(peeraddr);
	rc = recvfrom(sockmap->s, msg, sizeof(msg), 0,
	    (struct sockaddr *)&peeraddr, &peeraddrsize);
	if (rc < 1) {
		if (verbose > -1)
			logwarnx("proxy %s recvfrom", __func__);
		return -1;
	}
	msgsize = rc;

	totalrecv++;
	totalrecvsz += msgsize;

	mtcode = msg[0];
	if (mtcode >= MTNCODES) {
		loginfox("proxy %s unexpected message code got %d", __func__, mtcode);
		corrupted++;
		return -1;
	}

	if (msgtypes[mtcode].varsize) {
		if (msgsize < msgtypes[mtcode].size) {
			logwarnx("proxy %s expected at least %zu bytes instead of "
			    "%zu", __func__, msgtypes[1].size, msgsize);
			corrupted++;
			return -1;
		}
	} else if (msgsize != msgtypes[mtcode].size) {
		logwarnx("proxy %s expected message size %zu, got %zu",
		    __func__, msgtypes[1].size, msgsize);
		corrupted++;
		return -1;
	}

	if (verbose > 1)
		loginfox("proxy %s received %u for %s", __func__, mtcode,
		    ifn->ifname);

	switch (mtcode) {
	case MSGWGINIT:
		mwi = (struct msgwginit *)msg;
		if (!ws_validmac(mwi->mac1, sizeof(mwi->mac1), mwi,
		    MAC1OFFSETINIT, ifn->mac1key)) {
			logwarnx("proxy %s MSGWGINIT invalid mac1", __func__);
			invalidmac++;
			return -1;
		}

		if (wire_proxysendmsg(eport, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("proxy %s enclave does not respond", __func__);
			return -1;
		}

		totalfwdenc++;
		totalfwdencsz += msgsize;
		break;
	case MSGWGRESP:
		mwr = (struct msgwgresp *)msg;
		if (!findpeerbysessidandifn(&peer, ifn,
		    le32toh(mwr->receiver))) {
			loginfox("proxy %s MSGWGRESP unknown receiver %x for %s",
			    __func__, le32toh(mwr->receiver), ifn->ifname);
			invalidpeer++;
			return -1;
		}
		if (!ws_validmac(mwr->mac1, sizeof(mwr->mac1), mwr,
		    MAC1OFFSETRESP, ifn->mac1key)) {
			logwarnx("proxy %s MSGWGRESP invalid mac1", __func__);
			invalidmac++;
			return -1;
		}

		if (wire_proxysendmsg(eport, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("proxy %s enclave does not respond", __func__);
			return -1;
		}

		totalfwdenc++;
		totalfwdencsz += msgsize;
		break;
	case MSGWGCOOKIE:
		/* TODO */
		break;
	case MSGWGDATA:
		mwdhdr = (struct msgwgdatahdr *)msg;
		if (!findpeerbysessidandifn(&peer, ifn,
		    le32toh(mwdhdr->receiver))) {
			loginfox("proxy %s MSGWGDATA unknown receiver %x for %s",
			    __func__, le32toh(mwdhdr->receiver), ifn->ifname);
			invalidpeer++;
			return -1;
		}

		peer->recv++;
		peer->recvsz += msgsize;

		if (wire_proxysendmsg(ifn->port, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("proxy %s %s does not respond", __func__,
			    ifn->ifname);
			return -1;
		}

		peer->sent++;
		peer->sentsz += msgsize;
		totalfwdifn++;
		totalfwdifnsz += msgsize;
		break;
	default:
		if (verbose > 1)
			loginfox("proxy %s received unsupported message %d", __func__,
			    mtcode);
		corrupted++;
		return -1;
	}

	return 0;
}

/*
 * Listen for messages on the server sockets or from the ifn processes.
 *
 * Won't return on success.
 *
 * TODO: MSGWGCOOKIE	-> usock
 */
void
proxy_serv(void)
{
	struct sockmap *sockmap;
	struct kevent *ev;
	size_t evsize, n;
	int i, kq, nev;

	/*
	 * Setup listeners for each IPC and UDP socket.
	 */

	if ((kq = kqueue()) == -1)
		logexit(1, "proxy %s kqueue", __func__);

	evsize = sockmapvsize;
	if ((ev = calloc(evsize, sizeof(*ev))) == NULL)
		logexit(1, "proxy %s calloc", __func__);

	for (n = 0; n < sockmapvsize; n++)
		EV_SET(&ev[n], sockmapv[n]->s, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if ((nev = kevent(kq, ev, evsize, NULL, 0, NULL)) == -1)
		logexit(1, "proxy %s kevent", __func__);

	for (;;) {
		if (logstats) {
			proxy_loginfo();
			logstats = 0;
		}

		if (doterm)
			logexitx(1, "proxy %s received TERM, shutting down",
			    __func__);

		if ((nev = kevent(kq, NULL, 0, ev, evsize, NULL)) == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				logexit(1, "proxy %s kevent", __func__);
			}
		}

		if (verbose > 2)
			logdebugx("proxy %s %d events", __func__, nev);

		for (i = 0; i < nev; i++) {
			if (!findsockmapbysock(&sockmap, ev[i].ident)) {
				if (verbose > -1)
					logwarnx("proxy %s socket event not found: "
					    "%lu", __func__, ev[i].ident);
				continue;
			} else {
				if (verbose > 1) {
					loginfox("proxy %s %s event for %s",
					    __func__,
					    sockmap->listenaddr ? "UDP" : "IPC",
					    sockmap->ifn->ifname);
				}
			}

			if (sockmap->listenaddr) {
				if (ev[i].flags & EV_EOF) {
					if (verbose > -1)
						logwarnx("proxy %s %s socket EOF",
						    __func__,
						    sockmap->ifn->ifname);
					if (close(sockmap->s) == -1)
						logexit(1, "proxy %s close",
						    __func__);
					break;
				}
				handlesockmsg(sockmap);
				break;
			} else {
				if (ev[i].flags & EV_EOF) {
					if (verbose > -1)
						logwarnx("proxy %s %s EOF",
						    __func__,
						    sockmap->ifn->ifname);
					if (close(sockmap->s) == -1)
						logexit(1, "proxy %s close",
						    __func__);
					break;
				}
				handleifnmsg(sockmap);
				break;
			}
		}
	}
}

/*
 * Receive configuration from the master.
 *
 * SINIT
 * SIFN
 * SCIDRADDR
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
	size_t n, m, msgsize;
	unsigned char mtcode;
	struct ifn *ifn;
	union sockaddr_inet *listenaddr;
	struct peer *peer;
	struct sessmap *sessmap;

	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
		logexitx(1, "proxy %s wire_recvmsg SINIT %d", __func__, masterport);
	if (mtcode != SINIT)
		logexitx(1, "proxy %s mtcode SINIT %d", __func__, mtcode);

	background = smsg.init.background;
	verbose = smsg.init.verbose;
	uid = smsg.init.uid;
	gid = smsg.init.gid;
	eport = smsg.init.enclport;
	ifnvsize = smsg.init.nifns;

	if ((ifnv = calloc(ifnvsize, sizeof(*ifnv))) == NULL)
		logexit(1, "proxy %s calloc ifnv", __func__);

	for (n = 0; n < ifnvsize; n++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "proxy %s wire_recvmsg SIFN", __func__);
		if (mtcode != SIFN)
			logexitx(1, "proxy %s mtcode SIFN", __func__);

		if ((ifn = malloc(sizeof(**ifnv))) == NULL)
			logexit(1, "proxy %s malloc ifnv[%zu]", __func__, n);

		assert(smsg.ifn.ifnid == n);

		ifn->id = smsg.ifn.ifnid;
		ifn->ifname = strdup(smsg.ifn.ifname);
		ifn->port = smsg.ifn.ifnport;
		ifn->listenaddrssize = smsg.ifn.laddr6count +
		    smsg.ifn.laddr4count;
		memcpy(ifn->mac1key, smsg.ifn.mac1key,
		    MIN(sizeof ifn->mac1key, sizeof smsg.ifn.mac1key));
		memcpy(ifn->cookiekey, smsg.ifn.cookiekey,
		    MIN(sizeof ifn->cookiekey, sizeof smsg.ifn.cookiekey));

		ifn->peerssize = smsg.ifn.npeers;
		if ((ifn->peers = calloc(ifn->peerssize, sizeof(*ifn->peers)))
		    == NULL)
			logexit(1, "proxy %s calloc ifnv->peers", __func__);

		for (m = 0; m < ifn->peerssize; m++) {
			peer = malloc(sizeof(*ifn->peers[m]));
			if (peer == NULL)
				logexit(1, "proxy %s malloc peer", __func__);
			peer->id = m;
			peer->sesstent = -1;
			peer->sessnext = -1;
			peer->sesscurr = -1;
			peer->sessprev = -1;
			ifn->peers[m] = peer;
		}

		if (MAXPEERS / 4 < ifn->peerssize)
			logexitx(1, "proxy %s only %d peers are supported", __func__,
			    MAXPEERS);

		ifn->sessmapvsize = ifn->peerssize * 4;
		if ((ifn->sessmapv = calloc(ifn->sessmapvsize,
		    sizeof(*ifn->sessmapv))) == NULL)
			logexit(1, "proxy %s calloc ifn->sessmapv", __func__);

		for (m = 0; m < ifn->sessmapvsize; m++) {
			sessmap = malloc(sizeof(*ifn->sessmapv[m]));
			if (sessmap == NULL)
				logexit(1, "proxy %s malloc sessmap", __func__);
			sessmap->sessid = -1;
			sessmap->peer = NULL;
			ifn->sessmapv[m] = sessmap;
		}

		/* receive all server addresses */
		if ((ifn->listenaddrs = calloc(ifn->listenaddrssize,
		    sizeof(*ifn->listenaddrs))) == NULL)
			logexit(1, "proxy %s calloc ifn->listenaddrs", __func__);

		for (m = 0; m < ifn->listenaddrssize; m++) {
			msgsize = sizeof(smsg);
			if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize)
			    == -1)
				logexitx(1, "proxy %s wire_recvmsg SCIDRADDR",
				    __func__);
			if (mtcode != SCIDRADDR)
				logexitx(1, "proxy %s expected SCIDRADDR %d got %d",
				    __func__, SCIDRADDR, mtcode);

			assert(smsg.cidraddr.ifnid == ifn->id);

			if (smsg.cidraddr.addr.h.family != AF_INET6 &&
			    smsg.cidraddr.addr.h.family != AF_INET) {
				logwarnx("proxy %s unsupported address family: %d",
				    __func__, smsg.cidraddr.addr.h.family);
				continue;
			}

			if ((listenaddr = malloc(sizeof(*listenaddr))) == NULL)
				logexit(1, "proxy %s malloc listenaddr", __func__);

			memcpy(listenaddr, &smsg.cidraddr.addr,
			    MIN(sizeof *listenaddr, sizeof smsg.cidraddr.addr));

			ifn->listenaddrs[m] = listenaddr;
		}

		ifnv[n] = ifn;
	}

	/* expect end of startup signal */
	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
		logexitx(1, "proxy %s wire_recvmsg", __func__);
	if (mtcode != SEOS)
		logexitx(1, "proxy %s expected SEOS %d got %d", __func__, SEOS,
		    mtcode);

	explicit_bzero(&smsg, sizeof(smsg));

	if (verbose > 1)
		loginfox("proxy %s config received from %d", __func__, masterport);
}

/*
 * "masterport" descriptor to communicate with the master process and receive
 * the configuration.
 */
void
proxy_init(int masterport)
{
	char addrstr[MAXADDRSTR];
	union sockaddr_inet *listenaddr;
	struct sigaction sa;
	size_t heapneeded, i, m, n, nrlistenaddrs, nrpeers, nrsessmaps;
	const int on = 1;
	int stdopen, s;
	socklen_t len;
	uint32_t ifnid;

	recvconfig(masterport);

	/*
	 * Make sure we are not missing any communication channels and that
	 * there is no descriptor leak.
	 */

	stdopen = isopenfd(STDIN_FILENO) + isopenfd(STDOUT_FILENO) +
	    isopenfd(STDERR_FILENO);

	if (!isopenfd(masterport))
		logexitx(1, "proxy %s masterport %d", __func__, masterport);
	if (!isopenfd(eport))
		logexitx(1, "proxy %s eport %d", __func__, eport);

	for (n = 0; n < ifnvsize; n++) {
		if (!isopenfd(ifnv[n]->port))
			logexitx(1, "proxy %s %s port not open, fd %d", __func__,
			    ifnv[n]->ifname, ifnv[n]->port);
	}

	if ((size_t)getdtablecount() != stdopen + 2 + ifnvsize)
		logexitx(1, "proxy %s descriptor mismatch: %d", __func__,
		    getdtablecount());

	/*
	 * Initialize IPC and UDP sockets in one sorted array so that we can
	 * easily monitor events. Start server sockets but don't process input
	 * before dropping privileges.
	 */
	sockmapv = NULL;
	sockmapvsize = 0;
	i = 0;
	for (n = 0; n < ifnvsize; n++) {
		/* one IPC socket plus one for all listen addressses */
		sockmapvsize += 1 + ifnv[n]->listenaddrssize;

		sockmapv = reallocarray(sockmapv, sockmapvsize,
		    sizeof(*sockmapv));
		if (sockmapv == NULL)
			logexit(1, "proxy %s reallocarray error sockmapv", __func__);

		sockmapv[i] = malloc(sizeof(*sockmapv[i]));
		if (sockmapv[i] == NULL)
			logexit(1, "proxy %s malloc sockmapv[i]", __func__);

		sockmapv[i]->s = ifnv[n]->port;
		sockmapv[i]->ifn = ifnv[n];
		sockmapv[i]->listenaddr = NULL;

		/*
		 * Before creating server sockets, wait for each ifn process to
		 * send the signal that it has created its sockets.
		 */
		if (read(ifnv[n]->port, &ifnid, sizeof ifnid) == -1)
			logexit(1, "proxy read error proxy to ifn %zu", n);

		if (ifnid != ifnv[n]->id)
			logexit(1, "proxy ifn sent unexpected id %zu, got %zu",
			    ifnv[n]->id, ifnid);

		i++;

		for (m = 0; m < ifnv[n]->listenaddrssize; m++) {
			listenaddr = ifnv[n]->listenaddrs[m];
			s = socket(listenaddr->h.family, SOCK_DGRAM, 0);
			if (s == -1)
				logexit(1, "proxy %s socket listenaddr", __func__);

			if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on,
			    sizeof on) == -1)
				logexit(1, "proxy setsockopt reuseaddr error");

			len = MAXRECVBUF;
			if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &len,
			    sizeof len) == -1)
				logexit(1, "proxy setsockopt rcvbuf error");

			if (bind(s, (struct sockaddr *)listenaddr,
			    listenaddr->h.len) == -1) {
				addrtostr(addrstr, sizeof(addrstr),
				    (struct sockaddr *)listenaddr, 0);
				logexit(1, "proxy %s bind failed: %s", __func__,
				    addrstr);
			}

			sockmapv[i] = malloc(sizeof(*sockmapv[i]));
			if (sockmapv[i] == NULL)
				logexit(1, "proxy %s malloc sockmapv[i]", __func__);

			sockmapv[i]->s = s;
			sockmapv[i]->ifn = ifnv[n];
			sockmapv[i]->listenaddr = listenaddr;
			i++;

			addrtostr(addrstr, sizeof(addrstr),
			    (struct sockaddr *)listenaddr, 0);
			lognoticex("proxy %s listening %s", __func__, addrstr);
		}
	}

	loginfox("proxy %s server sockets created", __func__);

	/*
	 * Calculate roughly the amount of dynamic memory we need.
	 *
	 * XXX Unfortunately we cannot allocate everything upfront and then
	 * disable new allocations because it breaks forwarding packets somehow.
	 */

	nrlistenaddrs = 0;
	nrpeers = 0;
	nrsessmaps = 0;
	for (n = 0; n < ifnvsize; n++) {
		nrlistenaddrs += ifnv[n]->listenaddrssize;
		nrpeers += ifnv[n]->peerssize;
		nrsessmaps += ifnv[n]->sessmapvsize;
	}

	if (nrpeers > MAXPEERS)
		logexit(1, "proxy %s number of peers exceeds maximum %zu %zu",
		    __func__, nrpeers, MAXPEERS);

	heapneeded = MINDATA;
	heapneeded += nrpeers * sizeof(struct peer);
	heapneeded += ifnvsize * sizeof(struct ifn);
	heapneeded += nrlistenaddrs * sizeof(union sockaddr_inet);
	heapneeded += nrsessmaps * sizeof(struct sessmap);
	heapneeded += sockmapvsize * sizeof(struct kevent);
	heapneeded += sockmapvsize * sizeof(struct sockmap);

	xensurelimit(RLIMIT_DATA, heapneeded);
	xensurelimit(RLIMIT_FSIZE, MAXCORE);
	xensurelimit(RLIMIT_CORE, MAXCORE);
	xensurelimit(RLIMIT_MEMLOCK, 0);
	/* kqueue will be opened later */
	xensurelimit(RLIMIT_NOFILE, getdtablecount() + 1);
	xensurelimit(RLIMIT_NPROC, 0);
	xensurelimit(RLIMIT_STACK, MAXSTACK);

	/* print statistics on SIGUSR1 and do a graceful exit on SIGTERM */
	sa.sa_handler = handlesig;
	sa.sa_flags = SA_RESTART;
	if (sigemptyset(&sa.sa_mask) == -1)
		logexit(1, "proxy %s sigemptyset", __func__);
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		logexit(1, "proxy %s sigaction SIGUSR1", __func__);
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		logexit(1, "proxy %s sigaction SIGTERM", __func__);

	if (chroot(EMPTYDIR) == -1)
		logexit(1, "proxy %s chroot %s", __func__, EMPTYDIR);
	if (chdir("/") == -1)
		logexit(1, "proxy %s chdir", __func__);

	if (setgroups(1, &gid) ||
	    setresgid(gid, gid, gid) ||
	    setresuid(uid, uid, uid))
		logexit(1, "proxy %s: cannot drop privileges", __func__);

	if (pledge("stdio", "") == -1)
		logexit(1, "proxy %s pledge", __func__);
}

void
proxy_loginfo(void)
{
	struct ifn *ifn;
	struct peer *peer;
	size_t n, m;

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];
		logwarnx("proxy ifn %zu, id %d, port %d, sessmapvsize %zu", n,
		    ifn->id, ifn->port, ifn->sessmapvsize);

		for (m = 0; m < ifn->peerssize; m++) {
			peer = ifn->peers[m];
			logwarnx("proxy peer %zu session tent/next/curr/prev "
			    "%x/%x/%x/%x",
			    m,
			    (uint32_t)peer->sesstent,
			    (uint32_t)peer->sessnext,
			    (uint32_t)peer->sesscurr,
			    (uint32_t)peer->sessprev);
		}

		for (m = 0; m < ifn->sessmapvsize; m++)
			logwarnx("proxy %02d %08x", m, (uint32_t)ifn->sessmapv[m]->sessid);
	}

	logwarnx("proxy total recv %zu %zu bytes", totalrecv, totalrecvsz);
	logwarnx("proxy fwd ifn %zu %zu bytes", totalfwdifn, totalfwdifnsz);
	logwarnx("proxy fwd enc %zu %zu bytes", totalfwdenc, totalfwdencsz);
	logwarnx("proxy corrupted/invalid mac/invalid peer %zu/%zu/%zu",
	    corrupted, invalidmac, invalidpeer);
}
