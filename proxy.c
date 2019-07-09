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

void proxy_loginfo(void);

extern int background, verbose;

/*
 * A mapping between a IPC or a server socket. If listenaddr is set this is a
 * server socket, if it is not set this is an IPC socket.
 */
struct sockmap {
	int s;
	struct ifn *ifn;
	struct sockaddr_storage *listenaddr;
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
	struct sockaddr_storage **listenaddrs;
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
static struct sockaddr_storage peeraddr;
/* mapping of server sockets to listenaddr or ifn */
static struct sockmap **sockmapv;
static size_t sockmapvsize;

static size_t totalfwdifn, totalfwdifnsz, totalfwdenc, totalfwdencsz, totalrecv,
    totalrecvsz, corrupted, invalidmac, invalidpeer;

static int logstats, doterm;

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
 * Find a session by "sessid". Return 1 if found and updates "ifn" to
 * point to it. 0 if not found and updates "ifn" to NULL.
 *
 * XXX log(n) use sessmapv
 */
static int
findpeerbysessidandifn(struct peer **peer, const struct ifn *ifn,
    uint32_t sessid)
{
	size_t n;

	*peer = NULL;

	for (n = 0; n < ifn->peerssize; n++) {
		if (sessid == ifn->peers[n]->sesscurr) {
			*peer = ifn->peers[n];
			return 1;
		}
		if (sessid == ifn->peers[n]->sessprev) {
			*peer = ifn->peers[n];
			return 1;
		}
		if (sessid == ifn->peers[n]->sesstent) {
			*peer = ifn->peers[n];
			return 1;
		}
		if (sessid == ifn->peers[n]->sessnext) {
			*peer = ifn->peers[n];
			return 1;
		}
	}

	return 0;
}

/*
 * Replace session id "oid" with "nid".
 *
 * Return 0 on success, -1 if "oid" does not exist.
 *
 * XXX log(n)
 */
static int
sessmapvreplace(const struct ifn *ifn, struct peer *peer, int64_t oid,
    int64_t nid)
{
	size_t i;

	for (i = 0; i < ifn->sessmapvsize; i++) {
		if (ifn->sessmapv[i]->sessid == oid) {
			ifn->sessmapv[i]->sessid = nid;
			ifn->sessmapv[i]->peer = peer;
			return 0;
		}
	}

	return -1;
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
		logwarnx("wire_recvpeeridmsg %s", ifn->ifname);
		return -1;
	}

	if (!findpeerbyidandifn(&peer, peerid, ifn)) {
		logwarnx("unknown peerid from %s: %u", ifn->ifname, peerid);
		return -1;
	}

	switch (mtcode) {
	case MSGSESSID:
		msi = (struct msgsessid *)msg;

		if (verbose > 1)
			loginfox("received %u %u from %s", msi->type, msi->sessid,
			    ifn->ifname);

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
				logwarnx("%s: could not destroy session for peer "
				    "%u, session id not found: %u", ifn->ifname,
				    peer->id, msi->sessid);
				break;
			}
			if (sessmapvreplace(ifn, peer, msi->sessid, -1) == -1)
				logwarn("could not remove session id: %u",
				    msi->sessid);
			*sessid = -1;
			break;
		case SESSIDTENT:
			if (sessmapvreplace(ifn, peer, peer->sesstent,
			    msi->sessid) == -1)
				logwarn("could not find tent session id: %llu",
				    peer->sesstent);
			peer->sesstent = msi->sessid;
			break;
		case SESSIDNEXT:
			if (sessmapvreplace(ifn, peer, peer->sessnext,
			    msi->sessid) == -1)
				logwarn("could not find next session id: %llu",
				    peer->sessnext);
			peer->sessnext = msi->sessid;
			break;
		case SESSIDCURR:
			if (msi->sessid == peer->sesstent) {
				sessid = &peer->sesstent;
			} else if (msi->sessid == peer->sessnext) {
				sessid = &peer->sessnext;
			} else {
				logwarnx("%s: current session for peer %u was not "
				    "tentative or next: %u", ifn->ifname,
				    peer->id, msi->sessid);
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
					logwarn("could not find prev session id: "
					    "%llu", peer->sessprev);

			if (peer->sesscurr != -1)
				peer->sessprev = peer->sesscurr;

			peer->sesscurr = msi->sessid;
			*sessid = -1;
			break;
		}
		break;
	default:
		logwarnx("unexpected message from %s: %u", ifn->ifname, mtcode);
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
			logwarnx("%s recvfrom", __func__);
		return -1;
	}
	msgsize = rc;

	totalrecv++;
	totalrecvsz += msgsize;

	mtcode = msg[0];
	if (mtcode >= MTNCODES) {
		loginfox("%s unexpected message code got %d", __func__, mtcode);
		corrupted++;
		return -1;
	}

	if (msgtypes[mtcode].varsize) {
		if (msgsize < msgtypes[mtcode].size) {
			logwarnx("expected at least %zu bytes instead of %zu",
			    msgtypes[1].size, msgsize);
			corrupted++;
			return -1;
		}
	} else if (msgsize != msgtypes[mtcode].size) {
		logwarnx("%s expected message size %zu, got %zu",
		    __func__, msgtypes[1].size, msgsize);
		corrupted++;
		return -1;
	}

	if (verbose > 1)
		loginfox("received %u for %s", mtcode, ifn->ifname);

	switch (mtcode) {
	case MSGWGINIT:
		mwi = (struct msgwginit *)msg;
		if (!ws_validmac(mwi->mac1, sizeof(mwi->mac1), mwi, MAC1OFFSETINIT,
		    ifn->mac1key)) {
			logwarnx("MSGWGINIT invalid mac1");
			invalidmac++;
			return -1;
		}

		if (wire_proxysendmsg(eport, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("enclave does not respond");
			return -1;
		}

		totalfwdenc++;
		totalfwdencsz += msgsize;
		break;
	case MSGWGRESP:
		mwr = (struct msgwgresp *)msg;
		if (!findpeerbysessidandifn(&peer, ifn,
		    le32toh(mwr->receiver))) {
			loginfox("MSGWGRESP unknown receiver %u for %s",
			    le32toh(mwr->receiver), ifn->ifname);
			invalidpeer++;
			return -1;
		}
		if (!ws_validmac(mwr->mac1, sizeof(mwr->mac1), mwr,
		    MAC1OFFSETRESP, ifn->mac1key)) {
			logwarnx("MSGWGRESP invalid mac1");
			invalidmac++;
			return -1;
		}

		if (wire_proxysendmsg(eport, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("enclave does not respond");
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
			loginfox("MSGWGDATA unknown receiver %u for %s",
			    le32toh(mwdhdr->receiver), ifn->ifname);
			invalidpeer++;
			return -1;
		}

		peer->recv++;
		peer->recvsz += msgsize;

		if (wire_proxysendmsg(ifn->port, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("%s does not respond", ifn->ifname);
			return -1;
		}

		peer->sent++;
		peer->sentsz += msgsize;
		totalfwdifn++;
		totalfwdifnsz += msgsize;
		break;
	default:
		if (verbose > 1)
			loginfox("received unsupported message %d", mtcode);
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
		logexit(1, "kqueue");

	evsize = sockmapvsize;
	if ((ev = calloc(evsize, sizeof(*ev))) == NULL)
		logexit(1, "reallocarray");

	for (n = 0; n < sockmapvsize; n++)
		EV_SET(&ev[n], sockmapv[n]->s, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if ((nev = kevent(kq, ev, evsize, NULL, 0, NULL)) == -1)
		logexit(1, "kevent");

	for (;;) {
		if (logstats) {
			proxy_loginfo();
			logstats = 0;
		}

		if (doterm)
			logexitx(1, "received TERM, shutting down");

		if ((nev = kevent(kq, NULL, 0, ev, evsize, NULL)) == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				logexit(1, "kevent");
			}
		}

		if (verbose > 2)
			logdebugx("%d events", nev);

		for (i = 0; i < nev; i++) {
			if (!findsockmapbysock(&sockmap, ev[i].ident)) {
				if (verbose > -1)
					logwarnx("socket event not found: %lu",
					    ev[i].ident);
				continue;
			} else {
				if (verbose > 1) {
					loginfox("%s event %s",
					    sockmap->listenaddr ? "UDP" : "IPC",
					    sockmap->ifn->ifname);
				}
			}

			if (sockmap->listenaddr) {
				if (ev[i].flags & EV_EOF) {
					if (verbose > -1)
						logwarnx("%s socket EOF",
						    sockmap->ifn->ifname);
					if (close(sockmap->s) == -1)
						logexit(1, "close");
					break;
				}
				handlesockmsg(sockmap);
				break;
			} else {
				if (ev[i].flags & EV_EOF) {
					if (verbose > -1)
						logwarnx("%s EOF",
						    sockmap->ifn->ifname);
					if (close(sockmap->s) == -1)
						logexit(1, "close");
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
	struct sockaddr_storage *listenaddr;
	struct peer *peer;
	struct sessmap *sessmap;

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
	ifnvsize = smsg.init.nifns;

	if ((ifnv = calloc(ifnvsize, sizeof(*ifnv))) == NULL)
		logexit(1, "calloc ifnv");

	for (n = 0; n < ifnvsize; n++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "wire_recvmsg SIFN");
		if (mtcode != SIFN)
			logexitx(1, "mtcode SIFN");

		if ((ifn = malloc(sizeof(**ifnv))) == NULL)
			logexit(1, "malloc ifnv[%zu]", n);

		assert(smsg.ifn.ifnid == n);

		ifn->id = smsg.ifn.ifnid;
		ifn->ifname = strdup(smsg.ifn.ifname);
		ifn->port = smsg.ifn.ifnport;
		ifn->listenaddrssize = smsg.ifn.nlistenaddrs;
		memcpy(ifn->mac1key, smsg.ifn.mac1key, sizeof(smsg.ifn.mac1key));
		memcpy(ifn->cookiekey, smsg.ifn.cookiekey,
		    sizeof(smsg.ifn.cookiekey));

		ifn->peerssize = smsg.ifn.npeers;
		if ((ifn->peers = calloc(ifn->peerssize, sizeof(*ifn->peers)))
		    == NULL)
			logexit(1, "calloc ifnv->peers");

		for (m = 0; m < ifn->peerssize; m++) {
			peer = malloc(sizeof(*ifn->peers[m]));
			if (peer == NULL)
				logexit(1, "malloc peer");
			peer->id = m;
			peer->sesstent = -1;
			peer->sessnext = -1;
			peer->sesscurr = -1;
			peer->sessprev = -1;
			ifn->peers[m] = peer;
		}

		/* init session map with unused session ids */
		ifn->sessmapvsize = ifn->peerssize * 4;
		if ((ifn->sessmapv = calloc(ifn->sessmapvsize,
		    sizeof(*ifn->sessmapv))) == NULL)
			logexit(1, "calloc ifn->sessmapv");

		for (m = 0; m < ifn->sessmapvsize; m++) {
			sessmap = malloc(sizeof(*ifn->sessmapv[m]));
			if (sessmap == NULL)
				logexit(1, "malloc sessmap");
			sessmap->sessid = -1;
			sessmap->peer = NULL;
			ifn->sessmapv[m] = sessmap;
		}

		/* receive all server addresses */
		if ((ifn->listenaddrs = calloc(ifn->listenaddrssize,
		    sizeof(*ifn->listenaddrs))) == NULL)
			logexit(1, "calloc ifn->listenaddrs");

		for (m = 0; m < ifn->listenaddrssize; m++) {
			msgsize = sizeof(smsg);
			if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize)
			    == -1)
				logexitx(1, "wire_recvmsg SCIDRADDR");
			if (mtcode != SCIDRADDR)
				logexitx(1, "expected SCIDRADDR %d got %d",
				    SCIDRADDR, mtcode);

			assert(smsg.cidraddr.ifnid == ifn->id);

			if (smsg.cidraddr.addr.ss_family != AF_INET6 &&
			    smsg.cidraddr.addr.ss_family != AF_INET) {
				logwarnx("unsupported address family: %d",
				    smsg.cidraddr.addr.ss_family);
				continue;
			}

			if ((listenaddr = malloc(sizeof(*listenaddr))) == NULL)
				logexit(1, "malloc listenaddr");

			memcpy(listenaddr, &smsg.cidraddr.addr,
			    sizeof(smsg.cidraddr.addr));

			ifn->listenaddrs[m] = listenaddr;
		}

		ifnv[n] = ifn;
	}

	/* expect end of startup signal */
	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
		logexitx(1, "wire_recvmsg");
	if (mtcode != SEOS)
		logexitx(1, "expected SEOS %d got %d", SEOS, mtcode);

	explicit_bzero(&smsg, sizeof(smsg));

	if (verbose > 1)
		loginfox("config received from %d", masterport);
}

/*
 * "masterport" descriptor to communicate with the master process and receive
 * the configuration.
 */
void
proxy_init(int masterport)
{
	struct sockaddr_storage *listenaddr;
	struct sigaction sa;
	size_t i, m, n;
	int stdopen, s;

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

	for (n = 0; n < ifnvsize; n++) {
		if (!isopenfd(ifnv[n]->port))
			logexitx(1, "%s port not open, fd %d", ifnv[n]->ifname,
			    ifnv[n]->port);
	}

	if ((size_t)getdtablecount() != stdopen + 2 + ifnvsize)
		logexitx(1, "descriptor mismatch: %d", getdtablecount());

	/*
	 * Initialize IPC and UDP sockets in one sorted array so that we can
	 * easily monitor events. Start server sockets but don't process input
	 * before dropping privileges.
	 */
	sockmapv = NULL;
	sockmapvsize = 0;
	i = 0;
	for (n = 0; n < ifnvsize; n++) {
		sockmapvsize += 1 + ifnv[n]->listenaddrssize;

		sockmapv = reallocarray(sockmapv, sockmapvsize,
		    sizeof(*sockmapv));
		if (sockmapv == NULL)
			logexit(1, "reallocarray sockmapv");

		sockmapv[i] = malloc(sizeof(*sockmapv[i]));
		if (sockmapv[i] == NULL)
			logexit(1, "malloc sockmapv[i]");

		sockmapv[i]->s = ifnv[n]->port;
		sockmapv[i]->ifn = ifnv[n];
		sockmapv[i]->listenaddr = NULL;
		i++;

		for (m = 0; m < ifnv[n]->listenaddrssize; m++) {
			listenaddr = ifnv[n]->listenaddrs[m];
			s = socket(listenaddr->ss_family, SOCK_DGRAM, 0);
			if (s == -1)
				logexit(1, "socket listenaddr");
			if (bind(s, (struct sockaddr *)listenaddr,
			    listenaddr->ss_len) == -1) {
				if (verbose > -1)
					printaddr(stderr,
					    (struct sockaddr *)listenaddr,
					    "bind failed:", "\n");
				logexit(1, "bind");
			}

			sockmapv[i] = malloc(sizeof(*sockmapv[i]));
			if (sockmapv[i] == NULL)
				logexit(1, "malloc sockmapv[i]");

			sockmapv[i]->s = s;
			sockmapv[i]->ifn = ifnv[n];
			sockmapv[i]->listenaddr = listenaddr;
			i++;

			if (verbose > 0)
				printaddr(stderr, (struct sockaddr *)listenaddr,
				    "listening", "\n");
		}
	}

	if (verbose > 1)
		loginfox("server sockets created: ");

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
	if (pledge("stdio", "") == -1)
		logexit(1, "pledge");
}

void
proxy_loginfo(void)
{
	struct ifn *ifn;
	struct peer *peer;
	size_t n, m;

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];
		logwarnx("ifn %zu, id %d, port %d, sessmapvsize %zu", n,
		    ifn->id, ifn->port, ifn->sessmapvsize);

		for (m = 0; m < ifn->peerssize; m++) {
			peer = ifn->peers[m];
			logwarnx("peer %zu session tent/next/curr/prev "
			    "%x/%x/%x/%x",
			    m,
			    (uint32_t)peer->sesstent,
			    (uint32_t)peer->sessnext,
			    (uint32_t)peer->sesscurr,
			    (uint32_t)peer->sessprev);
		}

		for (m = 0; m < ifn->sessmapvsize; m++)
			logwarnx("%02d %07x", m, (uint32_t)ifn->sessmapv[m]->sessid);
	}

	logwarnx("total recv %zu %zu bytes\n"
	    "fwd ifn %zu %zu bytes\n"
	    "fwd enc %zu %zu bytes\n"
	    "corrupted %zu\n"
	    "invalid mac %zu\n"
	    "invalid peer %zu",
	    totalrecv, totalrecvsz,
	    totalfwdifn, totalfwdifnsz,
	    totalfwdenc, totalfwdencsz,
	    corrupted, invalidmac, invalidpeer);
}
