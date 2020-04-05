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

/*
 * All session ids in both the sessmap and peer structures are in 64 bits in
 * host byte order. This is to represent the inactive session -1. All incoming
 * messages over the listening sockets and ipc are in wire format which is
 * little-endian.
 */

struct sessmap {
	int64_t sessid;		/* host byte order */
	struct peer *peer;
};

struct peer {
	uint32_t id;
	int64_t sesstent;	/* host byte order */
	int64_t sessnext;	/* host byte order */
	int64_t sesscurr;	/* host byte order */
	int64_t sessprev;	/* host byte order */
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
	case SIGINT:
		/* FALLTHROUGH */
	case SIGTERM:
		doterm = 1;
		break;
	default:
		logwarnx("proxy unexpected signal %d %s", signo,
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
	if (sessidx == -1) {
		if (verbose > 0)
			lognoticex("proxy %s %llx old session id %llx not found",
			    ifn->ifname, nid, oid);
		return -1;
	}

	ifn->sessmapv[sessidx]->sessid = nid;
	ifn->sessmapv[sessidx]->peer = peer;

	if (nid == oid) {
		if (verbose > 0)
			lognoticex("proxy %s %llx old and new session ids are "
			    "equal", ifn->ifname, nid);
	} else if (nid > oid) {
		if (verbose > 1)
			loginfox("proxy %s %08x replaced %08x", ifn->ifname,
			    (uint32_t)nid, (uint32_t)oid);
		sort(&ifn->sessmapv[sessidx], ifn->sessmapvsize - sessidx);
	} else {
		if (verbose > 1)
			loginfox("proxy %s %08x replaced %08x", ifn->ifname,
			    (uint32_t)nid, (uint32_t)oid);
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
	int64_t *sessidp, sessid;

	ifn = sockmap->ifn;

	msgsize = sizeof(msg);
	if (wire_recvpeeridmsg(ifn->port, &peerid, &mtcode, msg, &msgsize)
	    == -1) {
		logwarnx("proxy %s wire_recvpeeridmsg error", ifn->ifname);
		return -1;
	}

	if (!findpeerbyidandifn(&peer, peerid, ifn)) {
		logwarnx("proxy %s unknown peerid %u", ifn->ifname, peerid);
		return -1;
	}

	switch (mtcode) {
	case MSGSESSID:
		msi = (struct msgsessid *)msg;
		sessid = le32toh(msi->sessid);

		if (verbose > 2)
			logdebugx("proxy %s %x type %u received", ifn->ifname,
			    sessid, msi->type);

		switch (msi->type) {
		case SESSIDDESTROY:
			if (sessid == peer->sesstent) {
				sessidp = &peer->sesstent;
			} else if (sessid == peer->sessnext) {
				sessidp = &peer->sessnext;
			} else if (sessid == peer->sesscurr) {
				sessidp = &peer->sesscurr;
			} else if (sessid == peer->sessprev) {
				sessidp = &peer->sessprev;
			} else {
				logwarnx("proxy %s %x could not destroy "
				    "session for peer %u, session id not found",
				    ifn->ifname, sessid, peer->id);
				break;
			}
			if (sessmapvreplace(ifn, peer, sessid, -1) == -1)
				logwarn("proxy %s %x could not remove session",
				    ifn->ifname, sessid);
			*sessidp = -1;
			break;
		case SESSIDTENT:
			if (sessmapvreplace(ifn, peer, peer->sesstent, sessid)
			    == -1)
				logwarn("proxy %s %llx tentative session not "
				    "found", ifn->ifname, peer->sesstent);
			peer->sesstent = sessid;
			break;
		case SESSIDNEXT:
			if (sessmapvreplace(ifn, peer, peer->sessnext, sessid)
			    == -1)
				logwarn("proxy %s %llx next session not found",
				    ifn->ifname, peer->sessnext);
			peer->sessnext = sessid;
			break;
		case SESSIDCURR:
			if (sessid == peer->sesstent) {
				sessidp = &peer->sesstent;
			} else if (sessid == peer->sessnext) {
				sessidp = &peer->sessnext;
			} else {
				logwarnx("proxy %s %x new current session for "
				    "peer %u was not tentative or next",
				    ifn->ifname, sessid, peer->id);
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
					logwarn("proxy %s %llx previous session"
					    " not found", ifn->ifname,
					    peer->sessprev);

			if (peer->sesscurr != -1)
				peer->sessprev = peer->sesscurr;

			peer->sesscurr = sessid;
			*sessidp = -1;
			break;
		}
		break;
	default:
		logwarnx("proxy %s unexpected message type %u from ifn",
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
	char verbosepeeraddr[MAXADDRSTR];
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
	if (rc == -1) {
		if (verbose > -1)
			logwarn("proxy %s recvfrom error", ifn->ifname);
		return -1;
	}
	if (rc < 1) {
		if (verbose > -1)
			logwarnx("proxy %s recvfrom zero read error",
			    ifn->ifname);
		return -1;
	}
	msgsize = rc;

	totalrecv++;
	totalrecvsz += msgsize;

	if (verbose > 0) {
		addrtostr(verbosepeeraddr, sizeof verbosepeeraddr,
		    (struct sockaddr *)&peeraddr, 0);
	} else {
		verbosepeeraddr[0] = '\0';
	}

	mtcode = msg[0];
	if (mtcode >= MTNCODES) {
		if (verbose > 0)
			lognoticex("proxy %s received message from %s with "
			    "unexpected message code %d", ifn->ifname,
			    verbosepeeraddr, mtcode);
		corrupted++;
		return -1;
	}

	if (msgtypes[mtcode].varsize) {
		if (msgsize < msgtypes[mtcode].size) {
			if (verbose > 0)
				lognoticex("proxy %s received message from %s"
				    " with an invalid message size, expected at"
				    " least %zu bytes instead of %zu",
				    ifn->ifname, verbosepeeraddr,
				    msgtypes[1].size, msgsize);
			corrupted++;
			return -1;
		}
	} else if (msgsize != msgtypes[mtcode].size) {
		if  (verbose > 0)
			lognoticex("proxy %s received message from %s with an "
			    "invalid message size, expected %zu bytes instead "
			    "of %zu", ifn->ifname, verbosepeeraddr,
			    msgtypes[1].size, msgsize);
		corrupted++;
		return -1;
	}

	if (verbose > 1) {
		if (mtcode == MSGWGINIT) {
			loginfox("proxy %s received init message from %s",
			    ifn->ifname, verbosepeeraddr);
		} else if (mtcode == MSGWGRESP) {
			loginfox("proxy %s received response message from %s",
			    ifn->ifname, verbosepeeraddr);
		} else if (mtcode == MSGWGCOOKIE) {
			loginfox("proxy %s received cookie message from %s",
			    ifn->ifname, verbosepeeraddr);
		} else if (mtcode == MSGWGDATA) {
			loginfox("proxy %s received data from %s (%zu bytes)",
			    ifn->ifname, verbosepeeraddr, msgsize);
		} else {
			loginfox("proxy %s received message type %u from %s "
			    "(%zu bytes)", ifn->ifname, mtcode, verbosepeeraddr,
			    msgsize);
		}
	}

	switch (mtcode) {
	case MSGWGINIT:
		mwi = (struct msgwginit *)msg;
		if (!ws_validmac(mwi->mac1, sizeof(mwi->mac1), mwi,
		    MAC1OFFSETINIT, ifn->mac1key)) {
			if (verbose > 0)
				lognoticex("proxy %s received init message from"
				    " %s with invalid mac1", ifn->ifname,
				    verbosepeeraddr);
			invalidmac++;
			return -1;
		}

		if (wire_proxysendmsg(eport, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("proxy %s error when trying to forward init "
			    "message from %s to enclave", ifn->ifname,
			    verbosepeeraddr);
			return -1;
		}

		totalfwdenc++;
		totalfwdencsz += msgsize;
		break;
	case MSGWGRESP:
		mwr = (struct msgwgresp *)msg;
		if (!findpeerbysessidandifn(&peer, ifn,
		    le32toh(mwr->receiver))) {
			if (verbose > 0)
				lognoticex("proxy %s received response message "
				    "from peer with unknown receiver %x",
				    ifn->ifname, le32toh(mwr->receiver));
			invalidpeer++;
			return -1;
		}
		if (!ws_validmac(mwr->mac1, sizeof(mwr->mac1), mwr,
		    MAC1OFFSETRESP, ifn->mac1key)) {
			if (verbose > 0)
				lognoticex("proxy %s received response message "
				    "from %s with invalid mac1", ifn->ifname,
				    verbosepeeraddr);
			invalidmac++;
			return -1;
		}

		if (wire_proxysendmsg(eport, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("proxy %s error when trying to forward response"
			    " message from %s to enclave", ifn->ifname,
			    verbosepeeraddr);
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
			if (verbose > 0)
				lognoticex("proxy %s received data from peer "
				    "with unknown receiver %x", ifn->ifname,
				    le32toh(mwdhdr->receiver));
			invalidpeer++;
			return -1;
		}

		peer->recv++;
		peer->recvsz += msgsize;

		if (wire_proxysendmsg(ifn->port, ifn->id, sockmap->listenaddr,
		    &peeraddr, mtcode, msg, msgsize) == -1) {
			logwarn("proxy %s error when trying to forward data "
			    "message from %s to ifn", ifn->ifname,
			    verbosepeeraddr);
			return -1;
		}

		peer->sent++;
		peer->sentsz += msgsize;
		totalfwdifn++;
		totalfwdifnsz += msgsize;
		break;
	default:
		if (verbose > 1)
			loginfox("proxy %s received unsupported message type "
			    "%d from %s", ifn->ifname, mtcode, verbosepeeraddr);
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

	if ((kq = kqueue()) == -1) {
		logwarn("proxy kqueue error");
		exit(1);
	}

	evsize = sockmapvsize;
	if ((ev = calloc(evsize, sizeof(*ev))) == NULL) {
		logwarn("proxy calloc evsize error");
		exit(1);
	}

	for (n = 0; n < sockmapvsize; n++)
		EV_SET(&ev[n], sockmapv[n]->s, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if ((nev = kevent(kq, ev, evsize, NULL, 0, NULL)) == -1) {
		logwarn("proxy kevent error");
		exit(1);
	}

	for (;;) {
		if (logstats) {
			proxy_loginfo();
			logstats = 0;
		}

		if (doterm) {
			if (verbose > 1)
				loginfox("proxy received termination signal, "
				    "shutting down");
			exit(1);
		}

		if ((nev = kevent(kq, NULL, 0, ev, evsize, NULL)) == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				logwarn("proxy kevent error");
				exit(1);
			}
		}

		if (verbose > 2)
			logdebugx("proxy %d events", nev);

		for (i = 0; i < nev; i++) {
			if (!findsockmapbysock(&sockmap, ev[i].ident)) {
				if (verbose > -1)
					logwarnx("proxy socket event not found:"
					    " %lu", ev[i].ident);
				continue;
			}

			if (sockmap->listenaddr) {
				if (ev[i].flags & EV_EOF) {
					if (verbose > -1)
						logwarnx("proxy %s server "
						    "socket eof",
						    sockmap->ifn->ifname);
					if (close(sockmap->s) == -1) {
						logwarn("proxy %s close "
						    "server socket error",
						    sockmap->ifn->ifname);
						exit(1);
					}
					break;
				}
				handlesockmsg(sockmap);
				break;
			} else {
				if (ev[i].flags & EV_EOF) {
					if (verbose > -1)
						logwarnx("proxy %s ipc socket "
						    "eof",
						    sockmap->ifn->ifname);
					if (close(sockmap->s) == -1) {
						logwarn("proxy %s close"
						    "ipc socket error",
						    sockmap->ifn->ifname);
						exit(1);
					}
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
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1) {
		logwarnx("proxy receive SINIT error %d", masterport);
		exit(1);
	}
	if (mtcode != SINIT) {
		logwarnx("proxy SINIT %d != %d", SINIT, mtcode);
		exit(1);
	}

	background = smsg.init.background;
	verbose = smsg.init.verbose;
	uid = smsg.init.uid;
	gid = smsg.init.gid;
	eport = smsg.init.enclport;
	ifnvsize = smsg.init.nifns;

	if ((ifnv = calloc(ifnvsize, sizeof(*ifnv))) == NULL) {
		logwarn("proxy calloc ifnv error");
		exit(1);
	}

	for (n = 0; n < ifnvsize; n++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1) {
			logwarnx("proxy receive SIFN error");
			exit(1);
		}
		if (mtcode != SIFN) {
			logwarnx("proxy SIFN %d != %d", SIFN, mtcode);
			exit(1);
		}

		if ((ifn = malloc(sizeof(**ifnv))) == NULL) {
			logwarn("proxy malloc ifnv[%zu] error", n);
			exit(1);
		}

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
		    == NULL) {
			logwarn("proxy calloc ifnv->peers error");
			exit(1);
		}

		for (m = 0; m < ifn->peerssize; m++) {
			peer = malloc(sizeof(*ifn->peers[m]));
			if (peer == NULL) {
				logwarn("proxy malloc peer error");
				exit(1);
			}
			peer->id = m;
			peer->sesstent = -1;
			peer->sessnext = -1;
			peer->sesscurr = -1;
			peer->sessprev = -1;
			ifn->peers[m] = peer;
		}

		if (MAXPEERS / 4 < ifn->peerssize) {
			logwarnx("proxy only %d peers are supported",
			    MAXPEERS);
			exit(1);
		}

		ifn->sessmapvsize = ifn->peerssize * 4;
		if ((ifn->sessmapv = calloc(ifn->sessmapvsize,
		    sizeof(*ifn->sessmapv))) == NULL) {
			logwarn("proxy calloc ifn->sessmapv error");
			exit(1);
		}

		for (m = 0; m < ifn->sessmapvsize; m++) {
			sessmap = malloc(sizeof(*ifn->sessmapv[m]));
			if (sessmap == NULL) {
				logwarn("proxy malloc sessmap error");
				exit(1);
			}
			sessmap->sessid = -1;
			sessmap->peer = NULL;
			ifn->sessmapv[m] = sessmap;
		}

		/* receive all server addresses */
		if ((ifn->listenaddrs = calloc(ifn->listenaddrssize,
		    sizeof(*ifn->listenaddrs))) == NULL) {
			logwarn("proxy calloc ifn->listenaddrs error");
			exit(1);
		}

		for (m = 0; m < ifn->listenaddrssize; m++) {
			msgsize = sizeof(smsg);
			if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize)
			    == -1) {
				logwarnx("proxy receive SCIDRADDR error");
				exit(1);
			}
			if (mtcode != SCIDRADDR) {
				logwarnx("proxy SCIDRADDR %d != %d",
				    SCIDRADDR, mtcode);
				exit(1);
			}

			assert(smsg.cidraddr.ifnid == ifn->id);

			if (smsg.cidraddr.addr.h.family != AF_INET6 &&
			    smsg.cidraddr.addr.h.family != AF_INET) {
				logwarnx("proxy unsupported address family: %d",
				    smsg.cidraddr.addr.h.family);
				continue;
			}

			if ((listenaddr = malloc(sizeof(*listenaddr))) == NULL) {
				logwarn("proxy malloc listenaddr error");
				exit(1);
			}

			memcpy(listenaddr, &smsg.cidraddr.addr,
			    MIN(sizeof *listenaddr, sizeof smsg.cidraddr.addr));

			ifn->listenaddrs[m] = listenaddr;
		}

		ifnv[n] = ifn;
	}

	/* expect end of startup signal */
	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1) {
		logwarnx("proxy receive SEOS error");
		exit(1);
	}
	if (mtcode != SEOS) {
		logwarnx("proxy SEOS %d != %d", SEOS, mtcode);
		exit(1);
	}

	explicit_bzero(&smsg, sizeof(smsg));

	if (verbose > 2)
		logdebugx("proxy config received from master");
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
	struct ifn *ifn;

	recvconfig(masterport);

	/*
	 * Make sure we are not missing any communication channels and that
	 * there is no descriptor leak.
	 */

	stdopen = isopenfd(STDIN_FILENO) + isopenfd(STDOUT_FILENO) +
	    isopenfd(STDERR_FILENO);

	if (!isopenfd(masterport)) {
		logwarnx("proxy masterport not open %d", masterport);
		exit(1);
	}
	if (!isopenfd(eport)) {
		logwarnx("proxy enclave port not open %d", eport);
		exit(1);
	}

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];
		if (!isopenfd(ifn->port)) {
			logwarnx("proxy %s port %d not open", ifn->ifname,
			    ifn->port);
			exit(1);
		}
	}

	if ((size_t)getdtablecount() != stdopen + 2 + ifnvsize) {
		logwarnx("proxy descriptor mismatch: %d != %zu",
		    getdtablecount(), stdopen + 2 + ifnvsize);
		exit(1);
	}

	/*
	 * Initialize IPC and UDP sockets in one sorted array so that we can
	 * easily monitor events. Start server sockets but don't process input
	 * before dropping privileges.
	 */
	sockmapv = NULL;
	sockmapvsize = 0;
	i = 0;
	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];

		/* one IPC socket plus one for all listen addressses */
		sockmapvsize += 1 + ifn->listenaddrssize;

		sockmapv = reallocarray(sockmapv, sockmapvsize,
		    sizeof(*sockmapv));
		if (sockmapv == NULL) {
			logwarn("proxy reallocarray sockmapv error");
			exit(1);
		}

		sockmapv[i] = malloc(sizeof(*sockmapv[i]));
		if (sockmapv[i] == NULL) {
			logwarn("proxy malloc sockmapv[i] error");
			exit(1);
		}

		sockmapv[i]->s = ifn->port;
		sockmapv[i]->ifn = ifn;
		sockmapv[i]->listenaddr = NULL;

		/*
		 * Before creating server sockets, wait for each ifn process to
		 * send the signal that it has created its sockets.
		 */
		if (read(ifn->port, &ifnid, sizeof ifnid) == -1) {
			logwarn("proxy %s read error port %d",
			    ifn->ifname, ifn->port);
			exit(1);
		}

		if (ifnid != ifn->id) {
			logwarnx("proxy %s received ifn id %u, expected "
			    "%u", ifn->ifname, ifnid, ifn->id);
			exit(1);
		}

		i++;

		for (m = 0; m < ifn->listenaddrssize; m++) {
			listenaddr = ifn->listenaddrs[m];
			s = socket(listenaddr->h.family, SOCK_DGRAM, 0);
			if (s == -1) {
				logwarn("proxy %s socket listenaddr error",
				    ifn->ifname);
				exit(1);
			}

			if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on,
			    sizeof on) == -1) {
				logwarn("proxy %s setsockopt reuseaddr "
				    "error", ifn->ifname);
				exit(1);
			}

			len = MAXRECVBUF;
			if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &len,
			    sizeof len) == -1) {
				logwarn("proxy %s setsockopt rcvbuf error",
				    ifn->ifname);
				exit(1);
			}

			if (bind(s, (struct sockaddr *)listenaddr,
			    listenaddr->h.len) == -1) {
				addrtostr(addrstr, sizeof(addrstr),
				    (struct sockaddr *)listenaddr, 0);
				logwarn("proxy %s bind for %s failed",
				    ifn->ifname, addrstr);
				exit(1);
			}

			sockmapv[i] = malloc(sizeof(*sockmapv[i]));
			if (sockmapv[i] == NULL) {
				logwarn("proxy %s malloc sockmapv[i] error",
				    ifn->ifname);
				exit(1);
			}

			sockmapv[i]->s = s;
			sockmapv[i]->ifn = ifn;
			sockmapv[i]->listenaddr = listenaddr;
			i++;

			addrtostr(addrstr, sizeof(addrstr),
			    (struct sockaddr *)listenaddr, 0);
			if (verbose > 0)
				lognoticex("proxy %s listening on %s",
				    ifn->ifname, addrstr);
		}
	}

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
		ifn = ifnv[n];
		nrlistenaddrs += ifn->listenaddrssize;
		nrpeers += ifn->peerssize;
		nrsessmaps += ifn->sessmapvsize;
	}

	if (nrpeers > MAXPEERS) {
		logwarn("proxy number of peers exceeds maximum %zu %d",
		    nrpeers, MAXPEERS);
		exit(1);
	}

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
	if (sigemptyset(&sa.sa_mask) == -1) {
		logwarn("proxy sigemptyset error");
		exit(1);
	}
	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		logwarn("proxy sigaction SIGUSR1 error");
		exit(1);
	}
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		logwarn("proxy sigaction SIGINT error");
		exit(1);
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		logwarn("proxy sigaction SIGTERM error");
		exit(1);
	}

	if (chroot(EMPTYDIR) == -1) {
		logwarn("proxy chroot %s error", EMPTYDIR);
		exit(1);
	}
	if (chdir("/") == -1) {
		logwarn("proxy chdir error");
		exit(1);
	}

	if (setgroups(1, &gid) ||
	    setresgid(gid, gid, gid) ||
	    setresuid(uid, uid, uid)) {
		logwarn("proxy cannot drop privileges");
		exit(1);
	}

	if (pledge("stdio", "") == -1) {
		logwarn("proxy pledge error");
		exit(1);
	}
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
			logwarnx("proxy %02zu %08x", m,
			    (uint32_t)ifn->sessmapv[m]->sessid);
	}

	logwarnx("proxy total recv %zu %zu bytes", totalrecv, totalrecvsz);
	logwarnx("proxy fwd ifn %zu %zu bytes", totalfwdifn, totalfwdifnsz);
	logwarnx("proxy fwd enc %zu %zu bytes", totalfwdenc, totalfwdencsz);
	logwarnx("proxy corrupted/invalid mac/invalid peer %zu/%zu/%zu",
	    corrupted, invalidmac, invalidpeer);
}
