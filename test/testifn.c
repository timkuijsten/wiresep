/*
 * Copyright (c) 2019 Tim Kuijsten
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

/*
 * Test packets from one ifn process to another.
 *
 * Fork the following processes:
 *   PITCHER that fires packets to a WireGuard peer via tun1
 *   IFN that sets up a tun1 interface
 *   IFN that sets up a tun2 interface
 *   CATCHER that catches any packets coming out of tun2
 *
 * let this process play the role of a pseudo master, enclave and proxy process.
 */

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include "../parseconfig.h"

/* inside job */
#include "../ifn.c"

#define DEFAULTPACKETS 100000
#define MINPAYLOADSIZE 0
#define MAXPAYLOADSIZE 256
#define MINPACKETSIZE (TUNHDRSIZ + MAXIPHDR + MINPAYLOADSIZE)
#define MAXPACKETSIZE (TUNHDRSIZ + MAXIPHDR + MAXPAYLOADSIZE)

typedef int chan[2];

struct testifn {
	pid_t pid;
	int mastwithtund;  /* tunnel descriptor for test ifn process */
	int ifnwithtund;
	int recvtun;       /* test counters */
	int recvencl;
	int recvprox;
	wskey sendkey;
	wskey recvkey;
	uint32_t sessid;
	uint32_t peersessid;
	struct cfgifn *cfgifn;
	struct testifn *peertestifn;
};

struct testsessmap {
	size_t peerid;
	uint32_t sessid;
};

struct testsockmap {
	struct sockaddr_storage ss;
	int s;
};

/* these are used by the other modules as well */
int background;
int verbose = 1;

/* global settings */
static uid_t guid;
static gid_t ggid;

static struct cfgifn **cfgifnv;
static size_t cfgifnvsize;

static size_t recvencl, recvprox, recvtun, recvtunsz;

static int logstats, doterm;

/* msg scratchpad is defined in ifn.c */

/*
 * Configure one interface with 8 peers.
 *
 * tun1 pubkey ErOyQKEbYQx/nFSiCFY+lDCe/3LfJ/v8UiHFpnvpo3Q=
 * tun2 pubkey 0PbkDqdhbg3N4JUA0cV+CxAWATiCQx7nZA+vjeG7s00=
 */
static const char config[] = "user 1109\n\
	interface tun1 {\n\
		ifaddr 172.16.1.17/16\n\
		listen [::1]:1234\n\
\n\
		privkey f5tK/SyL1G599SrSLPlul0Z4DFgqMglUrebRH7hSAZs=\n\
		psk     l8Oj31HlFvmxUOJw7zIvu/MJ66QDZfg/8+u3M4EHzbY=\n\
\n\
		# override global uid\n\
		user 1200\n\
\n\
		peer b {\n\
			pubkey  0PbkDqdhbg3N4JUA0cV+CxAWATiCQx7nZA+vjeG7s00=\n\
			allowedips 172.16.2.17/16\n\
			endpoint [::1]:2345\n\
		}\n\
	}\n\
	interface tun2 {\n\
		ifaddr 172.16.2.17/16\n\
		listen [::1]:2345\n\
\n\
		privkey X6EO9HiLHP+j7Gj9C9+P1eOoUjGjPZFSljJE4QLSFag=\n\
		psk     l8Oj31HlFvmxUOJw7zIvu/MJ66QDZfg/8+u3M4EHzbY=\n\
\n\
		# override global uid\n\
		user 2300\n\
\n\
		peer a {\n\
			pubkey ErOyQKEbYQx/nFSiCFY+lDCe/3LfJ/v8UiHFpnvpo3Q=\n\
			allowedips 172.16.1.17/16\n\
			endpoint [::1]:1234\n\
		}\n\
	}\n";

static union smsg smsg;

/*
 * Close a descriptor and point it to -1.
 */
void
xclose(int *d)
{
	if (d == NULL || *d < 0)
		abort();

	if (close(*d) == -1)
		logexit(1, "close");

	*d = -1;
}

static void
printusage(int d)
{
	dprintf(d, "usage: %s [-qv] [packets]\n", "testifn");
}

static void
createv6packet(uint8_t *buf, size_t bufsize, const struct in6_addr *src,
    const struct in6_addr *dst, size_t payloadsize)
{
	struct ip6_hdr *ip6hdr;

	if (bufsize < sizeof(*ip6hdr))
		abort();

	ip6hdr = (struct ip6_hdr *)buf;

	ip6hdr->ip6_vfc = IPV6_VERSION;
	ip6hdr->ip6_flow = htobe32(42);
	ip6hdr->ip6_plen = htobe16(payloadsize);
	ip6hdr->ip6_nxt = 0;
	ip6hdr->ip6_hlim = 1;
	memcpy(&ip6hdr->ip6_src, src, sizeof(*src));
	memcpy(&ip6hdr->ip6_dst, dst, sizeof(*dst));
}

static void
createv4packet(uint8_t *buf, size_t bufsize, const struct in_addr *src,
    const struct in_addr *dst, size_t payloadsize)
{
	struct ip *ip4hdr;

	assert(sizeof(*ip4hdr) == 20);

	if (bufsize < sizeof(*ip4hdr))
		abort();

	ip4hdr = (struct ip *)buf;

	ip4hdr->ip_v = 4;
	ip4hdr->ip_hl = 5;
	ip4hdr->ip_len = htobe16(20 + payloadsize);
	ip4hdr->ip_ttl = 1;

	memcpy(&ip4hdr->ip_src, src, sizeof(*src));
	memcpy(&ip4hdr->ip_dst, dst, sizeof(*dst));
}


/*
 * Return the number of bits between the start of an ip6 header and the
 * source host address.
 */
static size_t
src6hostoffset(size_t srcprefixlen)
{
	return offsetof(struct ip6_hdr, ip6_src) + srcprefixlen;
}

/*
 * Return the number of bits between the start of an ip4 header and the
 * source host address.
 */
static size_t
src4hostoffset(size_t srcprefixlen)
{
	return offsetof(struct ip, ip_src) + srcprefixlen;
}

/*
 * Return the number of bits between the start of an ip4 header and the
 * payload length (includes v4 header).
 */
static size_t
len4offset(void)
{
	return offsetof(struct ip, ip_len);
}

/*
 * Return the number of bits between the start of an ip6 header and the
 * payload length (does not include v6 header).
 */
static size_t
len6offset(void)
{
	return offsetof(struct ip6_hdr, ip6_plen);
}

/*
 * Return the number of bits between the start of an ip6 header and the
 * destination host address.
 */
static size_t
dst6hostoffset(size_t dstprefixlen)
{
	return offsetof(struct ip6_hdr, ip6_dst) + dstprefixlen;
}

/*
 * Return the number of bits between the start of an ip4 header and the
 * destination host address.
 */
static size_t
dst4hostoffset(size_t dstprefixlen)
{
	return offsetof(struct ip, ip_dst) + dstprefixlen;
}

/*
 * Create a packet with tunnel and ip header.
 *
 * Returns a pointer to the start of the ip header.
 */
static uint8_t *
createtunnelpacket(uint8_t *buf, size_t bufsize,
    const struct sockaddr_storage *src, const struct sockaddr_storage *dst,
    size_t payloadsize)
{
	struct in6_addr *srcia6, *dstia6;
	struct in_addr  *srcia4, *dstia4;
	char str[100];
	uint8_t *iphdr;

	if (bufsize < MINPACKETSIZE)
		abort();

	if (src->ss_family != dst->ss_family)
		abort();

	/* set tunnel header */
	*(uint32_t *)buf = htonl(dst->ss_family);

	iphdr = &buf[TUNHDRSIZ];

	switch (src->ss_family) {
	case AF_INET6:
		srcia6 = &((struct sockaddr_in6 *)src)->sin6_addr;
		dstia6 = &((struct sockaddr_in6 *)dst)->sin6_addr;

		lognoticex("src: %s", inet_ntop(AF_INET6, srcia6, str,
		    sizeof(str)));
		lognoticex("dst: %s", inet_ntop(AF_INET6, dstia6, str,
		    sizeof(str)));

		createv6packet(iphdr, bufsize - TUNHDRSIZ, srcia6, dstia6,
		    payloadsize);

		break;
	case AF_INET:
		srcia4 = &((struct sockaddr_in *)src)->sin_addr;
		dstia4 = &((struct sockaddr_in *)dst)->sin_addr;

		lognoticex("src: %s", inet_ntop(AF_INET, srcia4, str,
		    sizeof(str)));
		lognoticex("dst: %s", inet_ntop(AF_INET, dstia4, str,
		    sizeof(str)));

		createv4packet(iphdr, bufsize - TUNHDRSIZ, srcia4, dstia4,
		    payloadsize);

		break;
	}

	return iphdr;
}

/*
 * Send "nrpackets" packets from "src" to dst".
 */
static size_t
testsrcdst(int pitcherwithmast, size_t nrpackets,
    const struct sockaddr_storage *src, const struct sockaddr_storage *dst,
    int tund)
{
	struct timespec to;
	uint8_t buf[TUNHDRSIZ + MAXIPHDR + MAXPAYLOADSIZE], *iphdr, *randomness;
	size_t i, sent, lenoff, len;
	char c;

	if (nrpackets == 0)
		return 0;

	if (src->ss_family != dst->ss_family)
		return 0;

	switch (src->ss_family) {
	case AF_INET6:
		lenoff = len6offset();
		break;
	case AF_INET:
		lenoff = len4offset();
		break;
	}

	iphdr = createtunnelpacket(buf, sizeof(buf), src, dst, MINPAYLOADSIZE);

	/* wait 300 ms in case of ENOBUFS */
	to.tv_sec = 0;
	to.tv_nsec = 300000000;

	/*
	 * we need one byte per packet, a number between MINPACKETSIZE and
	 * MAXPACKETSIZE
	 */

	if ((randomness = malloc(nrpackets)) == NULL)
		logexit(1, "malloc");

	arc4random_buf(randomness, nrpackets);

	sent = 0;

	/* signal parent we're ready and wait for start signal */
	if (write(pitcherwithmast, &c, 1) != 1)
		logexit(1, "write ready error");
	if (read(pitcherwithmast, &c, 1) != 1)
		logexit(1, "read start error");

	for (i = 0; i < nrpackets; i++) {
		/*
		 * Ensure at least 20 bytes are sent so that we're comptible
		 * with ipv4 style headers that include the header in it's size.
		 */
		if (randomness[i] % MAXPAYLOADSIZE < 20) {
			len = randomness[i] % MAXPAYLOADSIZE + 20;
		} else {
			len = randomness[i] % MAXPAYLOADSIZE;
		}
		iphdr[lenoff] = htobe16(len);

		if (write(tund, buf, TUNHDRSIZ + len) == -1) {
			if (errno == ENOBUFS) {
				logwarn("sleep and retry packet %d", i);

				if (nanosleep(&to, NULL) == -1)
					logexit(1, "nanosleep");

				i--;
			} else {
				logwarn("write error packet %zu, tund %d", i,
				    tund);
			}
		} else {
			sent++;
		}
	}

	return sent;
}

/*
 * Send packets to and from random addressess within "prefix".
 */
static size_t
testwithinprefix(size_t nrpackets, const struct sockaddr_storage *prefix,
    size_t prefixlen, int tund)
{
	uint8_t buf[MINPACKETSIZE], *iphdr;
	uint64_t hostmask;
	size_t i, sent, suffixlen, srchostoff, dsthostoff, randomnesssize;
	int bpp; /* bytes per packet */
	char *randomness;

	if (nrpackets == 0)
		return 0;

	switch (prefix->ss_family) {
	case AF_INET6:
		if (prefixlen > 128)
			abort();

		if (prefixlen < 64)
			logexitx(1, "only prefix-lengths of at least 64 bits "
			    "are currently supported");

		suffixlen = 128 - prefixlen;
		srchostoff = src6hostoffset(prefixlen);
		dsthostoff = dst6hostoffset(prefixlen);

		break;
	case AF_INET:
		if (prefixlen > 32)
			abort();

		suffixlen = 32 - prefixlen;
		srchostoff = src4hostoffset(prefixlen);
		dsthostoff = dst4hostoffset(prefixlen);

		break;
	}

	assert(suffixlen <= 128);

	iphdr = createtunnelpacket(buf, sizeof(buf), prefix, prefix,
	    MINPAYLOADSIZE);

	/*
	 * Simply ceil the number of bytes needed per host address and multiply
	 * by two (one for source, one for dest).
	 */
	bpp = (suffixlen / 8 + 1) * 2;

	if (bpp == 0)
		logexitx(1, "fixed host addresses currently not supported");

	if (bpp && nrpackets > SIZE_MAX / bpp)
		return 0;

	/* add 8 byte trailer */
	randomnesssize = bpp * nrpackets + sizeof(uint64_t);

	if ((randomness = malloc(randomnesssize)) == NULL)
		logexit(1, "malloc");

	arc4random_buf(randomness, randomnesssize);

	hostmask = (size_t)-1 >> (64 - suffixlen);

	sent = 0;

	for (i = 0; i < nrpackets; i++) {
		iphdr[srchostoff] = *(uint64_t *)&randomness[i] % hostmask;
		iphdr[dsthostoff] = *(uint64_t *)&randomness[i + 1] % hostmask;

		if (write(tund, buf, sizeof(buf)) == -1) {
			logwarn("write error packet %zu, tund %d",
			    i, tund);
		} else {
			sent++;
		}
	}

	return sent;
}

static void
testhandlesig(int signo)
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
 * Receive and handle a message from an IFN.
 *
 * Respond with dummy messages on
 *   MSGWGINIT
 *   MSGWGRESP
 *   MSGREQWGINIT
 *
 * And send static session keys via MSGSESSKEYS
 *
 * Return 0 on success, -1 on error.
 */
static int
handleifnmsg(const struct testifn *testifn)
{
	struct msgwginit *mwi;
	struct msgwgresp *mwr;
	struct msgsesskeys msk;
	size_t msgsize;
	uint32_t peerid;
	unsigned char mtcode;

	msgsize = sizeof(msg);
        if (wire_recvpeeridmsg(testifn->cfgifn->enclwithifn, &peerid, &mtcode,
	    msg, &msgsize) == -1)
		return -1;

	switch (mtcode) {
	case MSGWGINIT:
		mwr = (struct msgwgresp *)msg;

		mwr->type = htole32(2);
		mwr->sender = htole32(testifn->sessid);
		mwr->receiver = htole32(testifn->peersessid);

		if (ws_mac(mwr->mac1, sizeof(mwr->mac1), mwr, MAC1OFFSETRESP,
		    testifn->peertestifn->cfgifn->mac1key) == -1)
			return -1;

		msk.sessid = testifn->sessid;
		msk.peersessid = testifn->peersessid;
		memcpy(&msk.sendkey, &testifn->sendkey, sizeof(msk.sendkey));
		memcpy(&msk.recvkey, &testifn->recvkey, sizeof(msk.recvkey));

		if (wire_sendpeeridmsg(testifn->cfgifn->enclwithifn, peerid,
		    MSGSESSKEYS, &msk, sizeof(msk)) == -1)
			return -1;

		if (wire_sendpeeridmsg(testifn->cfgifn->enclwithifn, peerid,
		    MSGWGRESP, mwr, sizeof(*mwr)) == -1)
			return -1;

		break;
	case MSGWGRESP:
		msk.sessid = testifn->sessid;
		msk.peersessid = testifn->peersessid;
		memcpy(&msk.sendkey, &testifn->sendkey, sizeof(msk.sendkey));
		memcpy(&msk.recvkey, &testifn->recvkey, sizeof(msk.recvkey));

		if (wire_sendpeeridmsg(testifn->cfgifn->enclwithifn, peerid,
		    MSGSESSKEYS, &msk, sizeof(msk)) == -1)
			return -1;

		break;
	case MSGREQWGINIT:
		mwi = (struct msgwginit *)msg;

		mwi->type = htole32(1);
		mwi->sender = htole32(testifn->sessid);

		if (ws_mac(mwi->mac1, sizeof(mwi->mac1), mwi, MAC1OFFSETINIT,
		    testifn->peertestifn->cfgifn->mac1key) == -1)
			return -1;

		if (wire_sendpeeridmsg(testifn->cfgifn->enclwithifn, peerid,
		    MSGWGINIT, mwi, sizeof(*mwi)) == -1)
			return -1;

		break;
	default:
		return -1;
	}

	return 0;
}

/*
 * Catcher acts as ENCLAVE and PROXY for all IFN processes and watches tunnel
 * descriptors.
 */
static void
runcatcher(int catcherwithmast, struct testifn *testifnv, size_t testifnvsize)
{
	struct sigaction sa;
	struct kevent *kev;
	size_t n, kevlen;
	int r2, queue;
	char c;

	/* print stats on SIGUSR1 */
	sa.sa_handler = testhandlesig;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		logexit(1, "sigaction");
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		logexit(1, "sigaction");

	if ((queue = kqueue()) == -1)
		logexit(1, "kqueue");

	if (SIZE_MAX / 3 < testifnvsize)
		logexitx(1, "overflow");

	kevlen = testifnvsize * 3;
	if ((kev = calloc(kevlen, sizeof(*kev))) == NULL)
		logexit(1, "calloc");

	for (n = 0; n < testifnvsize; n++) {
		EV_SET(&kev[n * 3 + 0], testifnv[n].cfgifn->proxwithifn, EVFILT_READ,
		    EV_ADD, 0, 0, NULL);
		EV_SET(&kev[n * 3 + 1], testifnv[n].cfgifn->enclwithifn, EVFILT_READ,
		    EV_ADD, 0, 0, NULL);
		EV_SET(&kev[n * 3 + 2], testifnv[n].mastwithtund, EVFILT_READ,
		    EV_ADD, 0, 0, NULL);
	}

	if (kevent(queue, kev, kevlen, NULL, 0, NULL) == -1)
		logexit(1, "kevent");

	/* signal parent we're ready and start catching without waiting */
	if (write(catcherwithmast, &c, 1) != 1)
		logexit(1, "write ready error");

	/*
	 * Simply read all messages on all tunnel descriptors, and communication
	 * with proxy and enclave.
	 */
	for (;;) {
		if (logstats) {
			logwarnx("packets received enclave %zu, proxy %zu, tun "
			    "%zu %zu bytes", recvencl, recvprox, recvtun,
			    recvtunsz);
			logstats = 0;
		}

		if (doterm)
			exit(0);

		if ((r2 = kevent(queue, NULL, 0, kev, kevlen, NULL)) == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				logexit(1, "kevent exit");
			}
		}

		while (r2--) {
			if (kev[r2].flags == EV_ERROR)
				logexit(1, "catcher pipe error");

			for (n = 0; n < testifnvsize; n++) {
				if ((int)kev[r2].ident ==
				    testifnv[n].mastwithtund) {
					recvtunsz += read(testifnv[n].mastwithtund,
					    msg, sizeof(msg));

					testifnv[n].recvtun++;
					recvtun++;
				} else if ((int)kev[r2].ident ==
				    testifnv[n].cfgifn->enclwithifn) {
					if (handleifnmsg(&testifnv[n]) == -1)
						logexitx(1, "handleifnmsg");

					testifnv[n].recvencl++;
					recvencl++;
				} else if ((int)kev[r2].ident ==
				    testifnv[n].cfgifn->proxwithifn) {
					if (read(testifnv[n].cfgifn->proxwithifn,
					    msg, sizeof(msg)) == -1)
						logexitx(1, "handle message "
						    "from ifn to proxy");

					testifnv[n].recvprox++;
					recvprox++;
				}
			}
		}
	}
}

/*
 * Derived from ifn.c ifn_init but without privilege dropping etc, since no
 * privileges are needed to begin with. Most importantly, no call to opentunnel.
 */
static void
testifn_init(int masterport, int tunneld)
{
	extern int tund;
	extern const EVP_AEAD *aead;
	struct sigaction sa;

	recvconfig(masterport);

	aead = EVP_aead_chacha20_poly1305();
	assert(EVP_AEAD_nonce_length(aead) == sizeof(nonce));
	assert(EVP_AEAD_max_tag_len(aead) == TAGLEN);

	tund = tunneld;

	/*
	 * Print statistics on SIGUSR1 and do a graceful exit on SIGTERM.
	 *
	 * Use the handler from ifn.c.
	 */
	sa.sa_handler = handlesig;
	sa.sa_flags = SA_RESTART;
	if (sigemptyset(&sa.sa_mask) == -1)
		logexit(1, "sigemptyset");
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		logexit(1, "sigaction SIGUSR1");
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		logexit(1, "sigaction SIGTERM");
}

/*
 * Test IFN throughput by sending packets through two IFN processes.
 *
 * Bootstrap the application:
 *   0. parse configuration
 *   1. setup communication ports and fork the IFN processes
 *   2. send config to each IFN
 *   3. run the tests by firing test packets at it from different processes
 */
int
main(int argc, char **argv)
{
	struct testifn *testifnv;
	chan tmpchan;
	size_t j, m, n, testifnvsize;
	socklen_t len;
	int ipc[2], stat, packets, stdopen;
	pid_t pid, pitcher, catcher, configpid;
	const char *errstr;
	char c, *logfacilitystr;

	while ((c = getopt(argc, argv, "hqv")) != -1) {
		switch(c) {
		case 'h':
			printusage(STDOUT_FILENO);
			exit(0);
		case 'q':
			verbose--;
			break;
		case 'v':
			verbose++;
			break;
		case '?':
			printusage(STDERR_FILENO);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	packets = DEFAULTPACKETS;
	if (argc > 0) {
		packets = strtonum(argv[0], 1, INT_MAX, &errstr);
		if (packets <= 0)
			logexit(1, "packets must be a number between 1 and %d: "
			    "%s", INT_MAX, *argv);

		argc--;
		argv++;
	}

	if (argc != 0) {
		printusage(STDERR_FILENO);
		exit(1);
	}

	setprogname("master");
	setproctitle(NULL);

	/* Can not pledge with profile */

	if (geteuid() == 0)
		logexitx(1, "must not run as the superuser");

	if (pipe(ipc) == -1)
		logexit(1, "pipe");

	/* pump the config to the parser */
	if ((configpid = fork()) == 0) {
		xclose(&ipc[0]);

		if (write(ipc[1], config, sizeof(config) - 1)
		    != sizeof(config) - 1)
			logexit(1, "write config error");
		xclose(&ipc[1]);
		exit(0);
	}

	/* read the config */
	xclose(&ipc[1]);
	xparseconfigfd(ipc[0], &cfgifnv, &cfgifnvsize, &guid, &ggid, &logfacilitystr);
	xclose(&ipc[0]);
	processconfig();

	if (waitpid(configpid, &stat, 0) == -1)
		logexit(1, "waitpid configpid");

	/*
	 * Make sure we are not missing any communication channels and that
	 * there is no descriptor leak.
	 */

	stdopen = isopenfd(STDIN_FILENO) + isopenfd(STDOUT_FILENO) +
	    isopenfd(STDERR_FILENO);

	assert(getdtablecount() == stdopen);

	/*
	 *   1. setup communication ports and fork the IFN processes
	 *
	 * One channel per interface + a channel with the master and with the
	 * enclave (which we all fulfill in this test setup).
	 */

	if ((testifnv = calloc(cfgifnvsize, sizeof(*testifnv))) == NULL)
		logexitx(1, "calloc");
	testifnvsize = cfgifnvsize;

	for (n = 0; n < cfgifnvsize; n++) {
		/*
		 * Open interface channels with master and catcher (that acts as
		 * enclave and ifn).
		 */

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1)
			logexit(1, "socketpair ifnmast %zu", n);

		cfgifnv[n]->mastwithifn = tmpchan[0];
		cfgifnv[n]->ifnwithmast = tmpchan[1];

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1)
			logexit(1, "socketpair ifnencl %zu", n);

		cfgifnv[n]->enclwithifn = tmpchan[0];
		cfgifnv[n]->ifnwithencl = tmpchan[1];

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1)
			logexit(1, "socketpair ifnencl %zu", n);

		cfgifnv[n]->proxwithifn = tmpchan[0];
		cfgifnv[n]->ifnwithprox = tmpchan[1];

		/* setup a fake tunnel device descriptor */
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1)
			logexit(1, "socketpair ifnmast %zu", n);

		testifnv[n].mastwithtund = tmpchan[0];
		testifnv[n].ifnwithtund = tmpchan[1];

		/* use a 2 MB buffer for the "tunnel" device */
		len = 1024 * 1024 * 2;

		if (setsockopt(testifnv[n].mastwithtund, SOL_SOCKET, SO_RCVBUF,
		    &len, sizeof(len)) == -1)
			logexit(1, "setsockopt");

		if (setsockopt(testifnv[n].ifnwithtund, SOL_SOCKET, SO_RCVBUF,
		    &len, sizeof(len)) == -1)
			logexit(1, "setsockopt");

		switch (testifnv[n].pid = fork()) {
		case -1:
			logexit(1, "fork %s", cfgifnv[n]->ifname);
		case 0:
			setprogname(cfgifnv[n]->ifname);
			setproctitle(NULL);

			/* gprof */
			if (mkdir(cfgifnv[n]->ifname, 0700) == -1 &&
			    errno != EEXIST)
				logexit(1, "mkdir %s", cfgifnv[n]->ifname);

			if (chdir(cfgifnv[n]->ifname) == -1)
				logexit(1, "chdir");

			for (m = 0; m <= n; m++) {
				xclose(&testifnv[m].mastwithtund);
				xclose(&cfgifnv[m]->mastwithifn);
				xclose(&cfgifnv[m]->enclwithifn);
				xclose(&cfgifnv[m]->proxwithifn);
			}

			assert(getdtablecount() == stdopen + 4);

			testifn_init(cfgifnv[n]->ifnwithmast,
			    testifnv[n].ifnwithtund);

			/* expect a v4 and a v6 socket per peer */
			if ((size_t)getdtablecount() != stdopen + 4 +
			    cfgifnv[n]->peerssize * 2)
				logexitx(1, "descriptor mismatch: %d",
				    getdtablecount());

			/* signal parent we're ready and start without waiting */
			if (write(cfgifnv[n]->ifnwithmast, &c, 1) != 1)
				logexit(1, "write ready error");

			ifn_serv();
			logexitx(1, "ifn[%d]: unexpected return", getpid());
		}

		/* parent */
		testifnv[n].cfgifn = cfgifnv[n];

		/* no xclose, keep descriptor number */
		if (close(testifnv[n].ifnwithtund) == -1)
			logexit(1, "close");
		if (close(testifnv[n].cfgifn->ifnwithmast) == -1)
			logexit(1, "close");
		if (close(testifnv[n].cfgifn->ifnwithencl) == -1)
			logexit(1, "close");
		if (close(testifnv[n].cfgifn->ifnwithprox) == -1)
			logexit(1, "close");

		assert(getdtablecount() == stdopen + (int)(n + 1) * 4);
	}

	/* setup symmetric keys between first and second interface */
	memset(&testifnv[0].sendkey, 5, sizeof(wskey));
	memset(&testifnv[0].recvkey, 7, sizeof(wskey));
	memset(&testifnv[1].sendkey, 7, sizeof(wskey));
	memset(&testifnv[1].recvkey, 5, sizeof(wskey));

	testifnv[0].sessid = 11;
	testifnv[0].peersessid = 13;
	testifnv[1].sessid = 13;
	testifnv[1].peersessid = 11;

	testifnv[0].peertestifn = &testifnv[1];
	testifnv[1].peertestifn = &testifnv[0];

	if (pipe(ipc) == -1)
		logexit(1, "pipe");

	/* fork catcher */
	switch (catcher = fork()) {
	case -1:
		logexit(1, "fork catcher");
	case 0:
		setprogname("catcher");
		setproctitle(NULL);

		runcatcher(ipc[1], testifnv, testifnvsize);
		logexit(1, "catcher done");
	}

	/*
	 *   2. send config to each IFN
	 */

	for (n = 0; n < cfgifnvsize; n++) {
		sendconfig_ifn(smsg, n);
		signal_eos(smsg, cfgifnv[n]->mastwithifn);
	}

	/*
	 *   3. fork a pitcher
	 *
	 * Spawn a process that sends packets to ifn2 via ifn1.
	 */

	switch (pitcher = fork()) {
	case -1:
		logexit(1, "fork");
	case 0:
		setprogname("pitcher");
		setproctitle(NULL);

		j = testsrcdst(ipc[1], packets, &cfgifnv[0]->ifaddrs[0]->addr,
		    &cfgifnv[1]->ifaddrs[0]->addr, testifnv[0].mastwithtund);
		logwarnx("testsrcdst, written %zu packets", j);
		exit(0);
	}

	/* Wait for ready signals from pitcher and catcher */
	for (n = 0; n < 2; n++) {
		if (read(ipc[0], &c, 1) != 1)
			logexit(1, "read ready error %zu", n);
	}

	/* Wait for ready signals from ifn processes. */
	for (n = 0; n < cfgifnvsize; n++) {
		if (read(cfgifnv[n]->mastwithifn, &c, 1) != 1)
			logexit(1, "read ifn %zu ready error", n);
	}

	logwarnx("pitcher, catcher and ifns ready, sending start signal to "
	    "pitcher");

	if (write(ipc[0], &c, 1) != 1)
		logexit(1, "write start error");

	/*
	 * The catcher acts like the enclave and proxy and simply accepts all
	 * packets from the IFN and prints info about it.
	 */

	/* Wait until the pitcher is done and then kill the catcher */

	if ((pid = waitpid(WAIT_ANY, &stat, 0)) == -1)
		logexit(1, "waitpid");

	if (WIFEXITED(stat)) {
		if (WEXITSTATUS(stat) != 0) {
			logwarnx("%d abnormal exit %d", pid,
			    WEXITSTATUS(stat));
		}
	} else if (WIFSIGNALED(stat)) {
		logwarnx("%d exit by signal %d %s", pid, WTERMSIG(stat),
		    strsignal(WTERMSIG(stat)));
	} else {
		logwarnx("%d exit cause unknown", pid);
	}

	/* print stats */
	sleep(1);
	for (n = 0; n < testifnvsize; n++) {
		if (kill(testifnv[n].pid, SIGUSR1) == -1)
			logexit(1, "stats ifn %d", n);
	}

	if (kill(catcher, SIGUSR1) == -1)
		logexit(1, "catcher stats");

	for (n = 0; n < testifnvsize; n++) {
		if (kill(testifnv[n].pid, SIGTERM) == -1)
			logexit(1, "kill SIGTERM ifn %d", n);
	}

	if (kill(catcher, SIGTERM) == -1)
		logexit(1, "kill catcher");

	exit(0);
}
