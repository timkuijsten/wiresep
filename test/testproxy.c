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

#include <sys/socket.h>
#include <sys/wait.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "../util.h"
#include "../wireprot.h"

#include "../parseconfig.h"

/* inside job */
#include "../proxy.c"

#define RANDPERPACK 8      /* randomness needed per packet */

typedef int chan[2];

struct testsessmap {
	size_t peerid;
	uint32_t sessid;
};

struct testsockmap {
	struct sockaddr_storage ss;
	int s;
};

/* these are used by the other modules as well */
int background, verbose;

/* global settings */
static uid_t guid;
static gid_t ggid;
static struct testsessmap *testsessmapv;
static size_t testsessmapvsize;
static struct testsockmap *testsockmapv;
static size_t testsockmapvsize;

static struct cfgifn **cfgifnv;
static size_t cfgifnvsize;

static size_t recvencl, recvifn, recvifnsz;

static int logstats, doterm;

/*
 * Configure one interface with 8 peers.
 *
 * tun3 pubkey ErOyQKEbYQx/nFSiCFY+lDCe/3LfJ/v8UiHFpnvpo3Q=
 */
static const char config[] = "user 1109\n\
	interface tun3 {\n\
		ifaddr 172.16.0.1/24\n\
		listen [::1]:1234\n\
\n\
		privkey f5tK/SyL1G599SrSLPlul0Z4DFgqMglUrebRH7hSAZs=\n\
\n\
		# override global uid\n\
		user 1200\n\
\n\
		peer a {\n\
			pubkey AhyBpDfD7joIPPpjBW/g/Wdhiu3iVOzQhKodbsLqJ3A=\n\
			allowedips 172.16.0.1\n\
		}\n\
\n\
		peer b {\n\
			pubkey  d90+F6sGfKZvgVf6Vg70JGmUnIRKTtQbR/NA+JjHB1I=\n\
			allowedips 172.16.0.2\n\
		}\n\
\n\
		peer c {\n\
			pubkey  dMGNOV9XPaiGtJPxzg2+tIu3P0pBdL3tALIHXiNrgmE=\n\
			allowedips 172.16.0.3\n\
		}\n\
\n\
		peer d {\n\
			pubkey  U1PT7rH71FBEzCwCzzETj+KF+eAWRcVS9opuB2qp+ns=\n\
			allowedips 172.16.0.4\n\
		}\n\
\n\
		peer e {\n\
			pubkey  oaPrFtD7tORZO8A9GVgkkY+hVOZp+M9BUoaGWi6UyUY=\n\
			allowedips 172.16.0.5\n\
		}\n\
\n\
		peer f {\n\
			pubkey  j4svXiKhvliOU/JZagIN7PIi+qbblmm7XzrtI++8wRg=\n\
			allowedips 172.16.0.6\n\
		}\n\
\n\
		peer g {\n\
			pubkey  x803j71Bs6WvP3M4sf9dV8JzRl6ovKO4WPC/zyRAIVI=\n\
			allowedips 172.16.0.7\n\
		}\n\
\n\
		peer h {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.8\n\
		}\n\
\n\
		peer i {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.9\n\
		}\n\
\n\
		peer j {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.10\n\
		}\n\
\n\
		peer k {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.11\n\
		}\n\
\n\
		peer l {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.12\n\
		}\n\
\n\
		peer m {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.13\n\
		}\n\
\n\
		peer n {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.14\n\
		}\n\
\n\
		peer o {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.15\n\
		}\n\
\n\
		peer p {\n\
			pubkey  35MLAuA/BAg06YZ7JRlJHm8AWQd0JlUKl/om9KTs0Eg=\n\
			allowedips 172.16.0.16\n\
		}\n\
	}\n";

static union smsg smsg;

static void
printusage(FILE *fp)
{
	fprintf(fp, "usage: %s [-v] [packets]\n", getprogname());
}

/*
 * Notify the proxy of a new session id or invalidate an existing session id.
 *
 * enum sessidtype { SESSIDDESTROY, SESSIDTENT, SESSIDNEXT, SESSIDCURR };
 *
 * Return 0 on success, -1 on error.
 */
static int
notifyproxy(int mast2prox, uint32_t peerid, uint32_t sessid, enum sessidtype type)
{
	struct msgsessid msi;

	msi.sessid = sessid;
	msi.type = type;

	return wire_sendpeeridmsg(mast2prox, peerid, MSGSESSID, &msi, sizeof(msi));
}

/*
 * Create a session with the proxy or exit.
 */
static void
create_session(const struct cfgifn *ifn, uint32_t peerid, uint32_t sessid)
{
	if (notifyproxy(ifn->ifnwithprox, peerid, sessid, SESSIDTENT) == -1)
		logexit(1, "notifyproxy");

	if (notifyproxy(ifn->ifnwithprox, peerid, sessid, SESSIDCURR) == -1)
		logexit(1, "notifyproxy");
}

/*
 * Create one valid current session per peer and a map of connected sockets, one
 * per listenaddr of the proxy.
 *
 * Updates "testsessmapv", "testsessmapvsize", "testsockmapv" and "testsockmapvsize".
 */
static void
testsetup(const struct cfgifn *ifn)
{
	size_t i;

	if ((testsessmapv = calloc(ifn->peerssize, sizeof(*testsessmapv))) == NULL)
		logexit(1, "calloc");
	testsessmapvsize = ifn->peerssize;

	for (i = 0; i < ifn->peerssize; i++) {
		testsessmapv[i].peerid = i;
		testsessmapv[i].sessid = arc4random();
		create_session(ifn, testsessmapv[i].peerid, testsessmapv[i].sessid);
	}

	if ((testsockmapv = calloc(ifn->listenaddrssize, sizeof(*testsockmapv)))
	    == NULL)
		logexit(1, "calloc");
	testsockmapvsize = ifn->listenaddrssize;

	for (i = 0; i < ifn->listenaddrssize; i++) {
		memcpy(&testsockmapv[i].ss, ifn->listenaddrs[i],
		    sizeof(testsockmapv[i].ss));

		testsockmapv[i].s = socket(testsockmapv[i].ss.ss_family, SOCK_DGRAM, 0);
		if (testsockmapv[i].s == -1)
			logexit(1, "socket");

		if (connect(testsockmapv[i].s, (struct sockaddr *)&testsockmapv[i].ss,
		    testsockmapv[i].ss.ss_len) == -1)
			logexit(1, "connect");
	}
}

/*
 * Send invalid packets to a peer with a valid session.
 */
static size_t
testinvalidpackets(size_t nrpackets, int sock)
{
	struct msgwgdatahdr mwdh;
	ssize_t r;
	size_t i, sent;
	char *randomness;

	if ((randomness = calloc(nrpackets, RANDPERPACK)) == NULL)
		logexit(1, "malloc");

	arc4random_buf(randomness, nrpackets * RANDPERPACK);

	memset(&mwdh, 0, sizeof(mwdh));
	mwdh.type = htole32(4);

	sent = 0;
	for (i = 0; i < (nrpackets * RANDPERPACK); i += RANDPERPACK) {
		mwdh.counter = htole64(&randomness[i]);
		mwdh.receiver = htole32(&randomness[i + 1]);

		r = write(sock, &mwdh, sizeof(mwdh));
		if (r == -1) {
			logwarn("write error packet %zu, sock %d",
			    i / RANDPERPACK, sock);
		} else {
			sent++;
		}
	}

	return sent;
}

/*
 * Send packets to a peer with a valid session.
 */
static size_t
testvalidpackets(size_t nrpackets, uint32_t sessid, int sock)
{
	struct msgwgdatahdr mwdh;
	ssize_t r;
	size_t i, sent;

	memset(&mwdh, 0, sizeof(mwdh));
	mwdh.type = htole32(4);

	/* Then start sending packets to peers. */
	sent = 0;
	for (i = 0; i < nrpackets; i++) {
		mwdh.counter = htole64(i);
		mwdh.receiver = htole32(sessid);

		r = write(sock, &mwdh, sizeof(mwdh));
		if (r == -1) {
			logwarn("write error packet %zu, sock %d, sess %u", i,
			    sock, sessid);
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
 * Catcher fulfills the role of both the enclave and ifn.
 */
static void
runcatcher(int ipc[2], int ifnwithprox, int enclwithprox)
{
	struct sigaction sa;
	struct kevent kev[2];
	ssize_t r;
	size_t n;
	int r2, queue;
	uint8_t msg[1]; /* no need to retreive full packets */
	char c;

	/* print stats on SIGUSR1 */
	sa.sa_handler = testhandlesig;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		logexit(1, "sigaction");
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		logexit(1, "sigaction");

	/* set receive buffer to 2 MB */
	n = 1024 * 1024 * 2;
	if (setsockopt(ifnwithprox, SOL_SOCKET, SO_RCVBUF, &n,
	    sizeof(n)) == -1)
		logexit(1, "setsockopt");

	if ((queue = kqueue()) == -1)
		logexit(1, "kqueue");

	EV_SET(&kev[0], ifnwithprox, EVFILT_READ, EV_ADD, 0, 0, 0);
	EV_SET(&kev[1], enclwithprox, EVFILT_READ, EV_ADD, 0, 0, 0);

	if (kevent(queue, kev, 2, NULL, 0, NULL) == -1)
		logexit(1, "kevent");

	/* signal parent we're ready and start catching without waiting */
	close(ipc[0]);
	if (write(ipc[1], &c, 1) != 1)
		logexit(1, "write ready error");
	close(ipc[1]);

	/* simply read all messages from the proxy */
	for (;;) {
		if (logstats) {
			logwarnx("packets received enclave %zu, ifn "
			    "%zu %zu bytes", recvencl, recvifn, recvifnsz);
			logstats = 0;
		}

		if (doterm)
			exit(0);

		if ((r2 = kevent(queue, NULL, 0, kev, 2, NULL)) == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				logexit(1, "kevent exit");
			}
		}

		while (r2--) {
			if (kev[r2].flags == EV_ERROR)
				logexit(1, "catcher pipe error");

			if ((int)kev[r2].ident == ifnwithprox) {
				if ((r = read(kev[r2].ident, msg, sizeof(msg)))
				    < 0)
					logexit(1, "read msg from proxy");

				recvifn++;
				recvifnsz += r;
			} else if ((int)kev[r2].ident == enclwithprox) {
				if ((r = read(kev[r2].ident, msg, sizeof(msg)))
				    < 0)
					logexit(1, "read msg from proxy");

				recvencl++;
			}
		}
	}
}

/*
 * Mostly a copy of proxy_init from proxy.c.
 */
static void
testproxy_init(int masterport)
{
	struct sockaddr_storage *listenaddr;
	struct sigaction sa;
	size_t i, m, n;
	int s;
	socklen_t len;

	recvconfig(masterport);

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

			len = MAXRECVBUF;
			if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &len,
			    sizeof(len)) == -1)
				logexit(1, "setsockopt");

			if (len < MAXRECVBUF)
				logexitx(1, "could not maximize receive buffer:"
				    " %d", len);

			loginfox("socket receive buffer: %d", len);

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
}

/*
 * Test proxy throughput by sending packets through the proxy.
 *
 * Both valid as well as packets with an invalid session are tested.
 *
 * Bootstrap the application:
 *   0. read configuration
 *   1. determine public key, mac1key and cookie key of each interface
 *   2. setup communication ports and fork the PROXY
 *   3. send startup info
 *   4. run the tests to PROXY by firing test packets at it from different
 *      processes
 */
int
main(int argc, char **argv)
{
	/* descriptors for all communication channels */
	chan tmpchan;
	int mastwithprox, proxwithmast, enclwithprox, proxwithencl, stdopen;
	size_t i, j, n, pitchers;
	int ipc[2], stat, proxysock, packets;
	pid_t pid, proxy, catcher, configpid;
	const char *errstr;
	char c, *logfacilitystr;

	while ((c = getopt(argc, argv, "hv")) != -1)
		switch(c) {
		case 'h':
			printusage(stdout);
			exit(0);
		case 'v':
			verbose++;
			break;
		case '?':
			printusage(stderr);
			exit(1);
		}

	argc -= optind;
	argv += optind;

	packets = 1000;
	if (argc == 1) {
		packets = strtonum(*argv, 1, INT_MAX, &errstr);
		if (packets == 0)
			logexit(1, "packets must be a number between 1 and %d: %s",
			    INT_MAX, *argv);

		argc -= optind;
		argv += optind;
	}

	if (argc != 0) {
		printusage(stderr);
		exit(1);
	}

	setprogname("master");
	setproctitle(NULL);

	/* Can not pledge with profile */

	if (pipe(ipc) == -1)
		logexit(1, "pipe");

	/* pump the config to the parser */
	if ((configpid = fork()) == 0) {
		close(ipc[0]);

		if (write(ipc[1], config, sizeof(config) - 1)
		    != sizeof(config) - 1)
			logexit(1, "write config error");
		close(ipc[1]);
		exit(0);
	}

	/* read the config */
	close(ipc[1]);
	xparseconfigfd(ipc[0], &cfgifnv, &cfgifnvsize, &guid, &ggid, &logfacilitystr);
	close(ipc[0]);
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
	 *   2. setup communication ports and fork the PROXY
	 *
	 * One channel per interface + a channel with the master and with the
	 * enclave (which we all fulfill in this test setup).
	 */

	for (n = 0; n < cfgifnvsize; n++) {
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1)
			logexit(1, "socketpair %zu", n);

		cfgifnv[n]->proxwithifn = tmpchan[0];
		cfgifnv[n]->ifnwithprox = tmpchan[1];
	}

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1)
		logexit(1, "socketpair");

	proxwithmast = tmpchan[0];
	mastwithprox = tmpchan[1];

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, tmpchan) == -1)
		logexit(1, "socketpair");

	proxwithencl = tmpchan[0];
	enclwithprox = tmpchan[1];

	/* create a pipe for bi-directional signalling */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ipc) == -1)
		logexit(1, "socketpair ipc", n);

	/* fork proxy */
	switch (proxy = fork()) {
	case -1:
		logexit(1, "fork proxy");
	case 0:
		setprogname("proxy");
		setproctitle(NULL);

		/* gprof */
		if (chdir("/tmp") == -1)
			logexit(1, "chdir");

		for (n = 0; n < cfgifnvsize; n++)
			close(cfgifnv[n]->ifnwithprox);

		close(mastwithprox);
		close(enclwithprox);

		close(ipc[0]);

		if ((size_t)getdtablecount() != stdopen + 3 + cfgifnvsize)
			logexitx(1, "descriptor mismatch: %d", getdtablecount());

		testproxy_init(proxwithmast);

		/* signal parent we're ready and start without waiting */
		if (write(ipc[1], &c, 1) != 1)
			logexit(1, "write ready error");
		close(ipc[1]);

		proxy_serv();
		logexitx(1, "proxy_serv returned");
	}

	for (n = 0; n < cfgifnvsize; n++)
		close(cfgifnv[n]->proxwithifn);

	close(proxwithmast);
	close(proxwithencl);

	/* fork catcher */
	switch (catcher = fork()) {
	case -1:
		logexit(1, "fork catcher");
	case 0:
		setprogname("catcher");
		setproctitle(NULL);

		close(mastwithprox);

		/* only one ifn */
		runcatcher(ipc, cfgifnv[0]->ifnwithprox, enclwithprox);
		logexit(1, "catcher done");
	}

	close(enclwithprox);

	/*
	 *   3. send startup info
	 */

	sendconfig_proxy(smsg, mastwithprox, proxwithencl);
	signal_eos(smsg, mastwithprox);

	/*
	 *   4. run the tests to PROXY by firing test packets at it from different
	 *      processes
	 *
	 * Spawn two processes per session/socket, one that only sends valid packets and
	 * one that sends only invalid packets. Spawning two processes will introduce some
	 * randomeness and more closely mimic a production environment.
	 */

	/* XXX setup all interfaces in testsetup */
	for (n = 0; n < cfgifnvsize; n++)
		testsetup(cfgifnv[n]);

	pitchers = 0;
	proxysock = testsockmapv[0].s;
	for (i = 0; i < testsessmapvsize; i++) {
		switch (fork()) {
		case -1:
			logexit(1, "fork");
		case 0:
			setprogname("testvalidpackets");
			setproctitle(NULL);

			/* signal parent we're ready and wait for start signal */
			close(ipc[0]);
			if (write(ipc[1], &c, 1) != 1)
				logexit(1, "write ready error");
			if (read(ipc[1], &c, 1) != 1)
				logexit(1, "read start error");
			close(ipc[1]);

			j = testvalidpackets(packets, testsessmapv[i].sessid,
			    proxysock);
			logwarnx("testvalidpackets, written %zu packets (%u)", j,
			    testsessmapv[i].sessid);
			exit(0);
		}
		pitchers++;

		switch (fork()) {
		case -1:
			logexit(1, "fork");
		case 0:
			setprogname("testinvalidpackets");
			setproctitle(NULL);

			/* signal parent we're ready and wait for start signal */
			close(ipc[0]);
			if (write(ipc[1], &c, 1) != 1)
				logexit(1, "write ready error");
			if (read(ipc[1], &c, 1) != 1)
				logexit(1, "read start error");
			close(ipc[1]);

			j = testinvalidpackets(packets, proxysock);
			logwarnx("testinvalidpackets, written %zu packets", j);
			exit(0);
		}
		pitchers++;
	}

	/* Wait for ready signals from pitchers, catcher and proxy. */
	for (i = 0; i < (pitchers + 1 + 1); i++)
		if (read(ipc[0], &c, 1) != 1)
			logexit(1, "read ready error %zu", i);

	sleep(1);
	logwarnx("pitchers, catcher and proxy ready, sending start signal to "
	    "pitchers (%d)", pitchers);

	for (i = 0; i < pitchers; i++)
		if (write(ipc[0], &c, 1) != 1)
			logexit(1, "write start error %zu", i);

	/*
	 * The catcher acts like each ifn process and the enclave and simply
	 * accepts all packets from the PROXY and prints info about it.
	 */

	/* Simply wait until all pitchers are done and then kill the catcher */

	i = 0;
	while (i < pitchers) {
		if ((pid = waitpid(WAIT_ANY, &stat, 0)) == -1)
			logexit(1, "waitpid");

		if (pid != proxy && pid != catcher)
			i++;

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

		logwarnx("awaited %d, pitchers left %zu", pid, pitchers - i);
	}

	logwarnx("pitchers are done (%zu)", pitchers);

	/* print stats */
	sleep(1);
	if (kill(proxy, SIGUSR1) == -1)
		logexit(1, "proxy stats");
	if (kill(catcher, SIGUSR1) == -1)
		logexit(1, "catcher stats");

	if (kill(proxy, SIGTERM) == -1)
		logexit(1, "kill proxy");
	if (kill(catcher, SIGTERM) == -1)
		logexit(1, "kill catcher");

	exit(0);
}
