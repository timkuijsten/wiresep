/*
 * Copyright (c) 2018 Tim Kuijsten
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

#ifndef WIRE_H
#define WIRE_H

#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <stdio.h>

#include "wiresep.h"

enum sessidtype { SESSIDDESTROY, SESSIDTENT, SESSIDNEXT, SESSIDCURR };

union sockaddr_inet {
	struct {
		u_int8_t    len;
		sa_family_t family;
		in_port_t   port;
	};
	struct sockaddr_in6 src6;
	struct sockaddr_in  src4;
};

/* 1-WGINIT */
struct msgwginit {
	uint32_t type;
	uint32_t sender;
	uint8_t ephemeral[32];
	uint8_t stat[48];
	uint8_t timestamp[28];
	uint8_t mac1[16];
	uint8_t mac2[16];
};

/* 2-WGRESP */
struct msgwgresp {
	uint32_t type;
	uint32_t sender;
	uint32_t receiver;
	uint8_t ephemeral[32];
	uint8_t empty[16];
	uint8_t mac1[16];
	uint8_t mac2[16];
};

/* 3-WGCOOKIE */
struct msgwgcook {
	uint32_t type;
	uint32_t receiver;
	uint8_t nonce[24];
	uint8_t cookie[32];
};

/* 4-WGDATA header */
struct msgwgdatahdr {
	uint32_t type;
	uint32_t receiver;
	uint64_t counter;
};

/* 5-CONNREQ */
struct msgconnreq {
	union sockaddr_inet lsa;
	union sockaddr_inet fsa;
};

/* SESSID */
struct msgsessid {
	uint32_t sessid;
	enum sessidtype type;
};

/* 8-SESSKEYS */
struct msgsesskeys {
	uint32_t sessid;
	uint32_t peersessid;
	wskey sendkey;
	wskey recvkey;
};

/* 9-REQWGINIT */
struct msgreqwginit {
	char i;
};

/*
 * Startup Messages.
 */

/* SINIT */
struct sinit {
	int background;
	int verbose;
	uid_t uid;
	gid_t gid;
	int enclport;
	int proxport;
	uint32_t nifns;
};

/* SIFN */
struct sifn {
	uint32_t ifnid;
	int ifnport;
	char ifname[8];
	char ifdesc[65];
	wskey privkey;
	wskey pubkey;
	wskey pubkeyhash;
	wskey mac1key;
	wskey cookiekey;
	size_t nifaddrs;
	size_t npeers;
	size_t laddr6count;
	size_t laddr4count;
};

/* SPEER */
struct speer {
	uint32_t ifnid;
	uint32_t peerid;
	char name[9];
	union sockaddr_inet fsa;
	wskey psk;
	wskey peerkey; /* XXX s/pubkey/ */
	wskey mac1key;
	size_t nallowedips;
};

/* SCIDRADDR */
struct scidraddr {
	uint32_t ifnid;
	uint32_t peerid;
	union sockaddr_inet addr;
	size_t prefixlen;
};

/* SEOS */
struct seos {
	char i;
};

#define MSGNONE	0
#define MSGWGINIT	1
#define MSGWGRESP	2
#define MSGWGCOOKIE	3
#define MSGWGDATA	4
#define MSGCONNREQ	5
#define MSGSESSID 	6
#define MSGSESSKEYS	7
#define MSGREQWGINIT	8
#define MSGCONNSTAT	9
#define SINIT	10
#define SIFN	11
#define SPEER	12
#define SCIDRADDR	13
#define SEOS 14

#define MTNCODES 15

struct msgtype {
	size_t size;
	char varsize;	/*
			 * Boolean, if true than msgtype.size indicates minimum
			 * required length.
			 */
};

struct msgtype msgtypes[MTNCODES];

void printmsgwginit(FILE *, const struct msgwginit *);
void printmsgwgresp(FILE *, const struct msgwgresp *);

int wire_recvmsg(int port, unsigned char *mtcode, void *msg, size_t *msgsize);
int wire_sendmsg(int port, unsigned char mtcode, const void *msg, size_t msgsize);
int wire_proxysendmsg(int port, uint32_t ifnid,
    const union sockaddr_inet *lsa, const union sockaddr_inet *fsa,
    unsigned char mtcode, const void *msg, size_t msgsize);
int wire_recvpeeridmsg(int port, uint32_t *peerid, unsigned char *mtcode,
    void *msg, size_t *msgsize);
int wire_recvproxymsg(int port, uint32_t *ifnid, union sockaddr_inet *fsa,
    union sockaddr_inet *lsa, unsigned char *mtcode, void *msg, size_t *msgsize);

/* Send a message with a peerid. Return 0 on success, -1 */
int wire_sendpeeridmsg(int port, uint32_t peerid, unsigned char mtcode,
    const void *msg, size_t msgsize);

/* Make a 5-CONNREQ message, updates "mcr".
 * Return 0 on success, -1 on failure. */
int makemsgconnreq(struct msgconnreq *mcr, const union sockaddr_inet *fsa,
    const union sockaddr_inet *lsa);

/* Make a 9-REQWGINIT message, updates "mri".
 * Return 0 on success, -1 on failure. */
int makemsgreqwginit(struct msgreqwginit *mri);

#endif /* WIRE_H */
