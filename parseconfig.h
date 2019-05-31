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

#ifndef PARSECONFIG_H
#define PARSECONFIG_H

#include <sys/socket.h>

#include <unistd.h>

#include "wireprot.h"
#include "wiresep.h"

#define MAXIFNDESC 65
#define MAXPEERNAME 8

/* these are used by the other modules as well */
int background, verbose;

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
	int ifnwithmast;	/* Read/write descriptor the ifn process uses
				 * for communication with the master process.
				 */
	int mastwithifn;	/* Read/write descriptor the master process uses
				 * for communication with the ifn.
				 */
	int ifnwithencl;
	int enclwithifn;
	int ifnwithprox;
	int proxwithifn;
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

union smsg {
	struct sinit init;
	struct sifn ifn;
	struct speer peer;
	struct scidraddr cidraddr;
	struct seos eos;
};

/*
 * Create a list of interfaces.
 *
 * yyparse creates a tree of scfg entries.
 *
 * In a first pass determine all global settings and in a second pass
 * create interfaces with peer specific settings.
 *
 * Exit on error.
 */
void xparseconfigfile(const char *, struct ifn ***, size_t *, uid_t *, gid_t *,
char **);

/*
 * Load private keys of all interfaces, determine public key and mac1key.
 */
void processconfig(void);

#endif /* PARSECONFIG_H */
