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
#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "blake2.h"
#include "tai64n.h"
#include "util.h"
#include "wireprot.h"
#include "wiresep.h"

#define TAGLEN 16
#define MINDATA  (1 << 21) /* malloc(3) and mmap(2) without ifn or peers */
#define MAXSTACK (1 << 15) /* 32 KB should be enough */

#ifdef DEBUG
#define MAXCORE (1024 * 1024 * 10)
#else
#define MAXCORE 0
#endif

void enclave_printinfo(FILE *);

extern int background, verbose;

/* handshake state */
struct hs {
	uint32_t sessid;
	uint32_t peersessid;
	wskey epriv;
	wskey epubi;
	wskey c;
	wshash h;
	struct peer *peer;
};

/*
 * pubkey	= Spubm'
 * pubkeyhash	= Hash(Hash(Hash(Construction) || Identifier) || Spubm')
 * mac1key	= Hash(Label-Mac1 || Spubm')
 * dhsecret	= DH(Sprivm, Spubm')
 */
struct peer {
	uint32_t id;
	wskey pubkey;
	wshash pubkeyhash;
	wskey mac1key;
	wskey dhsecret;
	wskey psk;
	struct ifn *ifn;
	struct hs *hs;
	uint8_t recvts[12]; /* last received authenticated timestamp */
};

/*
 * psk	= optional symmetric pre-shared secret, Q
 * pubkey	= Spubm
 * pubkeyhash	= Hash(Hash(Hash(Construction) || Identifier) || Spubm)
 * mac1key	= Hash(Label-Mac1 || Spubm)
 * cookiekey	= Hash(Label-Cookie || Spubm)
 */
struct ifn {
	uint32_t id;
	int port;
	char *ifname; /* null terminated name of the interface */
	size_t ifnamesize;
	wskey privkey;
	wskey pubkey;
	wshash pubkeyhash;
	wskey mac1key;
	wskey cookiekey;
	struct peer **peers;
	size_t peerssize;
};

static uid_t uid;
static gid_t gid;

static int kq, pport, doterm, logstats;

static uint8_t msg[MAXSCRATCH];

static struct ifn **ifnv;
static size_t ifnvsize;

static struct tai64n ts;
static struct iovec iov[3];
static wshash conshash, considhash, tmph;
static wskey k, t0, tau, tmpc;
static uint8_t tmpempty[0 + TAGLEN], tmpts[12 + TAGLEN],
    tmpstat[KEYLEN + TAGLEN];

/*
 * Copyright (c) 2019 Matt Dunwoodie
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Hmac(key, input) Hmac-Blake2s(key, input, 32), the ordinary BLAKE2s hash
 * function used in an HMAC construction, returning 32 bytes of output.
 */
static void
hmac(wskey out, const struct iovec *iovin, size_t iovinlen, const wskey key)
{
	 /* struct */ blake2s_state state;
	u_int8_t 	x_key[BLAKE2S_BLOCKBYTES] = {0};
	u_int8_t 	i_hash[BLAKE2S_OUTBYTES];
	int 		i;

	memcpy(x_key, key, BLAKE2S_KEYBYTES);

	for (i = 0; i < BLAKE2S_BLOCKBYTES; i++)
		x_key[i] ^= 0x36;

	blake2s_init(&state, BLAKE2S_OUTBYTES);
	blake2s_update(&state, x_key, BLAKE2S_BLOCKBYTES);
	for (size_t n = 0; n < iovinlen; n++)
		blake2s_update(&state, iovin[n].iov_base, iovin[n].iov_len);
	blake2s_final(&state, i_hash, BLAKE2S_OUTBYTES);

	for (i = 0; i < BLAKE2S_BLOCKBYTES; i++)
		x_key[i] ^= 0x5c ^ 0x36;

	blake2s_init(&state, BLAKE2S_OUTBYTES);
	blake2s_update(&state, x_key, BLAKE2S_BLOCKBYTES);
	blake2s_update(&state, i_hash, BLAKE2S_OUTBYTES);
	blake2s_final(&state, i_hash, BLAKE2S_OUTBYTES);

	memcpy(out, i_hash, BLAKE2S_OUTBYTES);
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
		logwarnx("unexpected signal %d %s", signo, strsignal(signo));
		break;
	}
}

/*
 * Derive "iovlen" new keys (HMAC).
 *
 * 0 < "iovlen" < 256
 *
 * Each "iov" entry must be at least KEYLEN bytes long
 *
 * Return 0 on success, -1 on failure.
 */
static int
kdfn(struct iovec *iovout, size_t iovoutlen, const wskey in, const wskey key)
{
	struct iovec iov[2];
	uint8_t t; /* must be one byte */

	if (iovoutlen < 1 || iovoutlen > 255)
		return -1;

	if (in) {
		iov[0].iov_base = (uint8_t *)in;
		iov[0].iov_len = KEYLEN;
		hmac(t0, iov, 1, key);
	} else {
		hmac(t0, NULL, 0, key);
	}

	t = 1;
	iov[0].iov_base = &t;
	iov[0].iov_len = 1;
	hmac(iovout[0].iov_base, iov, 1, t0);

	for (t = 2; t <= iovoutlen; t++) {
		iov[0].iov_base = iovout[t - 2].iov_base;
		iov[0].iov_len = iovout[t - 2].iov_len;
		iov[1].iov_base = &t;
		iov[1].iov_len = 1;
		hmac(iovout[t - 1].iov_base, iov, 2, t0);
	}

	explicit_bzero(t0, KEYLEN);
	return 0;
}

/*
 * Derive one new key (HMAC).
 *
 * Return 0 on success, -1 on failure.
 */
static int
kdf1(wskey out, const wskey in, const wskey key)
{
	struct iovec iov[1];

	iov[0].iov_base = out;
	iov[0].iov_len = KEYLEN;

	if (kdfn(iov, 1, in, key) == -1)
		return -1;

	return 0;
}

/*
 * Generate new transport data keys based on the chaining key.
 * Make a MSGSESSKEYS message, updates "msk".
 *
 * Return 0 on success, -1 on failure.
 */
static int
makemsgsesskeys(struct msgsesskeys *msk, struct hs *hs, int responder)
{
	if (msk == NULL || hs == 0)
		return -1;

	iov[0].iov_len = iov[1].iov_len = KEYLEN;

	if (responder) {
		iov[0].iov_base = msk->recvkey;
		iov[1].iov_base = msk->sendkey;
	} else {
		iov[0].iov_base = msk->sendkey;
		iov[1].iov_base = msk->recvkey;
	}

	if (kdfn(iov, 2, NULL, hs->c) == -1)
		return -1;

	msk->sessid = hs->sessid;
	msk->peersessid = hs->peersessid;

	return 0;
}

/*
 * Do the DH.
 *
 * Return 0 on success, -1 on failure.
 */
static int
dh(wskey sharedsecret, const wskey privkey, const wskey peerkey)
{
	if (X25519(sharedsecret, privkey, peerkey) == 0)
		return -1;

	return 0;
}

static void
inithash2(wshash out, const void *in1, size_t in1size, const void *in2,
    size_t in2size)
{
	iov[0].iov_base = (uint8_t *)in1;
	iov[0].iov_len = in1size;
	iov[1].iov_base = (uint8_t *)in2;
	iov[1].iov_len = in2size;
	ws_hash(out, iov, 2);
}

static void
appendhash(wshash h, const uint8_t *in, size_t insize)
{
	iov[0].iov_base = h;
	iov[0].iov_len = HASHLEN;
	iov[1].iov_base = (uint8_t *)in;
	iov[1].iov_len = insize;
	ws_hash(h, iov, 2);
}

/*
 * Find a peer by public key and interface. Return 1 if found and updates "p" to
 * point to it. 0 if not found and updates "p" to NULL.
 *
 * XXX log(n)
 */
static int
findifnpeerbypubkey(struct peer **p, const struct ifn *ifn, wskey pubkey)
{
	size_t n;

	*p = NULL;

	for (n = 0; n < ifn->peerssize; n++) {
		if (memcmp(ifn->peers[n]->pubkey, pubkey, sizeof(wskey)) == 0) {
			*p = ifn->peers[n];
			return 1;
		}
	}

	return 0;
}

/*
 * Find a peer by session id and interface. Return 1 if found and updates "p" to
 * point to it. 0 if not found and updates "p" to NULL.
 *
 * XXX log(n)
 */
static int
findifnpeerbysessid(struct peer **p, const struct ifn *ifn, uint32_t sessid)
{
	size_t n;

	*p = NULL;

	for (n = 0; n < ifn->peerssize; n++) {
		if (ifn->peers[n]->hs->sessid == sessid) {
			*p = ifn->peers[n];
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
findifnpeerbyid(struct peer **p, const struct ifn *ifn, uint32_t peerid)
{
	*p = NULL;

	if (peerid >= ifn->peerssize)
		return 0;

	*p = ifn->peers[peerid];
	return 1;
}

static void
prinths(FILE *fp, const struct hs *hs)
{
	fprintf(fp, "sessid %u\n", hs->sessid);
	fprintf(fp, "peersessid %u\n", hs->peersessid);
	fprintf(fp, "chaining key\n");
	hexdump(fp, hs->c, sizeof(hs->c), sizeof(hs->c));
	fprintf(fp, "hash\n");
	hexdump(fp, hs->h, sizeof(hs->h), sizeof(hs->h));
}

static void
printpeer(FILE *fp, const struct peer *peer)
{
	fprintf(fp, "id %u\n", peer->id);
	fprintf(fp, "pubkey\n");
	hexdump(fp, peer->pubkey, sizeof(peer->pubkey), sizeof(peer->pubkey));
	fprintf(fp, "pubkeyhash\n");
	hexdump(fp, peer->pubkeyhash, sizeof(peer->pubkeyhash),
	    sizeof(peer->pubkeyhash));
	fprintf(fp, "mac1key\n");
	hexdump(fp, peer->mac1key, sizeof(peer->mac1key),
	    sizeof(peer->mac1key));
	fprintf(fp, "recvts\n");
	hexdump(fp, peer->recvts, sizeof(peer->recvts), sizeof(peer->recvts));
}

/*
 * Authenticated encryption and decryption.
 *
 * Return 0 on success, -1 on failure. "outlen" is a value/result parameter.
 */
static int
aead(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen,
    const wskey key, const wshash h, int open)
{
	const EVP_AEAD *aead = EVP_aead_chacha20_poly1305();
	EVP_AEAD_CTX ctx;
	static const uint8_t nonce[12] = { 0 };

	assert(EVP_AEAD_nonce_length(aead) == sizeof(nonce));
	assert(EVP_AEAD_max_tag_len(aead) == TAGLEN);

	if (EVP_AEAD_CTX_init(&ctx, aead, key, KEYLEN, TAGLEN, NULL) == 0)
		return -1;

	if (open) {
		if (EVP_AEAD_CTX_open(&ctx, out, outlen, *outlen, nonce,
		    sizeof(nonce), in, inlen, h, HASHLEN) == 0)
			goto err;
	} else {
		if (EVP_AEAD_CTX_seal(&ctx, out, outlen, *outlen, nonce,
		    sizeof(nonce), in, inlen, h, HASHLEN) == 0)
			goto err;
	}

	EVP_AEAD_CTX_cleanup(&ctx);

	return 0;

err:
	EVP_AEAD_CTX_cleanup(&ctx);

	return -1;
}

/*
 * Upgrade handshake initialization state.
 *
 * The following fields are updated on success:
 *   peer->hs->c
 *   peer->hs->h
 *
 * In case we're the responder the peer is first searched for and mwi->stat and
 * mwi->timestamp are verified. The following extra fields are updated:
 *   peer is set if found
 *   peer->recvts
 *   peer->hs->epubi
 *
 * If we're the initiator ("peer" is not NULL) mwi->stat and mwi->timestamp are
 * set.
 *
 * Return 0 on success, -1 on failure.
 */
static int
upgradehsinit(struct ifn *ifn, struct msgwginit *mwi, struct peer **peer,
    int responder)
{
	struct hs *hs;
	struct peer *p;
	size_t n;

	if (ifn == NULL || mwi == NULL || peer == NULL)
		return -1;

	if (responder) {
		memcpy(tmph, ifn->pubkeyhash, HASHLEN);
	} else {
		memcpy(tmph, (*peer)->pubkeyhash, HASHLEN);
	}

	appendhash(tmph, mwi->ephemeral, sizeof(mwi->ephemeral));

	if (kdf1(tmpc, mwi->ephemeral, conshash) == -1)
		return -1;

	if (responder) {
		if (dh(k, ifn->privkey, mwi->ephemeral) == -1)
			return -1;
	} else {
		if (dh(k, (*peer)->hs->epriv, (*peer)->pubkey) == -1)
			return -1;
	}

	iov[0].iov_base = tmpc;
	iov[0].iov_len = KEYLEN;
	iov[1].iov_base = k;
	iov[1].iov_len = KEYLEN;
	if (kdfn(iov, 2, k, tmpc) == -1)
		return -1;

	if (responder) {
		n = sizeof(tmpstat);
		if (aead(tmpstat, &n, mwi->stat, sizeof(mwi->stat), k, tmph, 1)
		    == -1)
			return -1;

		if (!findifnpeerbypubkey(&p, ifn, tmpstat))
			return -1;
		/* extra verification on connected sockets */
		if (*peer && p != *peer)
			return -1;
		*peer = p;
	} else {
		n = sizeof(mwi->stat);
		if (aead(mwi->stat, &n, ifn->pubkey, sizeof(ifn->pubkey), k, tmph,
		    0) == -1)
			return -1;
	}

	hs = (*peer)->hs;

	appendhash(tmph, mwi->stat, sizeof(mwi->stat));

	iov[0].iov_base = tmpc;
	iov[0].iov_len = KEYLEN;
	iov[1].iov_base = k;
	iov[1].iov_len = KEYLEN;
	if (kdfn(iov, 2, (*peer)->dhsecret, tmpc) == -1)
		return -1;

	if (responder) {
		n = sizeof(tmpts);
		if (aead(tmpts, &n, mwi->timestamp, sizeof(mwi->timestamp), k,
		    tmph, 1))
			return -1;

		if (memcmp(tmpts, (*peer)->recvts, sizeof(tmpts)) <= 0) {
			logwarnx("%s hsinit replayed", __func__);
			return -1;
		}

		/* Successfully authenticated */
		memcpy((*peer)->recvts, tmpts, sizeof((*peer)->recvts));
		memcpy(hs->epubi, mwi->ephemeral, KEYLEN);
	} else {
		n = sizeof(mwi->timestamp);
		if (aead(mwi->timestamp, &n, mwi->timestamp,
		    sizeof(mwi->timestamp) - TAGLEN, k, tmph, 0))
			return -1;
	}

	appendhash(tmph, mwi->timestamp, sizeof(mwi->timestamp));

	memcpy(hs->c, tmpc, KEYLEN);
	memcpy(hs->h, tmph, HASHLEN);

	return 0;
}

/*
 * Create new handshake initialization state and a message.
 *
 * Return 0 on success if "hs" and "mwi" are initialized, -1 on failure.
 */
static int
createhsinit(struct peer *peer, struct msgwginit *mwi)
{
	struct hs *hs;

	if (peer == NULL || mwi == NULL)
		return -1;

	hs = peer->hs;

	hs->sessid = arc4random();

	mwi->type = htole32(1);
	mwi->sender = htole32(hs->sessid);

	X25519_keypair(mwi->ephemeral, hs->epriv);

	if (externaltai64n(mwi->timestamp, sizeof(mwi->timestamp) - TAGLEN,
	    nowtai64n(&ts)) == -1)
		return -1;

	if (upgradehsinit(peer->ifn, mwi, &peer, 0) == -1) {
		logwarnx("%s upgradehsinit", __func__);
		return -1;
	}

	/*
	 * Calculate MAC of message.
	 *
	 * msga = everything up to mac1 field, depends on structure of mwi.
	 *
	 * Mac1:
	 * 14. msg.mac1 := Mac(Hash(Label-Mac1 || Spubr), msga)
	 *   -> mac(msg.mac1, msga, Hash(Label-Mac1 || Spubr))
	 */

	if (ws_mac(mwi->mac1, sizeof(mwi->mac1), mwi, MAC1OFFSETINIT,
	    hs->peer->mac1key) == -1)
		return -1;

	/*
	 * Cookies are handled outside the enclave.
	 */

	memset(mwi->mac2, 0, sizeof(mwi->mac2));

	return 0;
}

/*
 * Upgrade handshake response state.
 *
 * In case we're the initiator the following fields are updated only if
 * successfully verified:
 *   hs->c
 *
 * If we're the responder these fields are always updated, including mwr->empty.
 *
 * Return 0 on success, -1 on failure.
 */
static int
upgradehsresp(struct hs *hs, struct msgwgresp *mwr, int responder)
{
	size_t n;

	if (kdf1(tmpc, mwr->ephemeral, hs->c) == -1)
		return -1;

	inithash2(tmph, hs->h, HASHLEN, mwr->ephemeral, KEYLEN);

	if (responder) {
		if (dh(k, hs->epriv, hs->epubi) == -1)
			return -1;
	} else {
		if (dh(k, hs->epriv, mwr->ephemeral) == -1)
			return -1;
	}

	if (kdf1(tmpc, k, tmpc) == -1)
		return -1;

	if (responder) {
		if (dh(k, hs->epriv, hs->peer->pubkey) == -1)
			return -1;
	} else {
		if (dh(k, hs->peer->ifn->privkey, mwr->ephemeral) == -1)
			return -1;
	}

	if (kdf1(tmpc, k, tmpc) == -1)
		return -1;

	iov[0].iov_base = tmpc;
	iov[0].iov_len = KEYLEN;
	iov[1].iov_base = tau;
	iov[1].iov_len = KEYLEN;
	iov[2].iov_base = k;
	iov[2].iov_len = KEYLEN;
	if (kdfn(iov, 3, hs->peer->psk, tmpc) == -1)
		return -1;

	appendhash(tmph, tau, KEYLEN);

	if (responder) {
		n = sizeof(mwr->empty);
		if (aead(mwr->empty, &n, NULL, 0, k, tmph, 0))
			return -1;
	} else {
		n = sizeof(tmpempty);
		if (aead(tmpempty, &n, mwr->empty, sizeof(mwr->empty), k, tmph,
		    1))
			return -1;
	}
	/* skip hashing msg.empty */

	/* Successfully authenticated */
	memcpy(hs->c, tmpc, KEYLEN);

	return 0;
}

/*
 * Create new handshake response state and a message.
 *
 * Return 0 on success if "hs" and "mwr" are initialized, -1 on failure.
 */
static int
createhsresp(struct peer *peer, struct msgwgresp *mwr,
    const struct msgwginit *mwi)
{
	struct hs *hs;

	if (peer == NULL || mwr == NULL || mwi == NULL)
		return -1;

	hs = peer->hs;

	/*
	 * Be careful to get everything from mwi before we write into mwr as it
	 * might point to the same memory.
	 */

	hs->sessid = arc4random();
	hs->peersessid = le32toh(mwi->sender);

	mwr->type = htole32(2);
	mwr->sender = htole32(hs->sessid);
	mwr->receiver = htole32(hs->peersessid);

	X25519_keypair(mwr->ephemeral, hs->epriv);

	if (upgradehsresp(hs, mwr, 1) == -1) {
		logwarnx("%s upgradehsresp", __func__);
		return -1;
	}

	if (ws_mac(mwr->mac1, sizeof(mwr->mac1), mwr, MAC1OFFSETRESP,
	    hs->peer->mac1key) == -1)
		return -1;

	memset(mwr->mac2, 0, sizeof(mwr->mac2));

	return 0;
}

/*
 * Handle an incoming MSGWGINIT, make sure it authenticates and determine or
 * verify the peer. Then write the appropriate response. Reads and writes to
 * "msg".
 *
 * Return 0 on success, -1 if data did not authenticate or another error
 * occurred.
 *
 * MSGWGINIT
 *   if data authenticates
 *      determine peer if it's not given, verify if it's given
 *      if fsn and lsn are not null send MSGCONNREQ
 *      send MSGSESSKEYS
 *      create and send MSGWGRESP
 */
static int
handlewginit(struct ifn *ifn, struct peer *peer,
    struct sockaddr_storage *fsn, struct sockaddr_storage *lsn)
{
	struct msgconnreq mcr;
	struct msgsesskeys msk;
	struct msgwgresp *mwr;
	struct msgwginit *mwi;

	mwi = (struct msgwginit *)msg;
	if (!ws_validmac(mwi->mac1, sizeof(mwi->mac1), mwi, MAC1OFFSETINIT,
	    ifn->mac1key)) {
		if (peer) {
			logwarnx("peer %u: packet with invalid mac received",
			    peer->id);
		} else {
			logwarnx("packet with invalid mac received");
		}
		return -1;
	}
	if (upgradehsinit(ifn, mwi, &peer, 1) == -1) {
		if (peer) {
			logwarnx("peer %u: unauthenticated initiation "
			    "received for %s: ", peer->id, ifn->ifname);
		} else {
			logwarnx("unauthenticated initiation received for %s",
			    ifn->ifname);
		}
		return -1;
	}

	/* Overwrite msg mwi with mwr */
	mwr = (struct msgwgresp *)msg;
	if (createhsresp(peer, mwr, mwi) == -1) {
		logwarnx("%s createhsresp", __func__);
		return -1;
	}

	if (fsn && lsn) {
		/* send MSGCONNREQ */
		if (makemsgconnreq(&mcr, fsn, lsn) == -1)
			logexitx(1, "%s makemsgconnreq", __func__);
		if (wire_sendpeeridmsg(ifn->port, peer->id, MSGCONNREQ, &mcr,
		    sizeof(mcr)) == -1) {
			logwarnx("%s error sending MSGCONNREQ to %s", __func__,
			    ifn->ifname);
			return -1;
		}
	}

	/* send MSGSESSKEYS to ifn */
	if (makemsgsesskeys(&msk, peer->hs, 1) == -1)
		logexitx(1, "%s makemsgsesskeys", __func__);

	if (wire_sendpeeridmsg(ifn->port, peer->id, MSGSESSKEYS, &msk,
	    sizeof(msk)) == -1) {
		logwarnx("%s error sending MSGSESSKEYS to %s", __func__,
		    ifn->ifname);
		return -1;
	}

	explicit_bzero(&msk, sizeof(msk));

	/* send MSGWGRESP to ifn */
	if (wire_sendpeeridmsg(ifn->port, peer->id, MSGWGRESP, mwr,
	    sizeof(*mwr)) == -1) {
		logwarnx("%s error sending MSGWGRESP to %s", __func__,
		    ifn->ifname);
		return -1;
	}

	return 0;
}

/*
 * Handle an incoming MSGWGRESP, make sure it authenticates and determine or
 * verify the peer. Then write the appropriate response. Reads and writes to
 * "msg".
 *
 * Return 0 on success, -1 if data did not authenticate or another error
 * occurred.
 *
 * MSGWGRESP
 *   if data authenticates
 *      determine peer if it's not given, verify if it's given
 *      if fsn and lsn are not null send MSGCONNREQ
 *      send MSGSESSKEYS
 *
 * Return 0 on success, -1 on error.
 */
static int
handlewgresp(struct ifn *ifn, struct peer *peer,
    struct sockaddr_storage *fsn, struct sockaddr_storage *lsn)
{
	struct msgconnreq mcr;
	struct msgsesskeys msk;
	struct msgwgresp *mwr;
	struct peer *p;

	mwr = (struct msgwgresp *)msg;
	if (!ws_validmac(mwr->mac1, sizeof(mwr->mac1), mwr, MAC1OFFSETRESP,
	    ifn->mac1key)) {
		logwarnx("%s invalid mac1 MSGWGRESP", __func__);
		return -1;
	}
	if (!findifnpeerbysessid(&p, ifn, mwr->receiver)) {
		logwarnx("%s findifnpeerbysessid", __func__);
		return -1;
	}
	/* verify the authenticated packet came in on the right socket */
	if (peer && peer->id != p->id) {
		logwarnx("%s authenticated packet received on wrong connected"
		    " socket", __func__);
		return -1;
	}
	peer = p;
	if (upgradehsresp(peer->hs, mwr, 0) == -1) {
		logwarnx("peer %u: unauthenticated response received",
		    peer->id);
		return -1;
	}

	peer->hs->peersessid = mwr->sender;

	if (fsn && lsn) {
		/* send MSGCONNREQ */
		if (makemsgconnreq(&mcr, fsn, lsn) == -1)
			logexitx(1, "%s makemsgconnreq", __func__);
		if (wire_sendpeeridmsg(ifn->port, peer->id, MSGCONNREQ, &mcr,
		    sizeof(mcr)) == -1) {
			logwarnx("%s error sending MSGCONNREQ to %s", __func__,
			    ifn->ifname);
			return -1;
		}
	}

	/* send MSGSESSKEYS to ifn */
	if (makemsgsesskeys(&msk, peer->hs, 0) == -1)
		logexitx(1, "%s makemsgsesskeys", __func__);

	if (wire_sendpeeridmsg(ifn->port, peer->id, MSGSESSKEYS, &msk,
	    sizeof(msk)) == -1) {
		logwarnx("%s error sending MSGSESSKEYS to %s", __func__,
		    ifn->ifname);
		return -1;
	}

	explicit_bzero(&msk, sizeof(msk));

	return 0;
}

/*
 * Receive and handle a message from an IFN.
 *
 * MSGWGINIT
 *   if data authenticates:
 *      create and send MSGWGRESP
 *      send MSGSESSKEYS
 * MSGWGRESP
 *   if data authenticates:
 *      send MSGSESSKEYS
 * MSGREQWGINIT
 *      create and send MSGWGINIT
 *
 * Return 0 on success, -1 on error.
 */
static int
handleifnmsg(const struct ifn *ifn)
{
	struct peer *peer;
	size_t msgsize;
	uint32_t peerid;
	unsigned char mtcode;

	msgsize = sizeof(msg);
	if (wire_recvpeeridmsg(ifn->port, &peerid, &mtcode, msg, &msgsize)
	    == -1) {
		logwarnx("wire_recvpeeridmsg %s", ifn->ifname);
		return -1;
	}

	if (!findifnpeerbyid(&peer, ifn, peerid)) {
		logwarnx("%s unknown peer id from ifn %s", __func__,
		    ifn->ifname);
		return -1;
	}

	switch (mtcode) {
	case MSGWGINIT:
		if (handlewginit(peer->ifn, peer, NULL, NULL) == -1)
			return -1;
		break;
	case MSGWGRESP:
		if (handlewgresp(peer->ifn, peer, NULL, NULL) == -1)
			return -1;
		break;
	case MSGREQWGINIT:
		if (createhsinit(peer, (struct msgwginit *)msg) == -1) {
			logwarnx("createhsinit");
			return -1;
		}

		if (wire_sendpeeridmsg(ifn->port, peerid, MSGWGINIT, msg,
		    sizeof(struct msgwginit)) == -1) {
			logwarnx("wire_sendpeeridmsg MSGWGINIT");
			return -1;
		}
		if (verbose > 0)
			lognoticex("sent MSGWGINIT to %s", ifn->ifname);
		break;
	default:
		logwarnx("wire_recvifnmsg unknown message from %s: %d",
		    ifn->ifname, mtcode);
		return -1;
	}

	return 0;
}

/*
 * Receive and handle one of the messages from the proxy.
 *
 * MSGWGINIT
 *   if data authenticates, determine the appropriate interface:
 *      send MSGCONNREQ
 *      send MSGSESSKEYS
 *      create and send MSGWGRESP
 * MSGWGRESP
 *   if data authenticates, determine the appropriate interface:
 *      send MSGCONNREQ
 *      send MSGSESSKEYS
 *
 * Return 0 on success, -1 on error.
 */
static int
handleproxymsg(void)
{
	struct sockaddr_storage fsn, lsn;
	struct ifn *ifn;
	size_t msgsize;
	uint32_t ifnid;
	unsigned char mtcode;

	msgsize = sizeof(msg);
	if (wire_recvproxymsg(pport, &ifnid, &lsn, &fsn, &mtcode, msg, &msgsize)
	    == -1) {
		logwarnx("%s wire_recvproxymsg", __func__);
		return -1;
	}

	if (ifnid > ifnvsize) {
		logwarnx("unknown interface id from proxy: %d", ifnid);
		return -1;
	}
	ifn = ifnv[ifnid];

	switch (mtcode) {
	case MSGWGINIT:
		if (handlewginit(ifn, NULL, &fsn, &lsn) == -1)
			return -1;
		break;
	case MSGWGRESP:
		if (handlewgresp(ifn, NULL, &fsn, &lsn) == -1) {
			logwarnx("%s handlewgresp", __func__);
			return -1;
		}
		break;
	default:
		logwarnx("wire_recvproxymsg unknown message from proxy: %d",
		    mtcode);
		return -1;
	}

	return 0;
}

/*
 * Setup read listeners for:
 *    proxy port
 *    each IFN port
 *
 * Handle events.
 *
 * Exit on error.
 */
void
enclave_serv(void)
{
	struct kevent *ev;
	size_t evsize, n;
	int nev, i;

	if ((kq = kqueue()) == -1)
		logexit(1, "kqueue");

	evsize = ifnvsize + 1;
	if ((ev = calloc(evsize, sizeof(*ev))) == NULL)
		logexit(1, "calloc ev");

	for (n = 0; n < ifnvsize; n++)
		EV_SET(&ev[n], ifnv[n]->port, EVFILT_READ, EV_ADD, 0, 0, NULL);

	EV_SET(&ev[ifnvsize], pport, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (kevent(kq, ev, evsize, NULL, 0, NULL) == -1)
		logexit(1, "kevent");

	for (;;) {
		if (logstats) {
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
			if ((int)ev[i].ident == pport) {
				if (ev[i].flags & EV_EOF) {
					if (verbose > -1)
						logwarnx("proxy EOF");
					if (close(pport) == -1)
						logexit(1, "close");
					break;
				}
				if (verbose > 1)
					loginfox("proxy readable");

				handleproxymsg();
				break;
			}

			/* XXX log(n) */
			for (n = 0; n < ifnvsize; n++) {
				if ((int)ev[i].ident == ifnv[n]->port) {
					if (ev[i].flags & EV_EOF) {
						if (verbose > -1)
							logwarnx("%s EOF",
							    ifnv[n]->ifname);
						if (close(ifnv[n]->port) == -1)
							logexit(1, "close");
						break;
					}
					if (verbose > 1)
						loginfox("%s readable",
						    ifnv[n]->ifname);
					handleifnmsg(ifnv[n]);
					break;
				}
			}
		}
	}
}

/*
 * Receive configuration from the master.
 *
 * SINIT
 * SIFN
 * SPEER
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
		struct seos eos;
	} smsg;
	struct peer *p;
	struct ifn *ifn;
	size_t n, m, msgsize;
	unsigned char mtcode;

	if (readhexnomem(conshash, HASHLEN, CONSHASH, strlen(CONSHASH)) == -1)
		abort();
	if (readhexnomem(considhash, HASHLEN, CONSIDHASH, strlen(CONSIDHASH))
	    == -1)
		abort();

	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
		logexitx(1, "wire_recvmsg SINIT %d", masterport);
	if (mtcode != SINIT)
		logexitx(1, "mtcode SINIT %d", mtcode);

	background = smsg.init.background;
	verbose = smsg.init.verbose;
	uid = smsg.init.uid;
	gid = smsg.init.gid;
	pport = smsg.init.proxport;
	ifnvsize = smsg.init.nifns;

	if ((ifnv = calloc(ifnvsize, sizeof(*ifnv))) == NULL)
		logexit(1, "calloc ifnv");

	for (n = 0; n < ifnvsize; n++) {
		msgsize = sizeof(smsg);
		if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
			logexitx(1, "wire_recvmsg SIFN");
		if (mtcode != SIFN)
			logexitx(1, "mtcode SIFN");

		if ((ifn = malloc(sizeof(*ifn))) == NULL)
			logexit(1, "malloc ifn");
		ifnv[n] = ifn;

		assert(n == smsg.ifn.ifnid);

		ifn->id = smsg.ifn.ifnid;
		ifn->ifname = strdup(smsg.ifn.ifname);
		ifn->port = smsg.ifn.ifnport;
		ifn->peerssize = smsg.ifn.npeers;

		if ((ifn->peers = calloc(ifn->peerssize,
		    sizeof(*ifn->peers))) == NULL)
			logexit(1, "calloc ifnv->peers");

		memcpy(ifn->privkey, smsg.ifn.privkey,
		    sizeof(smsg.ifn.privkey));
		memcpy(ifn->pubkey, smsg.ifn.pubkey, sizeof(smsg.ifn.pubkey));
		memcpy(ifn->pubkeyhash, smsg.ifn.pubkeyhash,
		    sizeof(smsg.ifn.pubkeyhash));
		memcpy(ifn->mac1key, smsg.ifn.mac1key,
		    sizeof(smsg.ifn.mac1key));
		memcpy(ifn->cookiekey, smsg.ifn.cookiekey,
		    sizeof(smsg.ifn.cookiekey));

		for (m = 0; m < ifn->peerssize; m++) {
			if ((p = malloc(sizeof(*p))) == NULL)
				logexit(1, "malloc peer");

			msgsize = sizeof(smsg);
			if (wire_recvmsg(masterport, &mtcode, &smsg,
			    &msgsize) == -1)
				logexitx(1, "wire_recvmsg SPEER");
			if (mtcode != SPEER)
				logexitx(1, "mtcode SPEER");

			assert(smsg.peer.ifnid == n);
			assert(smsg.peer.peerid == m);

			p->ifn = ifn;
			p->id = m;

			memcpy(p->psk, smsg.peer.psk, sizeof(smsg.peer.psk));
			memcpy(p->pubkey, smsg.peer.peerkey,
			    sizeof(smsg.peer.peerkey));
			memcpy(p->mac1key, smsg.peer.mac1key,
			    sizeof(smsg.peer.mac1key));

			memcpy(p->pubkeyhash, considhash, HASHLEN);
			appendhash(p->pubkeyhash, smsg.peer.peerkey, KEYLEN);

			dh(p->dhsecret, ifn->privkey, p->pubkey);

			if ((p->hs = malloc(sizeof(*p->hs))) == NULL)
				logexit(1, "malloc hs");

			memset(p->recvts, 0, sizeof(p->recvts));
			p->hs->peer = p;
			ifn->peers[m] = p;
		}
	}

	/* expect end of startup signal */
	msgsize = sizeof(smsg);
	if (wire_recvmsg(masterport, &mtcode, &smsg, &msgsize) == -1)
		logexitx(1, "wire_recvmsg SEOS");
	if (mtcode != SEOS)
		logexitx(1, "mtcode SEOS %d %d", masterport, mtcode);

	explicit_bzero(&smsg, sizeof(smsg));

	if (verbose > 1)
		loginfox("config received from %d", masterport);
}

/*
 * "masterport" descriptor to communicate with the master process and receive
 * the configuration.
 */
void
enclave_init(int masterport)
{
	struct sigaction sa;
	size_t heapneeded, n, nrpeers;
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
	if (!isopenfd(pport))
		logexitx(1, "pport %d", pport);

	for (n = 0; n < ifnvsize; n++) {
		if (!isopenfd(ifnv[n]->port))
			logexitx(1, "%s port not open, fd %d", ifnv[n]->ifname,
			    ifnv[n]->port);
	}

	if ((size_t)getdtablecount() != stdopen + 2 + ifnvsize)
		logexitx(1, "descriptor mismatch: %d", getdtablecount());

	/*
	 * Calculate the amount of dynamic memory we need.
	 *
	 * Unfortunately we cannot allocate everything upfront and then disable
	 * new allocations because EVP_AEAD_CTX_init(3) uses malloc.
	 */

	nrpeers = 0;
	for (n = 0; n < ifnvsize; n++)
		nrpeers += ifnv[n]->peerssize;

	if (nrpeers > MAXPEERS)
		logexit(1, "number of peers exceeds maximum %zu %zu", nrpeers,
		    MAXPEERS);

	heapneeded = MINDATA;
	heapneeded += nrpeers * sizeof(struct peer);
	heapneeded += nrpeers * 8;
	heapneeded += ifnvsize * sizeof(struct ifn);
	heapneeded += (ifnvsize + 1) * sizeof(struct kevent);

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

	if (pledge("stdio", "") == -1)
		logexit(1, "pledge");
}

void
enclave_printinfo(FILE *fp)
{
	struct ifn *ifn;
	size_t n, m;

	for (n = 0; n < ifnvsize; n++) {
		ifn = ifnv[n];
		fprintf(fp, "ifn %zu\n", n);
		fprintf(fp, "id %u\n", ifn->id);
		fprintf(fp, "port %d\n", ifn->port);
		fprintf(fp, "pubkey\n");
		hexdump(fp, ifn->pubkey, sizeof(ifn->pubkey),
		    sizeof(ifn->pubkey));
		fprintf(fp, "pubkeyhash\n");
		hexdump(fp, ifn->pubkeyhash, sizeof(ifn->pubkeyhash),
		    sizeof(ifn->pubkeyhash));
		fprintf(fp, "mac1key\n");
		hexdump(fp, ifn->mac1key, sizeof(ifn->mac1key),
		    sizeof(ifn->mac1key));
		fprintf(fp, "cookiekey\n");
		hexdump(fp, ifn->cookiekey, sizeof(ifn->cookiekey),
		    sizeof(ifn->cookiekey));

		for (m = 0; m < ifn->peerssize; m++) {
			printpeer(fp, ifn->peers[m]);
			prinths(fp, ifn->peers[m]->hs);
		}

	}
}
