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

#ifndef WIRESEP_H
#define WIRESEP_H

#include <sys/uio.h>

#include <stdio.h>

#define KEYLEN 32
#define HASHLEN 32
#define MAXSCRATCH 71680 /* 70 KB */

/* hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s") */
#define CONSHASH "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"

/* hash(hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s") + "WireGuard v1 zx2c4 Jason@zx2c4.com") */
#define CONSIDHASH "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"

#define LABELMAC1 "mac1----"
#define LABELCOOKIE "cookie--"

#define MAC1OFFSETINIT (1 + 3 + 4 + 32 + 48 + 28)
#define MAC1OFFSETRESP (1 + 3 + 4 + 4 + 32 + 16)

typedef uint8_t wskey[KEYLEN];
typedef uint8_t wshash[HASHLEN];

struct keypair {
	wskey privkey;
	wskey pubkey;
};

int ws_mac(void *, size_t, const void *, size_t, const wskey);
int ws_validmac(const uint8_t *, size_t, const void *, size_t, const wskey);
int ws_aead(uint8_t *, size_t *, const uint8_t *, size_t, const wskey,
    uint64_t, const uint8_t *, size_t, int);
void ws_hash(wshash, const struct iovec *, size_t);
void wspk(FILE *, const char *, wskey);
int ws_calcmac1key(wskey, const wskey);
int ws_calcpubkeyhash(wshash, const wskey);

#endif /* WIRESEP_H */
