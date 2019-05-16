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

#include <stdlib.h>
#include <string.h>

#include "blake2.h"
#include "util.h"
#include "wiresep.h"

/*
 * Return 16 bytes of output.
 *
 * Return 0 on success, -1 on failure.
 */
int
ws_mac(void *out, size_t outlen, const void *in, size_t inlen,
    const wskey key)
{
	if (outlen != 16)
		return -1;

	if (blake2s(out, outlen, in, inlen, key, KEYLEN) == -1)
		return -1;

	return 0;
}

/*
 * Verify that "mac" is correct for "data" using "key".
 *
 * Return 1 on success, 0 otherwise.
 */
int
ws_validmac(const uint8_t *mac, size_t macsize, const void *data,
    size_t datasize, const wskey key)
{
	static uint8_t tmpmac[16];

	if (macsize != sizeof(tmpmac))
		return 0;

	if (ws_mac(tmpmac, sizeof(tmpmac), (uint8_t *)data, datasize, key) == -1)
		return 0;

	if (memcmp(tmpmac, mac, macsize) != 0)
		return 0;

	return 1;
}

/*
 * Return 32 bytes of output.
 *
 * Abort on error.
 */
void
ws_hash(wshash out, const struct iovec *iov, size_t iovlen)
{
	size_t n;

	blake2s_state S[1];

	if (blake2s_init(S, sizeof(wshash)) == -1)
		abort();

	for (n = 0; n < iovlen; n++)
		blake2s_update(S, iov[n].iov_base,
		    iov[n].iov_len);

	if (blake2s_final(S, out, sizeof(wshash)) == -1)
		abort();
}

/*
 * Print key.
 */
void
wspk(FILE *fp, const char *pre, wskey key)
{
	size_t n;

	if (pre)
		fprintf(fp, "%s\t", pre);
	for (n = 0; n < sizeof(wskey); n++)
		fprintf(fp, "%02x ", key[n]);
	fprintf(fp, "\n");
}

/*
 * Calculate the mac1 key.
 *
 * Hash(Label-Mac1 || Spubm)
 */
int
ws_calcmac1key(wskey mac1key, const wskey pubkey)
{
	struct iovec iov[2];

	iov[0].iov_base = LABELMAC1;
	iov[0].iov_len = strlen(LABELMAC1);
	iov[1].iov_base = (void *)pubkey;
	iov[1].iov_len = KEYLEN;

	ws_hash(mac1key, iov, 2);

	return 0;
}

/*
 * Calculate the hash of a public key.
 *
 * Hash(Hash(Hash(Construction) || Identifier) || Spubm)
 */
int
ws_calcpubkeyhash(wshash pubkeyhash, const wskey pubkey)
{
	struct iovec iov[2];

	if (readhexnomem(pubkeyhash, HASHLEN, CONSIDHASH, strlen(CONSIDHASH))
	    == -1)
		return -1;

	iov[0].iov_base = pubkeyhash;
	iov[0].iov_len = HASHLEN;
	iov[1].iov_base = (void *)pubkey;
	iov[1].iov_len = KEYLEN;

	ws_hash(pubkeyhash, iov, 2);

	return 0;
}
