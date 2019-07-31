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

#include <err.h>
#include <openssl/curve25519.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"

int
main(void)
{
	uint8_t privkey[X25519_KEY_LENGTH];
	uint8_t pubkey[X25519_KEY_LENGTH];
	char b64[46];

	if (pledge("stdio", "") == -1)
		err(1, "pledge");

	X25519_keypair(pubkey, privkey);

	if (base64_ntop(privkey, sizeof(privkey), b64, sizeof(b64)) != 44)
		errx(1, "b64_ntop");

	fprintf(stdout, "privkey\t%s\n", b64);

	if (base64_ntop(pubkey, sizeof(pubkey), b64, sizeof(b64)) != 44)
		errx(1, "b64_ntop");

	fprintf(stdout, "pubkey\t%s\n", b64);

	arc4random_buf(privkey, sizeof(privkey));

	if (base64_ntop(privkey, sizeof(privkey), b64, sizeof(b64)) != 44)
		errx(1, "b64_ntop");

	fprintf(stdout, "psk\t%s\n", b64);

	explicit_bzero(privkey, sizeof(privkey));
	explicit_bzero(pubkey, sizeof(pubkey));
	explicit_bzero(b64, sizeof(b64));

	return 0;
}
