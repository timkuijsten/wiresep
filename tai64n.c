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

#include "tai64n.h"

/*
 * Initialize "out" with the current time in TAI64N format.
 *
 * Return "out" on success, NULL on error with errno set.
 */
struct tai64n *
nowtai64n(struct tai64n *out)
{
	struct timeval now;

	if (gettimeofday(&now, NULL) == -1)
		return NULL;

	out->sec = TAI0 + now.tv_sec;
	out->nano = 1000 * now.tv_usec + 500;

	return out;
}

/*
 * Convert a TAI64N label to external format.
 *
 * Return 0 on success, -1 on error with "out" unmodified.
 */
int
externaltai64n(uint8_t *out, size_t outsize, const struct tai64n *in)
{
	uint64_t s;
	uint32_t n;

	if (in == NULL)
		return -1;

	if (outsize != 12)
		return -1;

	n = in->nano;

	out[11] = n & 255; n >>= 8;
	out[10] = n & 255; n >>= 8;
	out[9]  = n & 255; n >>= 8;
	out[8]  = n;

	s = in->sec;

	out[7] = s & 255; s >>= 8;
	out[6] = s & 255; s >>= 8;
	out[5] = s & 255; s >>= 8;
	out[4] = s & 255; s >>= 8;
	out[3] = s & 255; s >>= 8;
	out[2] = s & 255; s >>= 8;
	out[1] = s & 255; s >>= 8;
	out[0] = s;

	return 0;
}
