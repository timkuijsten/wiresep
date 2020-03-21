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
 * Inspired by RFC 6479
 */

#ifndef ANTIREPLAY_H
#define ANTIREPLAY_H

#include <stddef.h>
#include <stdint.h>

/* Use 6 if you're on 64 bit, or 5 if you're on 32 bit. */
#ifndef ANTIREPLAY_BITS_PER_SEQNUM
#define ANTIREPLAY_BITS_PER_SEQNUM	6
#endif

/* must be a power of two */
#ifndef ANTIREPLAY_NRBUCKETS
#define ANTIREPLAY_NRBUCKETS	8
#endif

/* The number of numbers a bucket can hold. Ideally the result should be word sized. */
#define MAXBUCKETITEMS	(1 << ANTIREPLAY_BITS_PER_SEQNUM)
#define TOTALBITS	(ANTIREPLAY_NRBUCKETS * MAXBUCKETITEMS)
#define SEQBUCKMASK	(ANTIREPLAY_NRBUCKETS - 1)
#define SEQBITMASK	(MAXBUCKETITEMS - 1)
#define MAXTOTALITEMS	(MAXBUCKETITEMS * ANTIREPLAY_NRBUCKETS - MAXBUCKETITEMS)

struct antireplay {
	uint64_t maxseqnum;
	int bitmap[TOTALBITS / 8];
};

/*
 * Check if "seqnum" is either beyond the current window, or within the current
 * window but not seen yet, according to the bitmap in "ar".
 *
 * Return 1 if "seqnum" is new, or 0 if "seqnum" is replayed or too old.
 */
int
antireplay_isnew(const struct antireplay *ar, uint64_t seqnum)
{
	int bit, bucket;

	/* Check if in current window. */
	if (seqnum > ar->maxseqnum) {
		return 1; /* beyond window */
	} else if ((seqnum + MAXTOTALITEMS) < ar->maxseqnum) {
		return 0; /* behind window */
	}

	bucket = (seqnum >> ANTIREPLAY_BITS_PER_SEQNUM) & SEQBUCKMASK;
	bit = seqnum & SEQBITMASK;

	if (ar->bitmap[bucket] & (1 << bit))
		return 0;	/* replayed */

	return 1;
}

/*
 * Make sure "seqnum" is set in "ar". Slide the window if needed.
 *
 * Return 0 on success, -1 on error.
 */
int
antireplay_update(struct antireplay *ar, uint64_t seqnum)
{
	int bit, bucket;
	size_t n, slide;

	if (!antireplay_isnew(ar, seqnum))
		return -1;

	/* slide the window if needed */
	if (seqnum > ar->maxseqnum) {
		/* current bucket */
		bucket = ar->maxseqnum >> ANTIREPLAY_BITS_PER_SEQNUM &
		    SEQBUCKMASK;
		/*
		 * Determine the number of buckets to slide. Start counting the
		 * number of items from the start of the bucket that currently
		 * holds maxseqnum and divide by the number of items per bucket.
		 */
		slide = (seqnum - (ar->maxseqnum -
		    (ar->maxseqnum & ANTIREPLAY_BITS_PER_SEQNUM)))
		    / MAXBUCKETITEMS;

		if (slide > ANTIREPLAY_NRBUCKETS)	/* big jump */
			slide = ANTIREPLAY_NRBUCKETS;

		/* erase next buckets */
		for (n = 0; n < slide; n++)
			ar->bitmap[(bucket + n + 1) & SEQBUCKMASK] = 0;

		ar->maxseqnum = seqnum;
	}

	/* update the bit for this seqnum */
	bucket = (seqnum >> ANTIREPLAY_BITS_PER_SEQNUM) & SEQBUCKMASK;
	bit = seqnum & SEQBITMASK;

	ar->bitmap[bucket] |= (1 << bit);

	return 0;
}

#endif /* ANTIREPLAY_H */
