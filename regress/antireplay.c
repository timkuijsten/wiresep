#include <assert.h>
#include <err.h>
#include <string.h>

#include "../antireplay.h"

void
testwithupdatejump(void)
{
	struct antireplay ar;
	uint64_t seq;

	memset(&ar, 0, sizeof(ar));

	seq = 10000;

	/* everything bigger than 0 is new */
	assert(antireplay_isnew(&ar, seq));
	assert(antireplay_isnew(&ar, seq - 1000));
	antireplay_update(&ar, seq);
	assert(!antireplay_isnew(&ar, seq));
	assert(!antireplay_isnew(&ar, seq - 1000));

	/* Check next, update and recheck */
	assert(antireplay_isnew(&ar, seq + 1));
	assert(antireplay_isnew(&ar, seq - MAXTOTALITEMS));
	assert(!antireplay_isnew(&ar, seq - MAXTOTALITEMS - 1));
	assert(antireplay_isnew(&ar, seq + 1 - MAXTOTALITEMS));
	assert(antireplay_update(&ar, seq + 1) == 0);
	assert(antireplay_isnew(&ar, seq + 1 - MAXTOTALITEMS));
	assert(!antireplay_isnew(&ar, seq + 1));
	assert(!antireplay_isnew(&ar, seq - MAXTOTALITEMS));
	assert(!antireplay_isnew(&ar, seq - MAXTOTALITEMS - 1));
	assert(antireplay_isnew(&ar, seq - MAXTOTALITEMS + 1));
}

void
testwithupdateseq(void)
{
	struct antireplay ar;
	uint64_t seq;

	memset(&ar, 0, sizeof(ar));

	seq = 1;

	for (seq = 1; seq < 1000000; seq++) {
		assert(antireplay_isnew(&ar, seq));
		antireplay_update(&ar, seq);
		assert(!antireplay_isnew(&ar, seq));
	}

	for (seq = 0; seq < 1000000; seq++)
		assert(!antireplay_isnew(&ar, seq));
}


void
testnoupdate(void)
{
	struct antireplay ar;
	size_t n;

	memset(&ar, 0, sizeof(ar));

	assert(antireplay_isnew(&ar, 0));

	for (n = 1; n < 100; n++)
		assert(antireplay_isnew(&ar, n));
}

int
main(void)
{
	testnoupdate();
	testwithupdateseq();
	testwithupdatejump();

	return 0;
}
