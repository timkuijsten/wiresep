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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "wireprot.h"

/*
 * Maximum message size excluding the message
 * type code is 200 KB.
 */
#define MAXMSGSIZEP1 (204800 + 1)

struct msgtype msgtypes[MTNCODES] = {
	{ 0,	0 },
	{ sizeof(struct msgwginit),	0 },
	{ sizeof(struct msgwgresp),	0 },
	{ sizeof(struct msgwgcook),	0 },
	{ sizeof(struct msgwgdatahdr),	1 },
	{ sizeof(struct msgconnreq),	0 },
	{ sizeof(struct msgsessid),	0 },
	{ sizeof(struct msgsesskeys),	0 },
	{ sizeof(struct msgreqwginit),	0 },
	{ sizeof(struct sockaddr_storage),	0 },
	{ sizeof(struct sinit),	0 },
	{ sizeof(struct sifn),	0 },
	{ sizeof(struct speer),	0 },
	{ sizeof(struct scidraddr),	0 },
	{ sizeof(struct seos),	0 },
};

void
printmsgwginit(FILE *fp, const struct msgwginit *mwi)
{
	fprintf(fp, "type %u\n", le32toh(mwi->type));
	fprintf(fp, "sender %u\n", le32toh(mwi->sender));
	fprintf(fp, "ephemeral\n");
	hexdump(fp, mwi->ephemeral, sizeof(mwi->ephemeral), sizeof(mwi->ephemeral));
	fprintf(fp, "stat\n");
	hexdump(fp, mwi->stat, sizeof(mwi->stat), sizeof(mwi->stat));
	fprintf(fp, "timestamp\n");
	hexdump(fp, mwi->timestamp, sizeof(mwi->timestamp), sizeof(mwi->timestamp));
	fprintf(fp, "mac1\n");
	hexdump(fp, mwi->mac1, sizeof(mwi->mac1), sizeof(mwi->mac1));
	fprintf(fp, "mac2\n");
	hexdump(fp, mwi->mac2, sizeof(mwi->mac2), sizeof(mwi->mac2));
}

void
printmsgwgresp(FILE *fp, const struct msgwgresp *mwr)
{
	fprintf(fp, "type %u\n", le32toh(mwr->type));
	fprintf(fp, "sender %u\n", le32toh(mwr->sender));
	fprintf(fp, "receiver %u\n", le32toh(mwr->receiver));
	fprintf(fp, "ephemeral\n");
	hexdump(fp, mwr->ephemeral, sizeof(mwr->ephemeral), sizeof(mwr->ephemeral));
	fprintf(fp, "empty\n");
	hexdump(fp, mwr->empty, sizeof(mwr->empty), sizeof(mwr->empty));
	fprintf(fp, "mac1\n");
	hexdump(fp, mwr->mac1, sizeof(mwr->mac1), sizeof(mwr->mac1));
	fprintf(fp, "mac2\n");
	hexdump(fp, mwr->mac2, sizeof(mwr->mac2), sizeof(mwr->mac2));
}

/*
 * Read a message from a port.
 *
 * "mtcode", "msg" and "msgsize" are all value/result parameters.
 *
 * Return 0 on success, -1 on error.
 */
int
wire_recvmsg(int port, unsigned char *mtcode, void *msg, size_t *msgsize)
{
	struct iovec iov[3];
	struct msgtype *mt;
	ssize_t r;
	size_t iovlen;
	char overread;

	if (*msgsize >= MAXMSGSIZEP1)
		return -1;

	iovlen = 0;
	iov[iovlen].iov_base = mtcode;
	iov[iovlen].iov_len = sizeof(*mtcode);
	iovlen++;
	iov[iovlen].iov_base = (void *)msg;
	iov[iovlen].iov_len = *msgsize;
	iovlen++;
	iov[iovlen].iov_base = (void *)&overread;
	iov[iovlen].iov_len = 1;
	iovlen++;

again:
	r = readv(port, iov, iovlen);
	if (r <= 0) {
		if (r == -1 && errno == EINTR)
			goto again;

		return -1;
	}

	/*
	 * XXX make sure readv(2) on AF_UNIX SOCK_DGRAM never returns partially
	 * read datagrams.
	 */

	if ((size_t)r < sizeof(*mtcode))
		return -1;

	*msgsize = r - sizeof(*mtcode);

	if (*mtcode >= MTNCODES)
		return -1;

	mt = &msgtypes[*mtcode];
	if (mt->varsize) {
		/* size is a minimum on variable sized messages */
		if (*msgsize < mt->size)
			return -1;

		/* check overread */
		while (iovlen--)
			r -= iov[iovlen].iov_len;
		if (r >= 0)
			return -1;
	} else {
		if (*msgsize != mt->size)
			return -1;
		/* implicit overread check */
	}

	return 0;
}

/*
 * Send a message to a port.
 *
 * Return 0 on success, -1 on error.
 */
int
wire_sendmsg(int port, unsigned char mtcode, const void *msg, size_t msgsize)
{
	struct iovec iov[2];
	struct msgtype *mt;
	ssize_t r;
	size_t iovlen;

	if (mtcode >= MTNCODES)
		return -1;

	if (msgsize >= MAXMSGSIZEP1)
		return -1;

	mt = &msgtypes[mtcode];

	if (mt->varsize) {
		/* size is a minimum on variable sized messages */
		if (msgsize < mt->size)
			return -1;
	} else
		if (msgsize != mt->size)
			return -1;

	iovlen = 0;
	iov[iovlen].iov_base = &mtcode;
	iov[iovlen].iov_len = sizeof(mtcode);
	iovlen++;
	iov[iovlen].iov_base = (void *)msg;
	iov[iovlen].iov_len = msgsize;
	iovlen++;

again:
	r = writev(port, iov, iovlen);
	if (r <= 0) {
		if (r == -1 && errno == EINTR)
			goto again;

		return -1;
	}

	/*
	 * XXX make sure writev(2) on AF_UNIX SOCK_DGRAM never returns partially
	 * written datagrams.
	 * For now, make sure all bytes were written.
	 */
	while (iovlen--)
		r -= iov[iovlen].iov_len;
	if (r != 0)
		return -1;

	return 0;
}

/*
 * Send a message with a peerid.
 *
 * Return 0 on success, -1 on error.
 */
int
wire_sendpeeridmsg(int port, uint32_t peerid, unsigned char mtcode,
    const void *msg, size_t msgsize)
{
	struct iovec iov[3];
	struct msgtype *mt;
	ssize_t r;
	size_t iovlen;

	if (mtcode >= MTNCODES)
		return -1;

	if (msgsize >= MAXMSGSIZEP1)
		return -1;

	mt = &msgtypes[mtcode];

	if (msgsize != mt->size)
		return -1;

	iovlen = 0;
	iov[iovlen].iov_base = &peerid;
	iov[iovlen].iov_len = sizeof(peerid);
	iovlen++;
	iov[iovlen].iov_base = &mtcode;
	iov[iovlen].iov_len = sizeof(mtcode);
	iovlen++;
	iov[iovlen].iov_base = (void *)msg;
	iov[iovlen].iov_len = msgsize;
	iovlen++;

again:
	r = writev(port, iov, iovlen);
	if (r <= 0) {
		if (r == -1 && errno == EINTR)
			goto again;

		return -1;
	}

	if ((size_t)r < sizeof(peerid) + sizeof(mtcode))
		return -1;

	if ((size_t)r - sizeof(peerid) - sizeof(mtcode) != mt->size)
		return -1;

	return 0;
}

/*
 * Read a message that is prefixed with a peer id. All messages between the
 * enclave and the interface processes must be prefixed with a peer id. Each
 * message type has a fixed length.
 *
 * "peerid", "mtcode", "msg" and "msgsize" are all value/result parameters.
 *
 * Return 0 on success, -1 on error.
 */
int
wire_recvpeeridmsg(int port, uint32_t *peerid, unsigned char *mtcode, void *msg,
    size_t *msgsize)
{
	struct iovec iov[3];
	ssize_t r;
	size_t iovlen;

	iovlen = 0;
	iov[iovlen].iov_base = peerid;
	iov[iovlen].iov_len = sizeof(*peerid);
	iovlen++;
	iov[iovlen].iov_base = mtcode;
	iov[iovlen].iov_len = sizeof(*mtcode);
	iovlen++;
	iov[iovlen].iov_base = msg;
	iov[iovlen].iov_len = *msgsize;
	iovlen++;

again:
	r = readv(port, iov, iovlen);
	if (r <= 0) {
		if (r == -1 && errno == EINTR)
			goto again;

		return -1;
	}

	if ((size_t)r < sizeof(*peerid) + sizeof(*mtcode))
		return -1;

	if (*mtcode >= MTNCODES)
		return -1;

	*msgsize = r - sizeof(*peerid) - sizeof(*mtcode);

	if (*msgsize != msgtypes[*mtcode].size)
		return -1;

	if (*msgsize >= MAXMSGSIZEP1)
		return -1;

	return 0;
}

/*
 * Send a proxy type message. These messages are prefixed with an interface id,
 * a local socket address and a foreign socket address.
 *
 * Return 0 on success, -1 on error.
 */
int
wire_proxysendmsg(int port, uint32_t ifnid, const struct sockaddr_storage *lsa,
    const struct sockaddr_storage *fsa, unsigned char mtcode, const void *msg,
    size_t msgsize)
{
	struct iovec iov[5];
	struct msgtype *mt;
	ssize_t r;
	size_t iovlen;

	if (mtcode >= MTNCODES)
		return -1;

	if (msgsize >= MAXMSGSIZEP1)
		return -1;

	mt = &msgtypes[mtcode];

	if (mt->varsize) {
		/* size is a minimum on variable sized messages */
		if (msgsize < mt->size)
			return -1;
	} else
		if (msgsize != mt->size)
			return -1;

	iovlen = 0;
	iov[iovlen].iov_base = &ifnid;
	iov[iovlen].iov_len = sizeof(ifnid);
	iovlen++;
	iov[iovlen].iov_base = (void *)lsa;
	iov[iovlen].iov_len = sizeof(*lsa);
	iovlen++;
	iov[iovlen].iov_base = (void *)fsa;
	iov[iovlen].iov_len = sizeof(*fsa);
	iovlen++;
	iov[iovlen].iov_base = &mtcode;
	iov[iovlen].iov_len = sizeof(mtcode);
	iovlen++;
	iov[iovlen].iov_base = (void *)msg;
	iov[iovlen].iov_len = msgsize;
	iovlen++;

again:
	r = writev(port, iov, iovlen);
	if (r <= 0) {
		if (r == -1 && errno == EINTR)
			goto again;

		return -1;
	}

	/*
	 * XXX make sure writev(2) on AF_UNIX SOCK_DGRAM never returns partially
	 * written datagrams.
	 * For now, make sure all bytes were written.
	 */
	while (iovlen--)
		r -= iov[iovlen].iov_len;
	if (r != 0)
		return -1;

	return 0;
}

/*
 * Read a message from the proxy. All messages from the proxy should be prefixed
 * with an interface id, and a source and destination socket address structure.
 *
 * "ifnid" interface id
 * "lsa" is the local socket name
 * "fsa" is the foreign socket name
 *
 * "ifnid", "lsa", "fsa", "mtcode", "msg" and "msgsize" are all updated on receipt
 * of a valid message. "msgsize" is a value/result parameter.
 *
 * Return 0 on success, -1 on error.
 */
int
wire_recvproxymsg(int port, uint32_t *ifnid, struct sockaddr_storage *lsa,
    struct sockaddr_storage *fsa, unsigned char *mtcode, void *msg, size_t *msgsize)
{
	struct iovec iov[5];
	struct msgtype *mt;
	ssize_t r;
	size_t iovlen;

	iovlen = 0;
	iov[iovlen].iov_base = ifnid;
	iov[iovlen].iov_len = sizeof(*ifnid);
	iovlen++;
	iov[iovlen].iov_base = lsa;
	iov[iovlen].iov_len = sizeof(*lsa);
	iovlen++;
	iov[iovlen].iov_base = fsa;
	iov[iovlen].iov_len = sizeof(*fsa);
	iovlen++;
	iov[iovlen].iov_base = mtcode;
	iov[iovlen].iov_len = sizeof(*mtcode);
	iovlen++;
	iov[iovlen].iov_base = (void *)msg;
	iov[iovlen].iov_len = *msgsize;
	iovlen++;

again:
	r = readv(port, iov, iovlen);
	if (r <= 0) {
		if (r == -1 && errno == EINTR)
			goto again;

		return -1;
	}

	/*
	 * XXX make sure readv(2) on AF_UNIX SOCK_DGRAM never returns partially
	 * read datagrams.
	 */

	if ((size_t)r < sizeof(*ifnid) + sizeof(*lsa) + sizeof(*fsa) + sizeof(*mtcode))
		return -1;

	if (*mtcode >= MTNCODES)
		return -1;

	*msgsize = r - sizeof(*ifnid) - sizeof(*lsa) - sizeof(*fsa) -
	    sizeof(*mtcode);

	if (*msgsize >= MAXMSGSIZEP1)
		return -1;

	mt = &msgtypes[*mtcode];

	if (mt->varsize) {
		/* size is a minimum on variable sized messages */
		if (*msgsize < mt->size)
			return -1;
	} else
		if (*msgsize != mt->size)
			return -1;

	return 0;
}

/*
 * Make a 5-CONNREQ message, updates "mcr".
 *
 * "fsa" is the foreign socket name.
 * "lsa" is the local socket name.
 *
 * Return 0 on success, -1 on failure.
 */
int
makemsgconnreq(struct msgconnreq *mcr, const struct sockaddr_storage *fsa,
    const struct sockaddr_storage *lsa)
{
	if (mcr == NULL || fsa == NULL || lsa == NULL)
		return -1;

	memcpy(&mcr->fsa, fsa, sizeof(*fsa));
	memcpy(&mcr->lsa, lsa, sizeof(*lsa));

	return 0;
}

/*
 * Make a 9-REQWGINIT message, updates "mri".
 *
 * Return 0 on success, -1 on failure.
 */
int
makemsgreqwginit(struct msgreqwginit *mri)
{
	if (mri == NULL)
		return -1;

	memset(mri, 0, sizeof(*mri));

	return 0;
}
