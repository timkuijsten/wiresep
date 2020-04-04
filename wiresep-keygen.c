/*
 * Copyright (c) 2019, 2020 Tim Kuijsten
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
#include <sys/stat.h>
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/curve25519.h>

#include "base64.h"
#include "wiresep.h"

#define KEYPATH "/etc/wiresep"

void
printusage(int d)
{
	dprintf(d, "usage: %s [-o path] tunX\n", getprogname());
	dprintf(d, "       %s [-o path] -s global\n", getprogname());
	dprintf(d, "       %s [-o path] -s tunX [peer ...]\n", getprogname());
}

/*
 * Generate a pre-shared key and write it in "key file format" to "fd". See
 * wiresep(8) for a description of the used syntax.
 *
 * Return 0 on success, -1 on failure with errno set.
 */
int
genwritepskfile(int fd)
{
	struct iovec iov[2];
	uint8_t psk[KEYLEN];
	char b64psk[46];
	char *postfix = " pre-shared key\n";
	int ret;

	arc4random_buf(psk, sizeof psk);

	if (base64_ntop(psk, sizeof psk, b64psk, sizeof b64psk)
	    != 44) {
		errno = EINVAL;
		ret = -1;
		goto out;
	}

	iov[0].iov_base = b64psk;
	iov[0].iov_len = 44;
	iov[1].iov_base = postfix;
	iov[1].iov_len = strlen(postfix);

	if (writev(fd, iov, sizeof iov / sizeof iov[0]) == -1) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	explicit_bzero(psk, sizeof psk);
	explicit_bzero(b64psk, sizeof b64psk);

	return ret;
}

/*
 * Write a private key in "key file format" to "fd". See wiresep(8) for a
 * description of the used syntax.
 *
 * Return 0 on success, -1 on failure with errno set.
 */
int
writeprivkeyfile(int fd, const char *privkey, size_t privkeylen,
    const char *pubkey, size_t pubkeylen)
{
	struct iovec iov[5];
	const char *prefix = "# ";
	const char *intermediate = " public key\n";
	const char *postfix = "   private key\n";

	iov[0].iov_base = (char *)prefix;
	iov[0].iov_len = strlen(prefix);
	iov[1].iov_base = (char *)pubkey;
	iov[1].iov_len = pubkeylen;
	iov[2].iov_base = (char *)intermediate;
	iov[2].iov_len = strlen(intermediate);
	iov[3].iov_base = (char *)privkey;
	iov[3].iov_len = privkeylen;
	iov[4].iov_base = (char *)postfix;
	iov[4].iov_len = strlen(postfix);

	if (writev(fd, iov, sizeof iov / sizeof iov[0]) == -1)
		return -1;

	return 0;
}

int
main(int argc, char **argv)
{
	uint8_t privkey[X25519_KEY_LENGTH], pubkey[X25519_KEY_LENGTH];
	char b64privkey[46], b64pubkey[46];
	int i, fd, wd, ret;
	char c;
	char *keypath, *presharedkey, *filename;

	presharedkey = NULL;
	keypath = KEYPATH;

	while ((c = getopt(argc, argv, "o:s:h")) != -1) {
		switch(c) {
		case 'o':
			keypath = optarg;
			break;
		case 's':
			presharedkey = optarg;
			break;
		case 'h':
			printusage(STDOUT_FILENO);
			exit(0);
		case '?':
			printusage(STDERR_FILENO);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (presharedkey == NULL) {
		if (argc != 1) {
			printusage(STDERR_FILENO);
			exit(1);
		}
	}

	if (pledge("stdio rpath wpath cpath", "") == -1)
		err(1, "pledge");

	umask(S_IWUSR|S_IXUSR|S_IRWXG|S_IRWXO);

	if ((wd = open(keypath, O_RDONLY|O_DIRECTORY|O_CLOEXEC)) == -1)
		err(1, "could not open output directory %s", keypath);

	if (presharedkey == NULL) {
		if (asprintf(&filename, "%s.privkey", argv[0]) < 0)
			err(1, "asprintf error %s", argv[0]);

		fd = openat(wd, filename, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,
		    S_IRWXU);

		if (fd == -1)
			err(1, "could not create private key file %s/%s",
			    keypath, filename);

		ret = 1;

		X25519_keypair(pubkey, privkey);

		if (base64_ntop(privkey, sizeof privkey, b64privkey,
		    sizeof b64privkey) != 44) {
			warnx("base64_ntop privkey error");
			goto out;
		}

		if (base64_ntop(pubkey, sizeof pubkey, b64pubkey,
		    sizeof b64pubkey) != 44) {
			warnx("base64_ntop pubkey error");
			goto out;
		}

		if (writeprivkeyfile(fd, b64privkey, strlen(b64privkey),
		    b64pubkey, strlen(b64pubkey)) == -1) {
			warn("could not write private key file %s/%s",
			    keypath, filename);
			goto out;
		}

		if (close(fd) == -1) {
			warn("error when closing private key file %s/%s",
			    keypath, filename);
			goto out;
		}

		fprintf(stdout, "generated private key: %s/%s\n"
		    "associated public key: %s\n"
		    "The public key is also written as a comment into the private key file.\n",
		    keypath, filename, b64pubkey);
		free(filename);

		ret = 0;

out:
		explicit_bzero(privkey, sizeof privkey);
		explicit_bzero(pubkey, sizeof pubkey);
		explicit_bzero(b64privkey, sizeof b64privkey);
		explicit_bzero(b64pubkey, sizeof b64pubkey);

		if (close(wd) == -1)
			err(1, "error when closing directory handle %s",
			    keypath);

		return ret;
	}

	if (strcmp(presharedkey, "global") != 0 &&
	    strncmp(presharedkey, "tun", 3) != 0) {
		err(1, "pre-shared key argument must be either \"global\" or "
		    "the name of a tunnel interface: %s", presharedkey);
	}

	if (argc == 0) {
		if (asprintf(&filename, "%s.psk", presharedkey) < 0)
			err(1, "asprintf error %s", presharedkey);

		fd = openat(wd, filename, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,
		    S_IRWXU);

		if (fd == -1)
			err(1, "could not create pre-shared key file %s/%s",
			    keypath, filename);

		if (genwritepskfile(fd) == -1)
			err(1, "could not write pre-shared key file %s/%s",
			    keypath, filename);

		if (close(fd) == -1)
			err(1, "error when closing pre-shared key file %s/%s",
			    keypath, filename);

		fprintf(stdout, "generated pre-shared key: %s/%s\n", keypath,
		    filename);
		free(filename);

		if (close(wd) == -1)
			err(1, "error when closing directory handle %s",
			    keypath);

		return 0;
	}

	for (i = 0; i < argc; i++) {
		if (asprintf(&filename, "%s.%s.psk", presharedkey, argv[i]) < 0)
			err(1, "asprintf error %s", presharedkey);

		fd = openat(wd, filename, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,
		    S_IRWXU);

		if (fd == -1)
			err(1, "could not create pre-shared key file %s/%s",
			    keypath, filename);

		if (genwritepskfile(fd) == -1)
			err(1, "could not write pre-shared key file %s/%s",
			    keypath, filename);

		if (close(fd) == -1)
			err(1, "error when closing pre-shared key file %s/%s",
			    keypath, filename);

		fprintf(stdout, "generated pre-shared key: %s/%s\n", keypath,
		    filename);
		free(filename);
	}

	if (close(wd) == -1)
		err(1, "error when closing directory handle %s", keypath);

	return 0;
}
