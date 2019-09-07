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

#ifndef UTIL_H
#define UTIL_H

#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>

#define EMPTYDIR "/var/empty"
#define MAXIPSTR 40 /* full ipv6 address in hex notation with terminating nul */

int isopenfd(int);
int readhexnomem(uint8_t *, size_t, const char *, size_t);
void hexdump(FILE *, const uint8_t *, size_t , size_t);
int dropuser(uid_t, gid_t);
int strtoaddr(struct sockaddr_storage *, const char *, const char *, int);
int addrtostr(char *, size_t, const struct sockaddr *, int);
void printopenfds(FILE *, int);
int data2file(const char *, const void *, size_t);
ssize_t writen(int, const void *, size_t);
in_port_t getport(const struct sockaddr_storage *);
int resolveuser(uid_t *, gid_t *, const char *);
int resolvegroup(gid_t *, const char *);
int facilitystrtoint(int *, const char *);
int daemonize(void);
int initlog(const char *);
void logexit(int code, const char *, ...);
void logexitx(int code, const char *, ...);
void logwarn(const char *, ...);
void logwarnx(const char *, ...);
void lognotice(const char *, ...);
void lognoticex(const char *, ...);
void loginfo(const char *, ...);
void loginfox(const char *, ...);
void logdebug(const char *, ...);
void logdebugx(const char *, ...);

#endif /* UTIL_H */
