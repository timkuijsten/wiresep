CFLAGS = -Wall -Wextra -pedantic-errors -O0 -g

INSTALL_ETC 	= install -m 0640
INSTALL_BIN 	= install -m 0555
INSTALL_SBIN 	= install -m 0555
INSTALL_MAN	= install -m 0444

PREFIX	= /usr/local
ETCDIR	= /etc
BINDIR	= $(PREFIX)/bin
SBINDIR	= $(PREFIX)/sbin
MANDIR	= $(PREFIX)/man

VERSION_MAJOR	= 0
VERSION_MINOR	= 8
VERSION_PATCH	= 0

SRCFILES = base64.c enclave.c master.c proxy.c test.c wireprot.c wiresep.c \
	    ifn.c parseconfig.c tai64n.c util.c wiresep-keygen.c

HDRFILES = antireplay.h parseconfig.h tai64n.h wireprot.h base64.h scfg.h \
	    util.h wiresep.h

all: wiresep wiresep-keygen

lint:
	${CC} ${CFLAGS} -fsyntax-only ${SRCFILES} ${HDRFILES} 2>&1

wiresep: tai64n.o blake2s-ref.o wireprot.o wiresep.o util.o enclave.o proxy.o \
    ifn.o scfg.o base64.o parseconfig.o master.c
	${CC} ${CFLAGS} -DVERSION_MAJOR=${VERSION_MAJOR} \
	    -DVERSION_MINOR=${VERSION_MINOR} -DVERSION_PATCH=${VERSION_PATCH} \
	    tai64n.o blake2s-ref.o wiresep.o wireprot.o util.o enclave.o \
	    proxy.o ifn.o base64.o scfg.o parseconfig.o master.c -o $@ -lcrypto

wiresep-keygen: base64.o wiresep-keygen.c
	${CC} ${CFLAGS} base64.o wiresep-keygen.c -o $@ -lcrypto

tai64n.o: tai64n.c tai64n.h
	${CC} ${CFLAGS} -c tai64n.c

base64.o: base64.c base64.h
	${CC} ${CFLAGS} -c base64.c

wiresep.o: wiresep.c wiresep.h
	${CC} ${CFLAGS} -c wiresep.c

parseconfig.o: parseconfig.c parseconfig.h
	${CC} ${CFLAGS} -c parseconfig.c

util.o: util.c util.h
	${CC} ${CFLAGS} -c util.c

enclave.o: enclave.c wiresep.h wireprot.h util.h
	${CC} ${CFLAGS} -c enclave.c

wireprot.o: wireprot.c wireprot.h
	${CC} ${CFLAGS} -c wireprot.c

ifn.o: ifn.c wireprot.h util.h
	${CC} ${CFLAGS} -c ifn.c

proxy.o: proxy.c wiresep.h wireprot.h util.h
	${CC} ${CFLAGS} -c proxy.c

blake2s-ref.o: blake2s-ref.c blake2-impl.h blake2.h
	${CC} ${CFLAGS} -c blake2s-ref.c

scfg.o: y.tab.c
	${CC} ${CFLAGS} -c y.tab.c -o $@

y.tab.c: scfg.y scfg.h
	yacc scfg.y

processdesign.svg: doc/processdesign.gv
	dot -Tsvg doc/processdesign.gv -o $@

processdesign.png: doc/processdesign.gv
	dot -Tpng doc/processdesign.gv -o $@

initiatorsession.svg: doc/initiatorsession.gv
	dot -Tsvg doc/initiatorsession.gv -o $@

initiatorsession.png: doc/initiatorsession.gv
	dot -Tpng doc/initiatorsession.gv -o $@

respondersession.svg: doc/respondersession.gv
	dot -Tsvg doc/respondersession.gv -o $@

respondersession.png: doc/respondersession.gv
	dot -Tpng doc/respondersession.gv -o $@

dotsvg: processdesign.svg initiatorsession.svg respondersession.svg

dotpng: processdesign.png initiatorsession.png respondersession.png

dot: dotsvg dotpng

testifn: tai64n.o blake2s-ref.o wireprot.o wiresep.o util.o scfg.o base64.o \
    parseconfig.o ifn.c test/testifn.c
	${CC} ${CFLAGS} -g -pg tai64n.o blake2s-ref.o wiresep.o wireprot.o \
	    util.o base64.o scfg.o parseconfig.o test/testifn.c -o $@ -lcrypto

testproxy: tai64n.o blake2s-ref.o wireprot.o wiresep.o util.o scfg.o base64.o \
    parseconfig.o proxy.c test/testproxy.c
	${CC} ${CFLAGS} -g -pg tai64n.o blake2s-ref.o wiresep.o wireprot.o \
	    util.o base64.o scfg.o parseconfig.o test/testproxy.c -o $@ -lcrypto

clean:
	rm -f y.tab.c *.o *.core *.html wiresep wiresep-keygen testproxy

tags: *.[ch]
	find . -name '*.[chy]' | xargs ctags -d

wiresep-keygen.1.html:  wiresep-keygen.1
	mandoc -T html -O style=man.css wiresep-keygen.1 > wiresep-keygen.1.html

wiresep.conf.5.html:  wiresep.conf.5
	mandoc -T html -O style=man.css wiresep.conf.5 > wiresep.conf.5.html

wiresep.8.html:  wiresep.8
	mandoc -T html -O style=man.css wiresep.8 > wiresep.8.html

manhtml: wiresep.8.html wiresep-keygen.1.html wiresep.conf.5.html

install: wiresep wiresep-keygen
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(SBINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	$(INSTALL_BIN) wiresep-keygen $(DESTDIR)$(BINDIR)
	$(INSTALL_SBIN) wiresep $(DESTDIR)$(SBINDIR)
	$(INSTALL_MAN) wiresep-keygen.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL_MAN) wiresep.conf.5 $(DESTDIR)$(MANDIR)/man5
	$(INSTALL_MAN) wiresep.8 $(DESTDIR)$(MANDIR)/man8
	makewhatis $(DESTDIR)$(MANDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/wiresep-keygen
	rm -f $(DESTDIR)$(SBINDIR)/wiresep
	rm -f $(DESTDIR)$(MANDIR)/man1/wiresep-keygen.1
	rm -f $(DESTDIR)$(MANDIR)/man5/wiresep.conf.5
	rm -f $(DESTDIR)$(MANDIR)/man8/wiresep.8
