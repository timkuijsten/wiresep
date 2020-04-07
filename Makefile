CFLAGS += -Wall -Wextra -pedantic-errors

INSTALL_ETC 	= install -m 0640
INSTALL_BIN 	= install -m 0555
INSTALL_SBIN 	= install -m 0555
INSTALL_MAN	= install -m 0444
INSTALL_EXAMPLE	= install -m 0644

PREFIX	= /usr/local
ETCDIR	= /etc
BINDIR	= $(PREFIX)/bin
SBINDIR	= $(PREFIX)/sbin
MANDIR	= $(PREFIX)/man
EXAMPLEDIR	= $(PREFIX)/share/examples

VERSION_MAJOR	= 0
VERSION_MINOR	= 11
VERSION_PATCH	= 1

SRCFILES = base64.c enclave.c master.c proxy.c test.c wireprot.c wiresep.c \
	    ifn.c parseconfig.c tai64n.c util.c wiresep-keygen.c

HDRFILES = antireplay.h parseconfig.h tai64n.h wireprot.h base64.h \
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

y.tab.c: scfg.y
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
	rm -f y.tab.c *.o *.core wiresep wiresep-keygen testproxy

tags: *.[ch]
	find . -name '*.[chy]' | xargs ctags -d
	cd test && find . -name '*.[chy]' | xargs ctags -d

release: dotpng y.tab.c
	git archive \
	    --prefix=wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}/ \
	    -o wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar \
	    v${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}
	# reset access and modification times of extra files in the archive
	touch -d $$(git log -1 --format=%cI \
	    v${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH} | cut -d+ -f1) \
	    *.png y.tab.c
	# include these files in the archive
	tar -r \
	    -s '/^/wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}\/doc\//' \
	    -f wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar \
	    *.png
	tar -r \
	    -s '/^/wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}\//' \
	    -f wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar \
	    y.tab.c
	# reset access and modification times on the archive itself
	touch -r y.tab.c \
	    wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar
	gzip wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar
	cksum -ba sha256 \
	    wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar.gz | \
	    tee \
	    wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar.gz.SHA256
	touch -r \
	    wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar.gz \
	    wiresep-${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.tar.gz.SHA256

install: wiresep wiresep-keygen
	mkdir -p $(DESTDIR)$(ETCDIR)/wiresep
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(SBINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	mkdir -p $(DESTDIR)$(EXAMPLEDIR)/wiresep
	$(INSTALL_BIN) wiresep-keygen $(DESTDIR)$(BINDIR)
	$(INSTALL_SBIN) wiresep $(DESTDIR)$(SBINDIR)
	$(INSTALL_MAN) wiresep-keygen.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL_MAN) wiresep.conf.5 $(DESTDIR)$(MANDIR)/man5
	$(INSTALL_MAN) wiresep.8 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL_EXAMPLE) wiresep.conf.example $(DESTDIR)$(EXAMPLEDIR)/wiresep

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/wiresep-keygen
	rm -f $(DESTDIR)$(SBINDIR)/wiresep
	rm -f $(DESTDIR)$(MANDIR)/man1/wiresep-keygen.1
	rm -f $(DESTDIR)$(MANDIR)/man5/wiresep.conf.5
	rm -f $(DESTDIR)$(MANDIR)/man8/wiresep.8
	rm -f $(DESTDIR)$(ETCDIR)/wiresep/wiresep.conf.example
	rm -f $(DESTDIR)$(EXAMPLEDIR)/wiresep/wiresep.conf.example
	rmdir $(DESTDIR)$(EXAMPLEDIR)/wiresep
	rmdir $(DESTDIR)$(ETCDIR)/wiresep
