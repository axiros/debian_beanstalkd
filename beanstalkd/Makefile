DESTDIR=
LDLIBS := $(LDLIBS) -l apr-1 -l aprutil-1
PREFIX=/usr/local
BINDIR=$(DESTDIR)$(PREFIX)/bin
CFLAGS?=-Wall -Werror\
	-Wformat=2\
	-g\

OS=$(shell uname -s | tr A-Z a-z | sed 's?gnu/kfreebsd?freebsd?')
INSTALL=install

DEB_HOST_ARCH_OS:=$(shell dpkg-architecture -qDEB_HOST_ARCH_OS)
VERS=$(shell ./vers.sh)
TARG=beanstalkd
MOFILE=main.o
OFILES=\
	$(OS).o\
	conn.o\
	file.o\
	heap.o\
	job.o\
	ms.o\
	net.o\
	primes.o\
	prot.o\
	serv.o\
	time.o\
	tube.o\
	util.o\
	vers.o\
	walg.o\
	auth.o\

ifneq ($(DEB_HOST_ARCH_OS),linux)
OFILES += sd-daemon.o
endif

TOFILES=\
	testheap.o\
	testjobs.o\
	testserv.o\
	testutil.o\

HFILES=\
	dat.h\

ifneq ($(DEB_HOST_ARCH_OS),linux)
HFILES += sd-daemon.h
endif

CLEANFILES=\
	vers.c\

.PHONY: all
all: $(TARG)

$(TARG): $(OFILES) $(MOFILE)
	$(LINK.o) -o $@ $^ $(LDLIBS)

.PHONY: install
install: $(BINDIR) $(BINDIR)/$(TARG)

$(BINDIR):
	$(INSTALL) -d $@

$(BINDIR)/%: %
	$(INSTALL) $< $@

CLEANFILES:=$(CLEANFILES) $(TARG)

$(OFILES) $(MOFILE): $(HFILES)

.PHONY: clean
clean:
	rm -f *.o $(CLEANFILES)

.PHONY: check
check: ct/_ctcheck
	ct/_ctcheck

.PHONY: bench
bench: ct/_ctcheck
	ct/_ctcheck -b

ct/_ctcheck: ct/_ctcheck.o ct/ct.o $(OFILES) $(TOFILES)

ct/_ctcheck.c: $(TOFILES) ct/gen
	ct/gen $(TOFILES) >$@.part
	mv $@.part $@

ct/ct.o ct/_ctcheck.o: ct/ct.h ct/internal.h

$(TOFILES): $(HFILES) ct/ct.h

CLEANFILES:=$(CLEANFILES) ct/_* ct/*.o

ifneq ($(shell ./verc.sh),$(shell cat vers.c 2>/dev/null))
.PHONY: vers.c
endif
vers.c:
	./verc.sh >vers.c

doc/beanstalkd.1 doc/beanstalkd.1.html: doc/beanstalkd.ronn
	ronn $<

freebsd.o: darwin.c
