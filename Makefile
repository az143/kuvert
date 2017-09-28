# well, a simpler makefile is hardly imaginable...

# if destdir is set, debian package making is assumed
# so we install relative to that and don't touch /usr/local
#
# if destdir is unset, we install into /usr/local: bin and the perl sitelib dir
DESTDIR=

ifneq "$(DESTDIR)" ""
# the debian case
PERLDIR:=$(DESTDIR)$(shell perl -MConfig -e 'print $$Config{vendorlib}')
VERSION:=$(shell sed -n '1s/^.*(\(.*\)).*$$/\1/p' debian/changelog)
PREFIX:=$(DESTDIR)/usr
else
# the non-debian case
PERLDIR:=$(shell perl -MConfig -e 'print $$Config{sitelib}')
VERSION:=$(shell git tag --sort=v:refname | tail -1 | cut -f 2 -d v)
PREFIX:=/usr/local
endif

CPPFLAGS:=$(shell dpkg-buildflags --get CPPFLAGS)
CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)
CXXFLAGS:=$(shell dpkg-buildflags --get CXXFLAGS)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)

all: kuvert_submit

clean:
	-rm -f kuvert_submit kuvert.tmp

install:	kuvert_submit  kuvert
# ensure all needed dirs are present
	install -d $(PREFIX)/bin $(PREFIX)/share/man/man1 $(PERLDIR)/Net/Server/Mail/ESMTP
	install kuvert_submit $(PREFIX)/bin
# insert the version number
	sed 's/INSERT_VERSION/$(VERSION)/' kuvert > kuvert.tmp
	install kuvert.tmp $(PREFIX)/bin/kuvert
	-rm kuvert.tmp
	install plainAUTH.pm $(PERLDIR)/Net/Server/Mail/ESMTP/
	pod2man --center="User Commands" -r Mail  kuvert $(PREFIX)/share/man/man1/kuvert.1
	pod2man --center="User Commands" -r Mail kuvert_submit.pod $(PREFIX)/share/man/man1/kuvert_submit.1

