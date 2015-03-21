# well, a simpler makefile is hardly imaginable...
DESTDIR=

# the version number of the package
VERSION=$(shell sed -n '1s/^.*(\(.*\)).*$$/\1/p' debian/changelog)

CPPFLAGS:=$(shell dpkg-buildflags --get CPPFLAGS)
CFLAGS:=$(shell dpkg-buildflags --get CFLAGS)
CXXFLAGS:=$(shell dpkg-buildflags --get CXXFLAGS)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)

all: kuvert_submit

clean:
	-rm -f kuvert_submit kuvert.tmp

install:	kuvert_submit  kuvert
	install -d $(DESTDIR)/usr/bin $(DESTDIR)/usr/share/man/man1 \
	$(DESTDIR)/usr/share/perl5/Net/Server/Mail/ESMTP/
	install kuvert_submit $(DESTDIR)/usr/bin
# fix the version number
	sed 's/INSERT_VERSION/$(VERSION)/' kuvert > kuvert.tmp
	install kuvert.tmp $(DESTDIR)/usr/bin/kuvert
	-rm kuvert.tmp
	install plainAUTH.pm $(DESTDIR)/usr/share/perl5/Net/Server/Mail/ESMTP/
	pod2man --center="User Commands" -r Mail  kuvert $(DESTDIR)/usr/share/man/man1/kuvert.1
	pod2man --center="User Commands" -r Mail kuvert_submit.pod $(DESTDIR)/usr/share/man/man1/kuvert_submit.1

test:
	echo $(VERSION)
