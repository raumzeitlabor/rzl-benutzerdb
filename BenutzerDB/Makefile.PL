#!/usr/bin/env perl
# vim:ts=4:sw=4:noexpandtab
use strict;
use warnings;
use inc::Module::Install;

name     'RaumZeitBenutzerDB';
all_from 'lib/RaumZeitLabor/BenutzerDB.pm';

requires 'YAML';
requires 'Dancer';
requires 'Dancer::Plugin::Database';
requires 'Dancer::Session::Cookie';
requires 'Template';
requires 'Plack';
requires 'Plack::Middleware::Session';
requires 'Plack::Middleware::CSRFBlock';
requires 'Crypt::SaltedHash';
requires 'Twiggy';
requires 'JSON';

install_script 'script/raumzeitbenutzerdb';

postamble <<'END_OF_MAKEFILE';
install:: extra_install
pure_install:: extra_install
install_vendor:: extra_install

extra_install::
	install -d $(DESTDIR)/etc/benutzerdb
	install -d $(DESTDIR)/usr/share/benutzerdb
	install -m 640 config.yml.example $(DESTDIR)/etc/benutzerdb/config.yml
	cp -r views $(DESTDIR)/usr/share/benutzerdb/views
	cp -r public $(DESTDIR)/usr/share/benutzerdb/public
END_OF_MAKEFILE

WriteAll;
