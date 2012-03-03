#!/usr/bin/env perl
# vim:ts=4:sw=4:expandtab
use strict;
use warnings;
use inc::Module::Install;

name     'RaumZeitBenutzerDB';
all_from 'lib/BenutzerDB.pm';

requires 'YAML';
requires 'Dancer';
requires 'Dancer::Plugin::Database';
requires 'Dancer::Session::Cookie';
requires 'Template';
requires 'Plack';
requires 'Crypt::SaltedHash';
requires 'Twiggy';

postamble <<'END_OF_MAKEFILE';
install:: extra_install
pure_install:: extra_install
install_vendor:: extra_install

extra_install::
	install -d $(DESTDIR)/etc/
	install -m 640 config.yml.example $(DESTDIR)/etc/config.yml
END_OF_MAKEFILE

WriteAll;
