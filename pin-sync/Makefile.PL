#!/usr/bin/env perl
# vim:ts=4:sw=4:expandtab
use strict;
use warnings;
use inc::Module::Install;

name     'RaumZeitPinSync';
all_from 'lib/RaumZeitLabor/BenutzerDB/Pinsync.pm';

requires 'AnyEvent';
requires 'AnyEvent::HTTP';
requires 'AnyEvent::HTTP::Stream';
requires 'JSON::XS';
requires 'YAML::Syck';
requires 'DBI';
requires 'DBD::mysql';
requires 'String::CRC32';
requires 'Try::Tiny';

install_script 'pin-sync';

postamble <<'END_OF_MAKEFILE';
install:: extra_install
pure_install:: extra_install
install_vendor:: extra_install

extra_install:
	install -d $(DESTDIR)/etc/rsyslog.d/ $(DESTDIR)/etc/
	install -m 755 pin-sync.rsyslog $(DESTDIR)/etc/rsyslog.d/pin-sync.conf
	install -m 640 pin-sync.yml.ex $(DESTDIR)/etc/pin-sync.yml
END_OF_MAKEFILE

WriteAll;
