#!/usr/bin/env perl
# vim:ts=4:sw=4:expandtab
use strict;
use warnings;
use inc::Module::Install;

name     'RaumZeitPinValidator';
all_from 'lib/RaumZeitLabor/BenutzerDB/Pinvalidator.pm';

requires 'DateTime';
requires 'AnyEvent';
requires 'AnyEvent::HTTP';
requires 'AnyEvent::HTTP::Stream';
requires 'JSON::XS';
requires 'Data::Dumper';
requires 'DBI';
requires 'DBD::mysql';
requires 'YAML::Syck';

install_script 'pin-validator';

postamble <<'END_OF_MAKEFILE';
install:: extra_install
pure_install:: extra_install
install_vendor:: extra_install

extra_install:
	install -d $(DESTDIR)/etc/rsyslog.d/ $(DESTDIR)/etc/
	install -m 755 pin-validator.rsyslog $(DESTDIR)/etc/rsyslog.d/pin-validator.conf
	install -m 640 pin-validator.yml.ex $(DESTDIR)/etc/pin-validator.yml
END_OF_MAKEFILE

WriteAll;
