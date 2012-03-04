#!/usr/bin/env perl
# vim:ts=4:sw=4:noexpandtab
use strict;
use warnings;
use inc::Module::Install;

name     'RaumZeitSSHPubkeySync';
all_from 'script/ssh-pubkey-sync';

requires 'AnyEvent';
requires 'AnyEvent::HTTP';
requires 'JSON::XS';
requires 'Text::Sprintf::Named';
requires 'Try::Tiny';

install_script 'script/ssh-pubkey-sync';

WriteAll;
