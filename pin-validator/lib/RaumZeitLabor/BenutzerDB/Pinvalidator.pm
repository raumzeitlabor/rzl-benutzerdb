package RaumZeitLabor::BenutzerDB::Pinvalidator;
# vim:ts=4:sw=4:expandtab
# © 2011 Michael Stapelberg (see also: LICENSE)
#

####################################################

use strict;
use warnings;
# These modules are in core:
use v5.10;
use Sys::Syslog;
use POSIX qw(ceil strftime);
# These modules are not in core:
use DateTime;
use AnyEvent;
use AnyEvent::HTTP;
use AnyEvent::HTTP::Stream;
use JSON::XS;
use Data::Dumper;
use DBI;
use DBD::mysql;
use YAML::Syck;

our $VERSION = '1.0';

my $buffer = '';

my $cfg;
if (-e 'pin-validator.yml') {
    $cfg = LoadFile('pin-validator.yml');
} elsif (-e '/etc/pin-validator.yml') {
    $cfg = LoadFile('/etc/pin-validator.yml');
} else {
    die "Could not load ./pin-validator.yml or /etc/pin-validator.yml";
}

if (!exists($cfg->{Hausbus}) || !exists($cfg->{MySQL})) {
    die "Configuration sections incomplete: need Hausbus and MySQL";
}

sub validate_buffer {
    syslog 'info', "validating buffer";

    my $db = DBI->connect(
        $cfg->{MySQL}->{data_source},
        $cfg->{MySQL}->{user},
        $cfg->{MySQL}->{pass},
    ) or die "Could not connect to MySQL database: $!";

    my $row = $db->selectrow_hashref(q|SELECT * FROM nutzer WHERE pin = ?|,
        { },
        $buffer);
    if (!defined($row)) {
        syslog 'warn', "invalid pin ($buffer), not doing anything";
        $buffer = '';
        return;
    }
    syslog 'info', "user " . $row->{handle} . " opens the door with pin $buffer";

    http_post 'http://' . $cfg->{Hausbus}->{host} . '/send/pinpad',
              encode_json({ payload => 'open' }),
              sub {
                      my ($data, $headers) = @_;
                      syslog 'debug', "reply from server: " . Dumper($data);
              };

    $buffer = '';
}

sub run {
    openlog 'pin-validator', 'pid', 'daemon';
    syslog 'info', 'Starting up';

    my $stream = AnyEvent::HTTP::Stream->new(
        url => 'http://' . $cfg->{Hausbus}->{host} . '/group/pinpad',
        on_data => sub {
            my ($data) = @_;

            my $pkt = decode_json($data);
            return unless exists $pkt->{payload};
            my $payload = $pkt->{payload};

            return unless $payload =~ /^KEY /;
            my ($key) = ($payload =~ /^KEY ([0-9#\*])$/);
            syslog 'info', "user pressed key $key";

            # alle tasten außer #: taste im buffer speichern
            if ($key ne '#') {
                $buffer .= $key;
                # TODO: timer, der den buffer cleared
                return;
            }

            validate_buffer();
        });

    syslog 'info', "pin-validator initialized...";
    AE::cv->recv
}

1

__END__


=head1 NAME

RaumZeitPinValidator

=head1 DESCRIPTION

TODO

=head1 VERSION

Version 1.0

=head1 AUTHOR

Michael Stapelberg, C<< <michael at stapelberg.de> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2011 Michael Stapelberg.

This program is free software; you can redistribute it and/or modify it
under the terms of the BSD license.

=cut
