#!/usr/bin/env perl
# vim:ts=4:sw=4:expandtab

use strict;
use warnings;
use DateTime;
use AnyEvent;
use AnyEvent::HTTP;
use AnyEvent::HTTP::Stream;
use JSON::XS;
use Data::Dumper;
use DBI;
use DBD::mysql;
use v5.10;

my $buffer = '';

sub prefix {
    return DateTime->now->strftime("%Y-%m-%d %H:%M:%S") . ' - ';
}

my $stream = AnyEvent::HTTP::Stream->new(
    url => 'http://firebox:8888/group/pinpad',
    on_data => sub {
        my ($data) = @_;

        my $pkt = decode_json($data);
        return unless exists $pkt->{payload};
        my $payload = $pkt->{payload};

        return unless $payload =~ /^KEY /;
        my ($key) = ($payload =~ /^KEY ([0-9#\*])$/);
        say "user pressed key $key";

        # alle tasten außer #: taste im buffer speichern
        if ($key ne '#') {
            $buffer .= $key;
            # TODO: timer, der den buffer cleared
            return;
        }

        validate_buffer();
    });

sub validate_buffer {
    say prefix . "validating buffer";
    
    my $db = DBI->connect('DBI:mysql:host=172.22.36.6;database=nutzerdb',
        'nutzerdb',
        'GEHEIM'
    );
    my $row = $db->selectrow_hashref(q|SELECT * FROM nutzer WHERE pin = ?|,
        { },
        $buffer);
    if (!defined($row)) {
        say prefix . "invalid pin ($buffer), not doing anything";
        $buffer = '';
        return;
    }
    say prefix . "user " . $row->{handle} . " opens the door with pin $buffer";

    http_post 'http://firebox:8888/send/pinpad',
              encode_json({ payload => 'open' }),
              sub {
                      my ($data, $headers) = @_;
                      say prefix . "reply from server: " . Dumper($data);
              };
}

AE::cv->recv
