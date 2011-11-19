package RaumZeitLabor::BenutzerDB::Pinsync;
# vim:ts=4:sw=4:expandtab
# © 2011 Michael Stapelberg (see also: LICENSE)
#
# Synchronizes the database PINs to the pinpad-controller EEPROM.

use strict;
use warnings;
# These modules are in core:
use v5.10;
use Sys::Syslog;
use POSIX qw(ceil strftime);
# These modules are not in core:
use AnyEvent;
use AnyEvent::HTTP;
use AnyEvent::HTTP::Stream;
use JSON::XS;
use DBI;
use DBD::mysql;
use String::CRC32;
use Try::Tiny;
use YAML::Syck;

our $VERSION = '1.0';

# The following constants are from rzl-hausbus/firmware-pinpad/main.c:
# a CRC32 checksum needs 4 bytes
use constant CRC32_SIZE => 4;
# the amount of pins needs 1 byte (0 <= num_pins <= 180)
use constant NUM_SIZE => 1;
# a PIN is encoded in 3 bytes
use constant PIN_SIZE => 3;
# we have 6 pins (= 6 * 3 = 18 bytes) per block
use constant PINS_PER_BLOCK => 6;

use constant BLOCK_SIZE => ((PINS_PER_BLOCK * PIN_SIZE) + CRC32_SIZE);

# We use an own object to *NOT* use utf8. JSON::XS should just treat everything
# as raw bytes.
my $json = JSON::XS->new()->ascii(1);
my $cfg;
if (-e 'pin-sync.yml') {
    $cfg = LoadFile('pin-sync.yml');
} elsif (-e '/etc/pin-sync.yml') {
    $cfg = LoadFile('/etc/pin-sync.yml');
} else {
    die "Could not load ./pin-sync.yml or /etc/pin-sync.yml";
}

if (!exists($cfg->{Hausbus}) || !exists($cfg->{MySQL})) {
    die "Configuration sections incomplete: need Hausbus and MySQL";
}

my @waiting_updates = ();
my $retry = 0;

# Returns EEPROM contents (as binary string) for the given array of 6-digit
# PINs.
sub generate_eeprom {
    my @pins = @_;

    my $num_pins = scalar @pins;
    my $num_blocks = ceil($num_pins / PINS_PER_BLOCK);
    my $eeprom = pack('C', $num_pins);

    # Put all PINs in one long string, pad with zeros.
    my $pinstring = join('', @pins) . ("000000" x 5);

    for my $idx (1 .. $num_blocks) {
        # Get one block of PINs.
        my $block = substr($pinstring, 0, 6 * PINS_PER_BLOCK, '');

        # Hex-encode the PINs
        $block = pack('H*', $block);

        # Calculate the CRC32 checksum and append it (big endian).
        $block .= pack('N', crc32($block));

        $eeprom .= $block;
    }

    # Calculate the CRC32 for the whole EEPROM and prepend it (big endian).
    return pack('N', crc32($eeprom)) . $eeprom;
}

sub generate_updates {
    my ($bytes) = @_;

    my @updates = ();
    for my $idx (0 .. (length($bytes) / 8)) {
        my $block = substr($bytes, 0, 8, '');
        my $update = 'E' .
                     pack('n', ($idx * 8)) .
                     pack('C', length($block)) .
                     $block;
        $update .= pack('N', crc32($update));
        push @updates, $update;
    }
    return @updates;
}

sub prefix {
    strftime("%x %X - ", gmtime())
}

sub crc_to_hex {
    sprintf('0x%04x', unpack('N', $_[0]))
}

# Eliminates updates to minimize the amount of communication/EEPROM writes.
# Since we know the current Pinpad CRC, we just strip off the latest PINs,
# generate updates for that subset and see if this is what’s currently stored
# in the Pinpad EEPROM. If so, we filter out all updates which are duplicates
# -- only the first block (since it contains the number of PINs and EEPROM CRC)
# and the last block should remain.
sub eliminate_updates {
    my ($pinpad_crc, @pins) = @_;

    # We try stripping off up to 5 pins, but if that did not work, either this
    # script was not run for a long time or the EEPROM was corrupetd.
    for my $tries (1 .. 5) {
        pop @pins;
        my $eeprom = generate_eeprom(@pins);
        my $eeprom_crc = crc_to_hex(substr($eeprom, 0, 4));
        if ($eeprom_crc eq $pinpad_crc) {
            syslog('info', "Generated EEPROM state for current CRC32");

            # Only keep updates which were not already pushed previously.
            my @updates = generate_updates($eeprom);
            my $before = scalar @waiting_updates;
            @waiting_updates = grep { !($_ ~~ @updates) } @waiting_updates;
            my $eliminated = $before - @waiting_updates;
            syslog('info', "Eliminated $eliminated redundant updates.");
            return;
        }
    }

    syslog('info', "Could not generate EEPROM state for current CRC32.");
    syslog('info', "This hints EEPROM corruption on the Pinpad controller!");
}

# Pushes the first waiting update to the Pinpad controller.
sub push_update {
    if (@waiting_updates == 0) {
        syslog('info', "All updates pushed successfully.");
        return;
    }

    syslog('info', "Pushing update to Pinpad controller (" .
        (scalar @waiting_updates) . " updates remaining)");
    my $update = $waiting_updates[0];
    http_post 'http://' . $cfg->{Hausbus}->{host} . '/send/pinpad',
        $json->encode({ payload => $update }),
        sub {
            my ($data, $headers) = @_;
            my $status = $headers->{Status};
            if ($status ne '200') {
                syslog('info', "Server returned HTTP $status: $headers->{Reason}");
                return;
            }
            my $reply;
            try {
                $reply = $json->decode($data);
            } catch {
                warn "Server returned invalid JSON";
                return;
            };
            if ($reply->{status} ne 'ok') {
                syslog('info', "Server returned error: $reply->{status}");
                return;
            }

            syslog('info', "Update pushed to Pinpad via Hausbus");
            # TODO: add timeout timer
        };
}

sub run {
    openlog('pin-sync', 'pid', 'daemon');
    syslog('info', 'Starting up');

    my $stream;
    $stream = AnyEvent::HTTP::Stream->new(
        url => 'http://' . $cfg->{Hausbus}->{host} . '/group/pinpad',
        on_data => sub {
            my ($data) = @_;

            my $pkt = decode_json($data);
            return unless exists $pkt->{payload};
            my $payload = $pkt->{payload};

            # The pinpad-controller broadcasts the CRC32 checksum of its EEPROM
            # contents.
            if ($payload =~ /^X /) {
                # Ignore checksum broadcasts while we are updating the EEPROM.
                return if @waiting_updates > 0;

                # Generate the Pinpad and database CRC32.
                my $pinpad_crc = crc_to_hex(substr($payload, 2, 4));
                syslog('info', "Connecting to MySQL database...");
                my $db = DBI->connect(
                    $cfg->{MySQL}->{data_source},
                    $cfg->{MySQL}->{user},
                    $cfg->{MySQL}->{pass},
                ) or die "Could not connect to MySQL database: $!";
                my $pins = $db->selectcol_arrayref(
                    q|SELECT pin FROM nutzer WHERE pin IS NOT NULL|,
                    { Slice => {} });
                my $eeprom = generate_eeprom(@$pins);
                my $eeprom_crc = crc_to_hex(substr($eeprom, 0, 4));
                syslog('info', "Pinpad-Controller  EEPROM CRC32 is $pinpad_crc");
                syslog('info', "Database generated EEPROM CRC32 is $eeprom_crc");

                # If the CRC32 checksums are equal, we are done.
                return if ($eeprom_crc eq $pinpad_crc);

                # Otherwise: Fill @waiting_updates and start updating.
                @waiting_updates = generate_updates($eeprom);
                eliminate_updates($pinpad_crc, @$pins);
                push_update();
            }

            if ($payload =~ /^EEP /) {
                my $status = substr($payload, 4);
                syslog('info', "EEPROM write command status: $status");
                if ($status ne 'ACK') {
                    $retry++;
                    if ($retry > 5) {
                        syslog('info', "ERROR: EEPROM write failed more than five times.");
                        syslog('info', "Hausbus corruption is unlikely five times in a row.");
                        syslog('info', "This probably is a bug?");
                        syslog('info', "Exiting now, please fix this manually.");
                        exit 1;
                    }
                    syslog('info', "EEPROM write command failed. Re-trying ($retry/5)...");
                    push_update();
                } else {
                    $retry = 0;
                    shift @waiting_updates;
                    push_update();
                }
            }
        });

    syslog('info', "pin-sync initialized...");
    AE::cv->recv
}

1

__END__


=head1 NAME

RaumZeitPinSync - Syncs PINs to the Pinpad controller EEPROM

=head1 DESCRIPTION

This module synchronizes our user-specific PINs to the Pinpad controller
EEPROM.

=head1 VERSION

Version 1.0

=head1 AUTHOR

Michael Stapelberg, C<< <michael at stapelberg.de> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2011 Michael Stapelberg.

This program is free software; you can redistribute it and/or modify it
under the terms of the BSD license.

=cut
