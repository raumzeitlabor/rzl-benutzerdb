# vim:ts=4:sw=4:expandtab
package RaumZeitLabor::BenutzerDB;
use Dancer ':syntax';
use Dancer::Plugin::Database;
use Data::Dumper;
use Crypt::SaltedHash;

our $VERSION = '1.1';

my $login_url = qr#^/BenutzerDB/my(/?|$)#;
my $admin_url = qr#^/BenutzerDB/admin/?#;

hook before => sub {
    my $user = session('user');
    my $logged_in = defined($user);
    my $is_admin = 0;
    my $has_pin = 0;

    if ($logged_in) {
        my $entry = database->quick_select('nutzer', { handle => $user });
        $is_admin = $entry->{admin};
        $has_pin = defined($entry->{pin});
    }

    # Save the state in vars so that we can use it in templates.
    vars->{user} = $user;
    vars->{logged_in} = $logged_in;
    vars->{is_admin} = $is_admin;
    vars->{has_pin} = $has_pin;

    # Redirect to login page if necessary:
    # Either the user is not logged in but requests a URL for which you need to
    # be logged in (/BenutzerDB/my/*).
    # Or the user is not an admin but requests a URL for which you need to be
    # an admin (/BenutzerDB/admin/*).
    if ((!$logged_in && request->path_info =~ $login_url) ||
        (!$is_admin && request->path_info =~ $admin_url)) {
        var requested_path => request->path_info;
        request->path_info('/BenutzerDB/');
    }
};

get '/BenutzerDB/css/style.css' => sub {
    send_file 'css/style.css';
};

get '/BenutzerDB/images/logo.png' => sub {
    send_file 'images/logo.png';
};

#
# displays the login form for invalid sessions and in index page for
# valid sessions
#
get '/BenutzerDB/' => sub {
    if (not session('user')) {
        return template 'login';
    } else {
        return template 'index';
    }
};

post '/BenutzerDB/login' => sub {
    return redirect '/BenutzerDB/' unless exists params->{username} && exists params->{password};

    my $user = params->{username};
    my $pass = params->{password};
    my $db = database;

    my $entry = $db->quick_select('nutzer', { handle => $user });
    if (!defined($entry) ||
        !Crypt::SaltedHash->validate($entry->{passwort}, $pass)) {
        return template 'login', { error => 'Falscher Username/Password' };
    }

    session user => $user;

    redirect '/BenutzerDB/';
};

any '/BenutzerDB/logout' => sub {
    session user => undef;
    redirect '/BenutzerDB/';
};

get '/BenutzerDB/changepw' => sub {
    return template 'changepw';
};

post '/BenutzerDB/changepw' => sub {
    my $db = database;
    my $old = params->{oldpw};
    my $new = params->{newpw};
    my $new2 = params->{newpw2};
    my $handle = session('user');

    my $entry = $db->quick_select('nutzer', { handle => $handle });
    if (!defined($entry) ||
        !Crypt::SaltedHash->validate($entry->{passwort}, $old)) {
        return template 'error', { errormessage => 'Falscher Username/Password' };
    }

    if ($new eq '') {
        return template 'error', { errormessage => 'Kein neues Passwort angegeben' };
    }

    if ($new ne $new2) {
        return template 'error', { errormessage => 'Altes und neues Passwort stimmen nicht überein' };
    }

    my $csh = Crypt::SaltedHash->new(algorithm => 'SHA-1');
    $csh->add($new);
    my $hash = $csh->generate;

    $db->quick_update('nutzer', { handle => $handle }, { passwort => $hash });

    return template 'changepw_success';
};

get '/BenutzerDB/my/pin' => sub {
    my $db = database;
    my $entry = $db->quick_select('nutzer', { handle => session('user') });
    my @admins = $db->quick_select('nutzer', { admin => 1 }, { order_by => 'handle' });
    my $pin = $entry->{pin};
    return template 'mypin', { pin => $pin, admins => \@admins };
};

get '/BenutzerDB/my/sshkeys/:what' => sub {
    # The what parameter in the URL is there to distinguish between different
    # things, should that ever become necessary.
    my @keys = database->quick_select('sshpubkeys', { handle => session('user') });
    return template 'mysshkeys', { pubkeys => \@keys };
};

post '/BenutzerDB/my/sshkeys/add' => sub {
    # We need to validate the key carefully. It will end up verbatim in the
    # .ssh/authorized_keys on the firebox and might allow local user access
    # (shouldn’t be critical, but nevertheless!).
    my $pubkey = param('pubkey');
    if (!($pubkey =~ /^ssh-([a-z]+)/)) {
        return template 'mysshkeys_add_error', {
            errormessage => 'Key does not start with ssh-rsa or similar.',
            pubkey => $pubkey
        };
    }
    if (!($pubkey =~ /^ssh-([a-z]+) ([A-Za-z0-9\/\+]+)=*/)) {
        return template 'mysshkeys_add_error', {
            errormessage => 'Key is not valid base64.',
            pubkey => $pubkey
        };
    }
    my ($type, $base64, $trailing) = ($pubkey =~ /^ssh-([a-z]+) ([A-Za-z0-9\/\+]+)(=*)/);
    my $sanitized_key = "ssh-$type $base64$trailing";
    database->quick_insert('sshpubkeys', { handle => session('user'), pubkey => $sanitized_key });
    redirect '/BenutzerDB/my/sshkeys/tuer';
};

get '/BenutzerDB/my/sshkeys/remove/:keyid' => sub {
    # Verify that this SSH key actually belongs to the user :).
    my $entry = database->quick_select('sshpubkeys', { keyid => param('keyid') });
    if (!defined($entry) || $entry->{handle} ne session('user')) {
        send_error("Not allowed", 403);
    } else {
        return template 'mysshkeys_remove_confirm', {
            keyid => param('keyid'),
            pubkey => $entry->{pubkey},
        };
    }
};

post '/BenutzerDB/my/sshkeys/remove/:keyid' => sub {
    # The following query is a no-op if the specified key doesn’t belong to the
    # user.
    database->quick_delete('sshpubkeys', { keyid => param('keyid'), handle => session('user') });
    redirect '/BenutzerDB/my/sshkeys/tuer';
};

get '/BenutzerDB/sshkeys/:what' => sub {
    my $keys = database->selectall_arrayref(q|
        SELECT
            k.handle,
            k.keyid,
            k.pubkey
        FROM
            sshpubkeys AS k LEFT JOIN
            nutzer AS n ON k.handle = n.handle
        WHERE
            n.pin IS NOT NULL|
        , { Slice => {} });

    return to_json $keys;
};

get '/BenutzerDB/admin/users' => sub {
    my @entries = database->quick_select('nutzer', {}, { order_by => 'handle' });
    return template 'admin_users', { users => \@entries };
};

get '/BenutzerDB/admin/setpin' => sub {
    my $entries = database->selectall_arrayref('SELECT * FROM nutzer WHERE pin IS NULL ORDER BY handle', { Slice => {} });
    # Enable this line as soon as the bug in Dancer::Plugin::Database is fixed:
    # https://github.com/bigpresh/Dancer-Plugin-Database/pull/27
    #my @entries = database->quick_select('nutzer', { pin => undef }, { order_by => 'handle' });
    return template 'admin_setpin', { users => $entries };
};

get '/BenutzerDB/admin/setpin/:handle' => sub {
    my $entry = database->quick_select('nutzer', { handle => param('handle') });
    return template 'admin_setpin_confirm', { handle => $entry->{handle} };
};

post '/BenutzerDB/admin/setpin/:handle' => sub {
    my $db = database;
    my $handle = param('handle');

    # Verify that the user doesn’t have a PIN yet — we don’t want to overwrite
    # an existing PIN, no matter what.
    my $entry = $db->quick_select('nutzer', { handle => $handle });
    if (!defined($entry)) {
        return template 'error', { errormessage => 'No such handle' };
    }

    if (defined($entry->{pin})) {
        return template 'error', { errormessage => 'This user already has a PIN.' };
    }

    # Generate a PIN by using the better random data (/dev/random).
    my $pin_bad = 1;
    my $pindigits = undef;
    while ($pin_bad) {
        open(my $rndfh, '<', '/dev/random') or die "Could not open /dev/random: $!";
        # Read 6 bytes, then take each byte modulo 10 to get digits.
        my $pinbytes;
        read($rndfh, $pinbytes, 6);
        $pindigits = join '', map { ord($_) % 10 } split //, $pinbytes;

        # Blacklist a few sequences which nerds are likely to try.
        $pin_bad = ($pindigits =~ /23/ ||
                    $pindigits =~ /42/ ||
                    $pindigits =~ /1337/ ||
                    $pindigits =~ /17/);
        close($rndfh);
    }

    $db->quick_update('nutzer', { handle => $handle }, { pin => $pindigits });

    return template 'admin_setpin_success', { handle => $handle };
};

get '/BenutzerDB/admin/revokepin' => sub {
    my $entries = database->selectall_arrayref(
        'SELECT * FROM nutzer WHERE pin IS NOT NULL ORDER BY handle',
        { Slice => {} });
    return template 'admin_revokepin', { users => $entries };
};

get '/BenutzerDB/admin/revokepin/:handle' => sub {
    my $entry = database->quick_select('nutzer', { handle => param('handle') });
    return template 'admin_revokepin_confirm', { handle => $entry->{handle} };
};

post '/BenutzerDB/admin/revokepin/:handle' => sub {
    my $handle = param('handle');
    database->quick_update('nutzer', { handle => $handle }, { pin => undef });
    return template 'admin_revokepin_success', { handle => $handle };
};

get '/BenutzerDB/register' => sub {
    template 'register';
};

post '/BenutzerDB/register' => sub {
    if (!exists params->{reg_username} ||
        !exists params->{reg_password}) {
        return template 'register', { error => 'Nutzername/Passwort fehlen' };
    }
    my $user = params->{reg_username};
    my $pass = params->{reg_password};
    my $db = database;

    if (length($pass) < 6) {
        return template 'register', { error => 'Passwort zu kurz' };
    }

    my $entry = $db->quick_select('nutzer', { handle => $user });
    if (defined($entry)) {
        return template 'register', { error => 'Nutzername schon vergeben!' };
    }

    my $csh = Crypt::SaltedHash->new(algorithm => 'SHA-1');
    $csh->add($pass);
    my $hash = $csh->generate;

    $db->quick_insert('nutzer', { handle => $user, passwort => $hash });

    session user => $user;

    redirect '/BenutzerDB/';
};

true;

__END__


=head1 NAME

RaumZeitBenutzerDB - Benutzer-Datenbank für das Pinpad und andere Dienste

=head1 DESCRIPTION

Dieses Modul ist das Webinterface zur Benutzer-Datenbank für das Pinpad und
andere Dienste (Kassensystem, ...).

=head1 VERSION

Version 1.0

=head1 AUTHOR

Michael Stapelberg, C<< <michael at stapelberg.de> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2011-2012 Michael Stapelberg.

This program is free software; you can redistribute it and/or modify it
under the terms of the BSD license.

=cut
