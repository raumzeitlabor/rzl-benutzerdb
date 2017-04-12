# vim:ts=4:sw=4:expandtab
package RaumZeitLabor::BenutzerDB;
use Dancer ':syntax';
use Dancer::Plugin::Database;
use DateTime::Event::Recurrence;
use Crypt::SaltedHash;
use Net::Domain qw/hostfqdn/;

our $VERSION = '1.2';

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

        # force users to update their data if necessary
        if (request->path_info !~ qr#^/BenutzerDB/(css|images|fonts|logout)#
              && request->path_info !~ qr#^/BenutzerDB/my/data/?$#
              && !defined $entry->{realname}) {
            redirect '/BenutzerDB/my/data';
        }
    }

    # Save the state in vars so that we can use it in templates.
    vars->{user} = lc $user;
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

get '/BenutzerDB/css/bootstrap.css' => sub {
    send_file 'css/bootstrap.css';
};

get '/BenutzerDB/images/logo.png' => sub {
    send_file 'images/logo.png';
};

get '/BenutzerDB/images/logowhite.png' => sub {
    send_file 'images/logowhite.png';
};

get '/BenutzerDB/fonts/droid-sans.woff' => sub {
    send_file 'fonts/droid-sans.woff';
};

get '/BenutzerDB/fonts/droid-sans-bold.woff' => sub {
    send_file 'fonts/droid-sans-bold.woff';
};

#
# displays the login form for invalid sessions and in index page for
# valid sessions
#
get '/BenutzerDB/' => sub {
    if (not session('user')) {
        return template 'login', {}, { layout => 'login' };
    } else {
        return template 'index', { title => 'Willkommen' };
    }
};

get '/BenutzerDB/login' => sub {
    redirect '/BenutzerDB/';
};

post '/BenutzerDB/login' => sub {
    return redirect '/BenutzerDB/' unless exists params->{username} && exists params->{password};

    my $user = params->{username};
    my $pass = params->{password};
    my $db = database;

    my $entry = $db->quick_select('nutzer', { handle => $user });
    if (!defined($entry) ||
        !Crypt::SaltedHash->validate($entry->{passwort}, $pass)) {
        return template 'login', { error => 'Falscher Username/Password' }, { layout => 'login' };
    }

    session user => lc $entry->{handle};

    redirect '/BenutzerDB/';
};

any '/BenutzerDB/logout' => sub {
    session user => undef;
    redirect '/BenutzerDB/';
};

get '/BenutzerDB/changepw' => sub {
    return template 'changepw', { title => 'Passwort ändern' };
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

get '/BenutzerDB/my/data' => sub {
    my $db = database;
    my $entry = $db->quick_select('nutzer', { handle => session('user') });
    return template 'mydata', { title => 'Deine Daten', u => $entry };
};

post '/BenutzerDB/my/data' => sub {
    my $db = database;
    my $entry = $db->quick_select('nutzer', { handle => session('user') });

    my $hash = {};
    $hash->{realname} = params->{'realname'} unless $entry->{realname};
    $hash->{email}    = params->{'email'} if length (params->{'email'} =~ s/\s+//rg) > 0;

    $db->quick_update('nutzer', { handle => session('user') }, $hash) if keys %{$hash};

    $entry = $db->quick_select('nutzer', { handle => session('user') });
    return template 'mydata', { title => 'Deine Daten', u => $entry };
};

get '/BenutzerDB/my/pin' => sub {
    my $db = database;
    my $entry = $db->quick_select('nutzer', { handle => session('user') });
    my @admins = $db->quick_select('nutzer', { admin => 1 }, { order_by => 'handle' });
    my $pin = $entry->{pin};
    my $expiry = $entry->{pin_expiry};
    return template 'mypin', { title => 'Deine PIN', pin => $pin, expiry => $expiry, admins => \@admins };
};

get '/BenutzerDB/my/devices' => sub {
    my $db = database;
    my $current = $db->quick_select('leases', { ip => request->env->{'HTTP_X_FORWARDED_FOR'} });
    my @devices = $db->quick_select('devices', { handle => session('user') });

    # this does not work due to proxying
    #((my $intern_url = request->uri_base) =~ s/\.raumzeitlabor\.de\//.rzl\//);

    # use fqdn instead
    my $intern_url = hostfqdn;

    return template 'mydevices', {
        title => 'Deine Netzwerkgeräte',
        current => $current,
        intern_url => '//'.$intern_url.request->path_info,
        devices => \@devices,
    };
};

post '/BenutzerDB/my/devices/add' => sub {
    my $db = database;
    my $host  = params->{'hostname'};
    my $mac = params->{'mac'};
    my $update = params->{'updatelastseen'};

    if ($host eq '') {
        return template 'error', { errormessage => 'Keinen Hostname angegeben' };
    }
    if ($mac !~ m/[a-f0-9]{2}(?::[a-f0-9]{2}){5}/i) {
        return template 'error', { errormessage => 'Keine/ungültige MAC-Adresse angegeben' };
    }

    my $mac_exists = $db->quick_select('devices', { handle => session('user'), mac => lc $mac });
    if ($mac_exists) {
        return template 'error', { errormessage => 'MAC ist bereits registriert' };
    }

    my $mac_is_valid = $db->quick_select('leases', { mac => lc $mac });
    unless ($mac_is_valid) {
        return template 'error', { errormessage => 'MAC passt nicht zum Gerät' };
    }

    $db->quick_insert('devices', {
        handle => lc session('user'),
        name => $host,
        mac => lc $mac,
        updatelastseen => $update ? 1 : 0,
    });

    redirect '/BenutzerDB/my/devices';
};

get '/BenutzerDB/my/devices/delete/:fmac' => sub {
    my $mac = join(":", param('fmac') =~ m/[a-f0-9]{2}/g);
    database->quick_delete('devices', { handle => session('user'), mac => lc $mac });
    redirect '/BenutzerDB/my/devices';
};

get '/BenutzerDB/my/sshkeys/:what' => sub {
    # The what parameter in the URL is there to distinguish between different
    # things, should that ever become necessary.
    my @keys = database->quick_select('sshpubkeys', { handle => session('user') });
    return template 'mysshkeys', { title => 'SSH public-keys zum Öffnen der Tür', pubkeys => \@keys };
};

post '/BenutzerDB/my/sshkeys/add' => sub {
    # We need to validate the key carefully.

    # Therefore, let's first make sure only members are able to add keys.
    unless (vars->{has_pin}) {
        return template 'error', { errormessage => 'No authorization to add a key.' };
    }

    # It will end up verbatim in the .ssh/authorized_keys on the firebox and
    # might allow local user access (shouldn’t be critical, but nevertheless!).
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
            n.pin IS NOT NULL
            AND (n.pin_expiry IS NULL OR n.pin_expiry > NOW())|
        , { Slice => {} });

    return to_json $keys;
};

get '/BenutzerDB/pins/:what' => sub {
    my $http_auth = request->env->{HTTP_AUTHORIZATION};
    if (defined($http_auth) && $http_auth =~ /^Basic (.*)$/) {
        my ($user, $password) = split(/:/, (MIME::Base64::decode($1) || ':'));
        if (!defined($user) ||
            !defined($password) ||
            $user ne setting('pins_user') ||
            $password ne setting('pins_pass')) {
            status 401;
            header 'WWW-Authenticate' => 'Basic realm="Password Required"';
            return 'Authorization required';
        }
    } else {
        status 401;
        header 'WWW-Authenticate' => 'Basic realm="Password Required"';
        return 'Authorization required';
    }

    my $pins = database->selectall_arrayref(q|
        SELECT
            handle,
            pin
        FROM
            nutzer
        WHERE pin IS NOT NULL
            AND (pin_expiry IS NULL OR pin_expiry > NOW())
        ORDER BY id ASC|,
        { Slice => {} });

    return to_json($pins, {canonical => 1});
};

get '/BenutzerDB/admin/users' => sub {
    my @entries = database->quick_select('nutzer', {}, { order_by => 'handle' });
    return template 'admin_users', { title => 'Benutzerliste', users => \@entries };
};

get '/BenutzerDB/admin/setpin' => sub {
    my $entries = database->selectall_arrayref('SELECT * FROM nutzer WHERE pin IS NULL ORDER BY handle', { Slice => {} });
    # Enable this line as soon as the bug in Dancer::Plugin::Database is fixed:
    # https://github.com/bigpresh/Dancer-Plugin-Database/pull/27
    #my @entries = database->quick_select('nutzer', { pin => undef }, { order_by => 'handle' });
    return template 'admin_setpin', { title => 'PIN zuweisen', users => $entries };
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
        #
        # We also require PINs to be unique for various reason, most importantly for
        # self-provisioning of cashpoint tokens.
        my $pin_exists = defined database->quick_select('nutzer', { pin => $pindigits });
        $pin_bad = ($pindigits =~ /23/ ||
                    $pindigits =~ /42/ ||
                    $pindigits =~ /1337/ ||
                    $pindigits =~ /17/ ||
                    $pin_exists);
        close($rndfh);
    }

    $db->quick_update('nutzer', { handle => $handle }, {
        pin => $pindigits,
        pin_expiry => undef,
    });

    return template 'admin_setpin_success', { handle => $handle };
};

get '/BenutzerDB/admin/revokepin' => sub {
    my $entries = database->selectall_arrayref(
        'SELECT * FROM nutzer WHERE pin IS NOT NULL ORDER BY handle',
        { Slice => {} });
    return template 'admin_revokepin', { title => 'PIN revoken', users => $entries };
};

get '/BenutzerDB/admin/revokepin/:handle' => sub {
    forward '/BenutzerDB/admin/revokepin/'.params->{handle}.'/now';
};

get '/BenutzerDB/admin/revokepin/:handle/:when' => sub {
    my $entry = database->quick_select('nutzer', { handle => param('handle') });

    my $when = params->{when};
    if ($when eq 'deferred') {
        # 3 Wochen Kündigungsfrist zum Ende des Quartals
        my $dt = DateTime->now;
        $dt->add( end_of_month => 'wrap', weeks => 3 );

        my $fiscal = monthly DateTime::Event::Recurrence( interval => 3 );
        $when = $fiscal->next( $dt );
    }

    return template 'admin_revokepin_confirm', {
        handle => $entry->{handle},
        when   => $when,
    };
};

post '/BenutzerDB/admin/revokepin/:handle' => sub {
    forward '/BenutzerDB/admin/revokepin/'.params->{handle}.'/now';
};

post '/BenutzerDB/admin/revokepin/:handle/:when' => sub {
    my $handle = param('handle');

    my $when = params->{when};
    if ($when eq 'deferred') {
        my $fiscal = monthly DateTime::Event::Recurrence( interval => 3 );
        $when = $fiscal->next( DateTime->today );
        database->quick_update('nutzer', { handle => $handle }, {
            pin_expiry => $when,
        });
    } else {
        database->quick_update('nutzer', { handle => $handle }, {
            pin => undef,
            pin_expiry => DateTime->now,
        });
        database->quick_delete('sshpubkeys', { handle => $handle });
    }

    return template 'admin_revokepin_success', {
        handle => $handle,
        when => $when,
    };
};

get '/BenutzerDB/register' => sub {
    template 'register', { title => 'Registration' }, { layout => 'login' };
};

post '/BenutzerDB/register' => sub {
    if (!exists params->{reg_username} ||
        !exists params->{reg_password}) {
        return template 'register', { title => 'Registration', error => 'Nutzername/Passwort fehlen' };
    }
    my $user = lc params->{reg_username};
    my $real = params->{reg_realname};
    my $pass = params->{reg_password};
    my $db = database;

    if (length($user) < 1) {
        return template 'register', { title => 'Registration', error => 'Nutzername zu kurz' }, { layout => 'login' };
    }

    if (length($real) < 1) {
        return template 'register', { title => 'Registration', error => 'Realname zu kurz' }, { layout => 'login' };
    }

    if (length($pass) < 6) {
        return template 'register', { title => 'Registration', error => 'Passwort zu kurz' }, { layout => 'login' };
    }

    my $entry = $db->quick_select('nutzer', { handle => $user });
    if (defined($entry)) {
        return template 'register', { title => 'Registration', error => 'Nutzername schon vergeben!' }, { layout => 'login' };
    }

    my $csh = Crypt::SaltedHash->new(algorithm => 'SHA-1');
    $csh->add($pass);
    my $hash = $csh->generate;

    $db->quick_insert('nutzer', {
        handle => $user,
        realname => $real,
        passwort => $hash,
        admin => 0
    });

    session user => lc $user;

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

Version 1.2

=head1 AUTHOR

Michael Stapelberg, C<< <michael at stapelberg.de> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2011-2012 Michael Stapelberg.
Copyright 2013-2014 Simon Elsbrock.

This program is free software; you can redistribute it and/or modify it
under the terms of the BSD license.

=cut
