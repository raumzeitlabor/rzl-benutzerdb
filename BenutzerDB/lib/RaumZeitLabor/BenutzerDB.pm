# vim:ts=4:sw=4:expandtab
package RaumZeitLabor::BenutzerDB;
use Dancer ':syntax';
use Dancer::Plugin::Database;
use Data::Dumper;
use Crypt::SaltedHash;

our $VERSION = '1.0';

my $login_url = qr#^/BenutzerDB/my(/?|$)#;
my $admin_url = qr#^/BenutzerDB/admin/?#;

hook before => sub {
    my $user = session('user');
    my $logged_in = defined($user);
    my $is_admin = ($logged_in ? is_admin($user) : 0);

    vars->{user} = $user;
    vars->{logged_in} = $logged_in;
    vars->{is_admin} = $is_admin;

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

=head2 is_admin($handle)

Returns true if and only if the given $handle has admin rights.

=cut
sub is_admin {
    my ($user) = @_;

    my $entry = database->quick_select('nutzer', { handle => $user });
    return 0 unless defined($entry);
    return $entry->{admin};
}

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

    debug "login attempt with user = $user and pass = $pass";

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

get '/BenutzerDB/my/pin' => sub {
    my $db = database;
    my $entry = $db->quick_select('nutzer', { handle => session('user') });
    my @admins = $db->quick_select('nutzer', { admin => 1 }, { order_by => 'handle' });
    my $pin = $entry->{pin};
    return template 'mypin', { pin => $pin, admins => \@admins };
};

get '/BenutzerDB/admin/users' => sub {
    my @entries = database->quick_select('nutzer', {}, { order_by => 'handle' });
    return template 'admin_users', { users => \@entries };
};

get '/BenutzerDB/admin/setpin' => sub {
    my @entries = database->quick_select('nutzer', { pin => undef });
    return template 'admin_setpin', { users => \@entries };
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
    my @entries = database->quick_select('nutzer', {});
    return template 'admin_revokepin', { users => \@entries };
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
