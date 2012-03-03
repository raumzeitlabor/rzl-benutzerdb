# vim:ts=4:sw=4:expandtab
package BenutzerDB;
use Dancer ':syntax';
use Dancer::Plugin::Database;
use Data::Dumper;
use Crypt::SaltedHash;

our $VERSION = '0.1';

my $login_url = qr#^/BenutzerDB/my(/?|$)#;
my $admin_url = qr#^/BenutzerDB/admin/?#;

before sub {
    my $user = session('user');
    my $logged_in = defined($user);
    my $is_admin = ($logged_in ? is_admin($user) : 0);

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
        return template 'index', { user => session('user'), admin => is_admin(session('user')) };
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
    my $user = session('user');

    my $entry = $db->quick_select('nutzer', { handle => $user });
    debug 'entry = ' . Dumper($entry);
    my $pin = $entry->{pin};
    return template 'mypin', { user => $user, pin => $pin, admin => is_admin($user) };
};

get '/BenutzerDB/admin/users' => sub {
    my $db = database;
    my $user = session('user');

    my @entries = $db->quick_select('nutzer', {});

    return template 'admin_users', {
        user => $user,
        admin => is_admin($user),
        users => \@entries
    };
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
