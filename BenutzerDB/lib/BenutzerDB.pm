# vim:ts=4:sw=4:expandtab
package BenutzerDB;
use Dancer ':syntax';
use Dancer::Plugin::Database;
use Data::Dumper;
use Crypt::SaltedHash;

our $VERSION = '0.1';

before sub {
    # Redirect to login page if necessary (for /my and /admin)
    if (not session('user') and
        (request->path_info =~ q,^/BenutzerDB/my(/?|$), or
         request->path_info =~ q,^/BenutzerDB/admin(/?|$),)) {
        var requested_path => request->path_info;
        request->path_info('/BenutzerDB/');
    }
};

#
# displays the login form for invalid sessions and in index page for
# valid sessions
#
get '/BenutzerDB/' => sub {
    if (not session('user')) {
        return template 'login';
    } else {
        return template 'index', { user => session('user') };
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
    return template 'mypin', { user => $user, pin => $pin };
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
