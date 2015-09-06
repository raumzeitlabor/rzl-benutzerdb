package RaumZeitLabor::Apache::BenutzerDBAuthenticator;
use strict;
use warnings;

use Apache2::Access;
use Apache2::RequestUtil;
use Apache2::RequestRec;

use Apache2::Const qw(:log :common :http);
use Apache2::Log;

use DBI;
use Crypt::SaltedHash;

my %conf;
sub global_config {
    %conf = @_;
}

sub handler {
    my $r = shift;

    my ($status, $password) = $r->get_basic_auth_pw;

    # abort if no/unsupported auth is provided
    if ($status != OK) {
        $r->note_basic_auth_failure;
        return $status;
    }

    # user is only set after a successful call to get_basic_auth_pw()
    my $user = $r->user;
    my $crypt = fetch_crypt($user);

    if ($crypt and Crypt::SaltedHash->validate($crypt, $password)) {
        return OK;
    }

    $r->note_basic_auth_failure;
    return HTTP_UNAUTHORIZED;
}

sub fetch_crypt {
    my ($user) = @_;

    my $dsn = "DBI:mysql:database=$conf{database};host=$conf{host}";
    my $dbh = DBI->connect($dsn, $conf{user}, $conf{password}, { RaiseError => 1 });
    my $sth = $dbh->prepare("SELECT passwort FROM $conf{table} WHERE handle = ?");
    $sth->execute($user);

    my ($crypt) = $sth->fetchrow_array;
    $sth->finish;

    $dbh->disconnect;

    return $crypt;
}
1;
# vim: set sts=4 ts=4 sw=4 expandtab:  

