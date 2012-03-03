use Test::More tests => 2;
use strict;
use warnings;

# the order is important
use RaumZeitLabor::BenutzerDB;
use Dancer::Test;

route_exists [GET => '/BenutzerDB/'], 'a route handler is defined for /';
response_status_is ['GET' => '/BenutzerDB/'], 200, 'response status is 200 for /';
