#!perl -w
use strict;
use Auth::GoogleAuthenticator;

my $auth = Auth::GoogleAuthenticator->new( secret => 'test@example.com');
warn $auth->registration_key();
warn $auth->totp();
warn "Print these out:";
warn join " ", @{$auth->{hotp}};
warn $auth->verify( shift );