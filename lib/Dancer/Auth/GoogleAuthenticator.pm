package Dancer::Auth::GoogleAuthenticator;
use Dancer ':syntax';

our $VERSION = '0.01';

my %users = (
    { name => 'test',
      pass => 'test',
      otp_secret => 'abcde12345',
    },
    { name => 'test2',
      pass => 'test2',
      otp_secret => '',
    },
    { name => 'admin',
      pass => 'admin',
      otp_secret => 'abcde123456',
    },
);

# Map a user to its authenticator
sub get_otp_auth {
    my ($user) = @_;
    
    return unless $user;
    
    my ($otp_secret) = $users{$user}->{otp_secret};
    if( $otp_secret ) {
        return Authen::GoogleAuthenticator->new( secret => $otp_secret );
    };
    return
};

get '/' => sub {
    template 'index', {
        user => session('user'),
        twofactor_active => get_otp_auth(session('user')),
        twofactor_available => session('twofactor'),
    };
};

# Force authentication for all non-index pages
before '/' => sub {
    ...
};

get '/auth/setup' => sub {
    my ($user) = session->{user};
    
    my ($otp_secret) = $users{$user}->{otp_secret};
    my $auth = get_otp_auth( $user );
    
    # Display otp_secret if we have it
    # XXX Maybe this should be over SSH only
    template 'setup_otp', {
        otp_secret => $otp_secret
    };
}

post '/auth/setup' => sub {
    my ($user) = session->{user};
    
    my $enable= params->{enable_otp};
    my $have_otp= $users{ $user }->{otp_secret};
    
    if( !$enable and $have_otp ) {
        delete $users{ $user }->{otp_secret};
    } else {
        # Make up random OTP secret
        # XXX Should be configurable/callback
        my @letters = ('a'..'z','0'..'9');
        $users{ $user }->{otp_secret} = map { $letters[rand @letters]} 1..16;
    };
    
    redirect '/auth/setup';
}

get '/auth/login' => sub {
    my $return = params->{return} || '';
    template 'login', { return => params->{return} };
}

# Maybe also have "requires('password')"
#                 "requires('twofactor')"
post '/auth/login' => sub {
    my ($user_id,$pass,$otp) = params->{user}, params->{pass}, params->{otp};
    my $return = params->{return} || '';
    
    my $user = $users{ $user_id };
    
    if( $pass eq $user->{pass} ) {
        my $auth_twofactor= get_otp_auth( $user );
        if( $auth_twofactor ) {
            # Check OTP in addition to password
            if( 1 == $auth->verify( $otp )) {
                session 'user' => $user;
                session 'twofactor' => 1;
            } else {
                # Log the failure
                # Increment a failure counter for that user
                # Increment a failure counter for that IP
                # Increment a failure counter overall, to detect clock skew
            };
        } else {
            session 'user' => $user;
            session 'twofactor' => 0;
        };
    };
    
    return redirect $return
        if( session('user') and $return );
    template 'login';
}

get '/auth/logout' => sub {
    session('user', undef);
};

true;

=head1 SEE ALSO

L<http://stackoverflow.com/questions/549/the-definitive-guide-to-forms-based-website-authentication>

=cut