package Dancer::Auth::GoogleAuthenticator;
use Dancer ':syntax';

our $VERSION = '0.01';

my %users = (
    { name => 'test',
      pass => 'test',
      otp_secret => 'abcde12345',
    },
    { name => 'admin',
      pass => 'admin',
      otp_secret => 'abcde123456',
    },
);

get '/' => sub {
    template 'index';
};

get '/auth/setup' => sub {
    my ($user) = params->{user};
    
    my ($otp_secret) = $users{$user}->{otp_secret};
    my $auth = Authen::GoogleAuthenticator->new( secret => $otp_secret );
    
    template 'setup_otp';
}

# Maybe also have "requires('password')"
#                 "requires('twofactor')"
get '/auth/login' => sub {
    my ($user_id,$pass,$otp) = params->{user}, params->{pass}, params->{otp};
    my $return = params->{return} || '';
    
    my $user = $users{ $user_id };
    
    if( $pass eq $user->{pass} ) {
        if( $user->{otp_secret}) {
            # Check OTP in addition to password
            my $auth = Authen::GoogleAuthenticator->new( secret => $user->{otp_secret} );
            if( 1 == $auth->verify( $otp )) {
                session 'user' => $user;
            };
        } else {
            session 'user' => $user;
        };
    };
    
    return redirect $return
        if( $return );
    template 'login';
}

true;

=head1 SEE ALSO

L<http://stackoverflow.com/questions/549/the-definitive-guide-to-forms-based-website-authentication>

=cut