package Dancer::Auth::GoogleAuthenticator;
use Dancer ':syntax';
use Dancer::Plugin::FlashMessage;
use Auth::GoogleAuthenticator;

=head1 NAME

Dancer::Auth::GoogleAuthenticator - Two-Factor demo app

=cut

our $VERSION = '0.01';

my %users = (
    test => { name => 'test',
      pass => 'test',
      otp_secret => 'test@example.com',
    },
    test2 => { name => 'test2',
      pass => 'test2',
      otp_secret => '',
    },
    admin => { name => 'admin',
      pass => 'admin',
      otp_secret => 'abcde123456',
    },
);

# Map a user to its authenticator
sub get_otp_auth {
    my ($user) = @_;
    
    return unless $user;
    
    my ($otp_secret) = $user->{otp_secret};
    if( $otp_secret ) {
        return Auth::GoogleAuthenticator->new( secret => $otp_secret );
    };
    return
};

get '/' => sub {
    template 'index', {
        (user => session('user')),
        #(twofactor_available => get_otp_auth(session('user') || '')),
        #(twofactor_active => session('twofactor')),
    };
};

# Force authentication for all non-index pages
hook before => sub {
    return
        if request->path_info =~ m{^/(css|javascripts|400|500|favicon.ico|$)};
    if (! session('user') && request->path_info !~ m{^/auth/login}) {
        # XXX We should store the redirect target internally
        # and give the user
        # not an URL but an internal session as the redirect target
        var requested_path => request->path_info;
        request->path_info('/auth/login');
        # We should redirect here!
        redirect '/auth/login';
    }
};

get '/auth/setup' => sub {
    my ($user) = session->{user};
    
    my ($otp_secret) = $users{$user}->{otp_secret};
    my $auth = get_otp_auth( $user );
    
    # Display otp_secret if we have it
    # XXX Maybe this should be over SSH only
    template 'setup_twofactor', {
        auth => $auth,
        user => $user,
        otp_secret => $otp_secret
    };
};

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
};

get '/auth/login' => sub {
    my $return = vars->{requested_path} || '';
    
    # XXX Should only store relative URLs here, or at least
    #     only site-local URLs
    session->{return_url} = $return;
    template 'login';
};

# Maybe also have "requires('password')"
#                 "requires('twofactor')"
# XXX use session flash instead of session
post '/auth/login' => sub {
    my ($user_id,$pass,$otp) = (params->{user}, params->{pass}, params->{otp});
    my $return = vars->{requested_path} || session->{return_url} || '';
    
    my $user= $users{ $user_id };
    if(     $user and $user->{pass}
        and $pass and $pass eq $user->{pass} ) {
        my $auth_twofactor= get_otp_auth( $user );
        if( $auth_twofactor ) {
            # Check OTP in addition to password
            if( $auth_twofactor->verify( $otp )) {
                session 'user' => $user;
                session 'twofactor' => 1;
                flash success => "User logged in with two-factor auth";
                warning "User '$user_id' logged in with two-factor auth";
            } else {
                # Log the failure
                # Increment a failure counter for that user
                # Increment a failure counter for that IP
                # Increment a failure counter overall, to detect clock skew
                warning "Wrong OTP for user '$user_id'";
                flash error => "User unknown or wrong password/OTP";
            };
        } else {
            warning "User '$user_id' logged in with password";
            session 'user' => $user;
            session 'twofactor' => 0;
            flash success => "User logged in with password auth";
        };
    } else {
        warning "Wrong password for user '$user_id'";
        flash error => "User unknown or wrong password/OTP";
    };
    
    return redirect $return
        if( session('user') and $return );
    template 'login';
};

get '/auth/logout' => sub {
    session->destroy; # boom
};

get '/' => sub {
    template 'index';
};

true;

=head1 SEE ALSO

L<http://stackoverflow.com/questions/549/the-definitive-guide-to-forms-based-website-authentication>

=cut