package Auth::GoogleAuthenticator;
use strict;
use Authen::OATH;
use Convert::Base32 ;

sub new {
    my ($class, %args) = @_;
    if( $args{ secret_base32 }) {
        $args{ secret } = decode_base32( delete $args{ secret_base32 });
    };
    
    $args{ auth } ||= Authen::OATH->new();
    bless \%args => $class;
}

sub auth { $_[0]->{auth} };

sub registration_qr_code {
    # ...
    require Imager::QRCode;
    my $qrcode = Imager::QRCode->new(
        size          => 2,
        margin        => 2,
        version       => 1,
        level         => 'M',
        casesensitive => 1,
        lightcolor    => Imager::Color->new(255, 255, 255),
        darkcolor     => Imager::Color->new(0, 0, 0),
    );
    my $img = $qrcode->plot($self->registration_key);
    $img->write( data => \my $res );
    $res
}

sub registration_key {
    return encode_base32( $_[0]->{secret} );
}

sub totp {
    my ($self, $ts) = @_;
    $self->auth->totp( $self->{secret}, $ts )
};

sub registration_url {
    my ($self, $label, $type) = @_;
    $type ||= 'totp';
    return "otpauth://$type/$label?secret=" . $self->registration_key
}

sub verify {
    my ($self, $code, $ts) = @_;
    return $code and
        $self->totp( $ts ) == $code;
}

1;

=head1 WORKFLOW

=over 4

=item *

Install Google Authenticator

=item *

Visit the "Install Two Factor Authentication" page

=item *

Display the secret key there

  ->registration_qr_code
  ->registration_key

Display the "Panic" OTPs there so that the user can print them out
on paper and store them in a secure location:

  my @recovery_passwords = generate_recovery_strings( 3 );
  for my $pass ( @recovery_passwords ) {
    print $pass, "\n";
  };

=item *

Photograph the QR code

or

Manually enter the key into the Authenticator

=item *

On the Login page enter the password
and the OTP code from the Authenticator
or on the Recovery page, enter one of the panic keys.

=back

=head1 PASSWORD STORAGE

The password should be stored as a hash.

The shared authenticator secret needs to be stored as plaintext.

=head1 RECOVERY

As phones tend to get lost, the recovery passphrases become
important. They also are password equivalent. So, my recommendation
is to store the recovery passphrases only as hashes, just
like you store passwords.

=cut