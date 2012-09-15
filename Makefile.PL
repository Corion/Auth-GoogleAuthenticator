use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer::Auth::GoogleAuthenticator',
    AUTHOR              => q{L<mailto:corion@corion.net>},
    VERSION_FROM        => 'lib/Dancer/Auth/GoogleAuthenticator.pm',
    ABSTRACT            => 'Authenticate through Google Authenticator',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        # Dancer prereqs
        'Test::More' => 0,
        'YAML'       => 0,
        'Dancer'     => 1.3097,
        # Auth::GoogleAuthenticator prereqs
        'Authen::OATH' => 0,
        'Convert::Base32' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer-Auth-GoogleAuthenticator-*' },
);
