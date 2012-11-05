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
        # Dancer app prereqs
        'Test::More' => 0,
        'YAML'       => 0,
        'Dancer'     => 1.3097,
        'Dancer::Plugin::FlashMessage' => 0,
        # Auth::GoogleAuthenticator prereqs
        'Authen::OATH' => 0,
        'Convert::Base32' => 0,
        'Math::Random::MT' => 0, # for generation of good passcodes
        'URI::Escape' => 0, # for url-escaping the user name
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer-Auth-GoogleAuthenticator-*' },
);
