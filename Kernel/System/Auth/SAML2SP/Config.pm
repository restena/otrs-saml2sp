# --
# Kernel::System::Auth::SAML2SP::Config.pm - authentication module
# Copyright (C) (2016) (Maxime Appolonia) (maxime.appolonia@restena.lu)
# https://github.com/restena-ma/otrs-saml2sp
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (AGPL). If you
# did not receive this file, see http://www.gnu.org/licenses/agpl.txt.
# --

package Kernel::System::Auth::SAML2SP::Config;

use strict;
use warnings;

# This class is a structure which holds the settings defined in the otrs config file
# Do not fill your settings here !

sub new{
	my $class = shift;
	my ( $cgi ) = @_; 
	
	my $self = bless {
		idp_sso_target_url => "",
		x509certificate => "",
		assertion_consumer_service_url => $cgi->url(),
		issuer => "$ENV{REQUEST_SCHEME}://$ENV{HTTP_HOST}/",
		name_identifier_format => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}, $class; 
	
	return $self;
}

1;