# --
# Kernel::System::Auth::SAML2SP::AuthRequest.pm - authentication module
# Copyright (C) (2016) (Maxime Appolonia) (maxime.appolonia@restena.lu)
# https://github.com/restena-ma/otrs-saml2sp
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (AGPL). If you
# did not receive this file, see http://www.gnu.org/licenses/agpl.txt.
# --

package Kernel::System::Auth::SAML2SP::AuthRequest;

use strict;
use warnings;

use DateTime;
use MIME::Base64;
use Compress::Zlib;
use URI::Escape;


sub new{
	my $class = shift;
	my ( $settings ) = @_; 
	
	my $self = bless {
		settings => $settings 
	}, $class; 
	
	return $self;
}

sub create{
	my $self = shift;
	
	
    
	my $id = $self->generateUniqueID(20);
	my $issue_instant = $self->getTimeStamp();

    my $request = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"$id\" Version=\"2.0\" IssueInstant=\"$issue_instant\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"".$self->{settings}->{assertion_consumer_service_url}."\">".
            "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">".$self->{settings}->{issuer}."</saml:Issuer>\n".
            "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"$self->{settings}->{name_identifier_format}\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n".
            "</samlp:AuthnRequest>";
	
	
	my $deflated_request  = compress($request);
	$deflated_request = substr($deflated_request, 2, length($deflated_request)-4); # php inflate does not like first 2 bytes and last 4th ?!?
	
	
	my $base64_request = encode_base64($deflated_request);
	
	my $encoded_request = uri_escape($base64_request);
	
    return $self->{settings}->{idp_sso_target_url}."?SAMLRequest=".$encoded_request;
}


sub generateUniqueID{
	my $self = shift;
	my ( $length ) = @_;
	
	my $chars = "abcdef0123456789";
    my $chars_len = length($chars);
    my $uniqueID = "";
    for (my $i = 0; $i < $length; $i++){
    	$uniqueID .= substr($chars,rand($chars_len),1);
    }
    return "_".$uniqueID;
}


sub getTimeStamp{
	my $self = shift;
	
    my $dt = DateTime->now();
    return $dt->strftime("%Y-%m-%dT%H:%M:%SZ");
}

1;