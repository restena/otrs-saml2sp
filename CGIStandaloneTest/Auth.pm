#!/usr/bin/perl
# --
# Kernel::System::Auth::SAML2SP::Config.pm - authentication module
# Copyright (C) (2016) (Maxime Appolonia) (maxime.appolonia@restena.lu)
# https://github.com/restena-ma/otrs-saml2sp
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (AGPL). If you
# did not receive this file, see http://www.gnu.org/licenses/agpl.txt.
# --

package CGIStandaloneTest::Auth;

use strict;
use warnings;

use CGI;

use Data::Dumper;


use Kernel::System::Auth::SAML2SP::Config;
use Kernel::System::Auth::SAML2SP::AuthRequest;
use Kernel::System::Auth::SAML2SP::Response;


our $SSO_IDP_URL = "https://idp.example.com/simplesaml/saml2/idp/SSOService.php";
our $SSO_ASSERTION_CONSUMER_URL = "/cgitest/test.pl";


sub new{
	my $class = shift;
	my ( $cgi ) = @_; 
	
	my $self = bless {
		cgi => $cgi,
		config => Kernel::System::Auth::SAML2SP::Config->new($cgi) 
	}, $class; 
	
	$self->{config}->{idp_sso_target_url} = $SSO_IDP_URL;
	$self->{config}->{assertion_consumer_service_url} = "$ENV{REQUEST_SCHEME}://$ENV{HTTP_HOST}/" . $SSO_ASSERTION_CONSUMER_URL;
	
	return $self;
}

sub Run{
	my $self = shift;
	
	my $post_samlResponse = $self->{cgi}->param('SAMLResponse');
	
	if( ! defined $post_samlResponse || $post_samlResponse eq "" ){
		
		# This page call is not triggered by an saml response so we will create an saml request
		my $request = Kernel::System::Auth::SAML2SP::AuthRequest->new($self->{config});
		my $idp_redirect = $request->create();
		
		print CGI::redirect($idp_redirect);
		
	}else{
		my $response = Kernel::System::Auth::SAML2SP::Response->new($post_samlResponse);
		
		print CGI::header();
		
		print($response->get_nameid()."<br/>");
		print("UserId: " . $response->get_attribute("UserId")."<br/>"); # userid
		
		
	}
	
	#print("<hr><pre>" . Dumper($self->{config}) . "</pre>");
}


1;


