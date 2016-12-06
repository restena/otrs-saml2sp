# --
# Kernel::System::Auth::SAML2SP.pm - authentication module
# Copyright (C) (2016) (Maxime Appolonia) (maxime.appolonia@restena.lu)
# https://github.com/restena-ma/otrs-saml2sp
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (AGPL). If you
# did not receive this file, see http://www.gnu.org/licenses/agpl.txt.
# --
# Note:
#
#  In order to display a "Login via SAML" button you have to include the html code below into the Login.tt template file near the login form
#
#  <!-- Add the sso login button -->
#  <div class="Content" style="text-align: center; display: block; height: 40px; padding-top: 20px; padding-bottom: 0; vertical-align: bottom; line-height: 40px;">
#    <a href="./index.pl?Action=Login&WantSAMLRequest=true" style="background: #e9e9e9; border-radius: 5px; padding: 10px;border: 1px solid #ccc; font-weight: bold;" >Login via SAML2 SSO</a>
#  </div>
#  <!-- end sso login button -->
#
#
#  In the Default.pm you can active this auth module with a fallback on the default DB module
#  
#  $Self->{AuthModule1} = 'Kernel::System::Auth::DB';
#  $Self->{AuthModule} = 'Kernel::System::Auth::SAML2SP';
#  $Self->{'AuthModule::SAML2SP::SSOIdpUrl'} = 'https://idp.example.com/simplesaml/saml2/idp/SSOService.php';
#  $Self->{'AuthModule::SAML2SP::SSOAssertionConsumerURL'} = '/otrs/index.pl?Action=Login';
#  $Self->{'AuthModule::SAML2SP::SSOUserIdAttribute'} = 'UserId';
#  $Self->{'AuthModule::SAML2SP::SSOx509Cert'} = "-----BEGIN CERTIFICATE-----xxxxxxx-----END CERTIFICATE-----";
#
# --

package Kernel::System::Auth::SAML2SP;

use strict;
use warnings;

our @ObjectDependencies = (
    'Kernel::Config',
    'Kernel::System::Web::Request',
    'Kernel::System::Log'
);


use CGI;
#use FindBin qw($Bin);
#use lib "$Bin/../";
use Kernel::System::Auth::SAML2SP::Config;
use Kernel::System::Auth::SAML2SP::AuthRequest;
use Kernel::System::Auth::SAML2SP::Response;

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    # Debug 0=off 1=on
    $Self->{Debug} = 0;

    # get config object
    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');


    # get config
    $Self->{SSOIdpUrl} = $ConfigObject->Get( 'AuthModule::SAML2SP::SSOIdpUrl' . $Param{Count} ) || die "Need AuthModule::SAML2SP::SSOIdpUrl{Count} in Kernel/Config.pm";
    $Self->{SSOAssertionConsumerURL} = $ConfigObject->Get( 'AuthModule::SAML2SP::SSOAssertionConsumerURL' . $Param{Count} ) || die "Need AuthModule::SAML2SP::SSOAssertionConsumerURL{Count} in Kernel/Config.pm";
    $Self->{SSOUserIdAttribute} = $ConfigObject->Get( 'AuthModule::SAML2SP::SSOUserIdAttribute' . $Param{Count} ) || die "Need AuthModule::SAML2SP::SSOUserIdAttribute{Count} in Kernel/Config.pm";
    $Self->{SSOx509Cert} = $ConfigObject->Get( 'AuthModule::SAML2SP::SSOx509Cert' . $Param{Count} ) || die "Need AuthModule::SAML2SP::SSOx509Cert{Count} in Kernel/Config.pm";


    return $Self;
}


sub GetOption {
    my ( $Self, %Param ) = @_;

    # check needed stuff
    if ( !$Param{What} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => "Need What!"
        );
        return;
    }

    # module options
    my %Option = (
        PreAuth => 0,
    );

    # return option
    return $Option{ $Param{What} };
}

sub Auth {
    my ( $Self, %Param ) = @_;
    
    my $ParamObject  = $Kernel::OM->Get('Kernel::System::Web::Request');
    
    my $wantSamlRequest = $ParamObject->GetParam( Param => 'WantSAMLRequest' );
	my $samlResponse = $ParamObject->GetParam( Param => 'SAMLResponse' );
    
    
    my $config = Kernel::System::Auth::SAML2SP::Config->new(CGI->new());
    $config->{idp_sso_target_url} = $Self->{SSOIdpUrl};
	$config->{assertion_consumer_service_url} = "$ENV{REQUEST_SCHEME}://$ENV{HTTP_HOST}/" . $Self->{SSOAssertionConsumerURL};
	$config->{SSOx509Cert} = $Self->{SSOx509Cert};
	
	
    if( ! defined $samlResponse || $samlResponse eq "" ){

		# This page call is not triggered by an saml response. We will create an saml request only if it was explicitely requested
		if( defined $wantSamlRequest){
			my $request = Kernel::System::Auth::SAML2SP::AuthRequest->new($config);
			my $idp_redirect = $request->create()."&ReturnURL=".$config->{assertion_consumer_service_url};
			print CGI::redirect($idp_redirect);
		}else{
			return;
		}
		
	}else{
		my $response = Kernel::System::Auth::SAML2SP::Response->new($samlResponse, $config);
		
		if($response->is_valid()){
			return $response->get_attribute($Self->{SSOUserIdAttribute});
		}else{
			$Kernel::OM->Get('Kernel::System::Log')->Log(
	            Priority => 'error',
	            Message  => "Received an SAML response with a wrong signature!"
        	);
        
			return;
		}
		
		
	}
    
    
    
	return;
}

1;