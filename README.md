# otrs-saml2sp

## SAML2 Service Provider for OTRS

This is an authentication addon for OTRS which acts as a SAML2 Service Provider.  
This addon does not process to the auto-provisionning of the accounts, it means that the users have to be created in the OTRS database.  
The main advantage of this auth provider is that it can be chained with other auth providers so it is possible to have agents authenticated via SSO and others via a fallback Auth provider (otrs DB, Radius...)  
Another advantage is that it does not depend on specific Apache auth modules.

### Requirements:
DateTime;  
DateTime::Format::DateParse;  
MIME::Base64;  
XML::LibXML;  
Digest::SHA qw(sha1_base64 sha256_base64 sha512_base64);  
Crypt::OpenSSL::RSA;  
Crypt::OpenSSL::X509;  
Compress::Zlib;  
URI::Escape;  


### Installation:
  You can download the latest opm build on the dist folder of this repo and then install it using the web based addon manager.  
  Alternatively you can  download the source files and copy them to ./Kernel/System/Auth folder of your OTRS installation.
  
### Notes on configuration:

  In order to display a "Login via SAML" (mandatory) button you have to include the html following code into the Login.tt template file, below or above the login form
  ```html
  <!-- Add the sso login button -->
  <div class="Content" style="text-align: center; display: block; height: 40px; padding-top: 20px; padding-bottom: 0; vertical-align: bottom; line-height: 40px;">
    <a href="./index.pl?Action=Login&WantSAMLRequest=true" style="background: #e9e9e9; border-radius: 5px; padding: 10px;border: 1px solid #ccc; font-weight: bold;" >Login via SAML2 SSO</a>
  </div>
  <!-- end sso login button -->
  ```

  In the Default.pm you can activate this auth module with a fallback on the default DB module

  ```perl
  $Self->{AuthModule1} = 'Kernel::System::Auth::DB';
  $Self->{AuthModule} = 'Kernel::System::Auth::SAML2SP';
  $Self->{'AuthModule::SAML2SP::SSOIdpUrl'} = 'https://idp.example.com/simplesaml/saml2/idp/SSOService.php';
  $Self->{'AuthModule::SAML2SP::SSOAssertionConsumerURL'} = '/otrs/index.pl?Action=Login';
  $Self->{'AuthModule::SAML2SP::SSOUserIdAttribute'} = 'UserId';
  $Self->{'AuthModule::SAML2SP::SSOx509Cert'} = "-----BEGIN CERTIFICATE-----[certificate content here can spread on many lines]-----END CERTIFICATE-----";
```

### Credits
This addons is highly inspired by the php's [xmlseclibs](https://github.com/robrichards/xmlseclibs) by Rob Richards
