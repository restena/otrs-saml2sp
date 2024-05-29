# --
# Kernel::System::Auth::SAML2SP::Response.pm - authentication module
# Copyright (C) (2016) (Maxime Appolonia) (maxime.appolonia@restena.lu)
# https://github.com/restena-ma/otrs-saml2sp
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (AGPL). If you
# did not receive this file, see http://www.gnu.org/licenses/agpl.txt.
# --

package Kernel::System::Auth::SAML2SP::Response;

use strict;
use warnings;

use Data::Dumper;
use DateTime;
use DateTime::Format::DateParse;
use MIME::Base64;
use XML::LibXML;
use Digest::SHA qw(sha1_base64 sha256_base64 sha512_base64);
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use Switch;
use utf8;

sub new{
	my $class = shift;
	my ( $raw_response, $settings ) = @_;
	
	my $self = bless {
		raw_response => $raw_response,
		settings => $settings,
		xml_as_dom => "",
		signature_node => "",
		signedInfo => "",
		validated_nodes => undef,
		signed_info => "",
		key_sign_algo => ""
	}, $class;
	
	$self->decode();
	
	return $self;
}


sub decode{
	my $self = shift;
	
	$self->{xml_as_string} = decode_base64($self->{raw_response});
	utf8::decode($self->{xml_as_string});
	
	my $parser = XML::LibXML->new();
	$self->{xml_as_dom} = $parser->parse_string($self->{xml_as_string});
}


sub is_valid{
	my $self = shift;
	
	if(!$self->validateNumAssertions()){
		$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML: no or more than one saml assertion in the response, need only one");
		return;
	}
	
	if(!$self->validateTimestamps()){
		$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML: timestamps do not match");
		return;
	}
	
	if(!$self->validateTimestamps()){
		$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML: timestamps do not match");
		return;
	}
	
	
	my $signature = $self->get_signature();
	if(!$signature){
		$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML: no digital signature found");
		return;
	}
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "DEBUG: ".$signature);
	
	$self->{signed_info} = $self->canonicalizeSignedInfo();
	
	if(!$self->validate_reference()){
		$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML: digest is not valid or was not found");
		return;
	}
	
	my $objKey = $self->locateKey();
	if(! $objKey ) {
			$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML: We have no idea about the key");
			return;
	}
	
	if(!$self->verify_signature()){
		$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML: Signature verification failed !");
		return;		
	}
	
	return 1;
}


sub get_signature{
	my $self = shift;
	
	my $xpath = XML::LibXML::XPathContext->new($self->{xml_as_dom});
	$xpath->registerNs("secdsig", "http://www.w3.org/2000/09/xmldsig#");
	my $query = ".//secdsig:Signature";
	my @nodes = $xpath->findnodes($query);
	$self->{signature_node} = $nodes[0]; 
	return $nodes[0];
}


sub canonicalizeSignedInfo() {
	my $self = shift;
	
	my $canonicalmethod = undef;
	
	my $xpath = XML::LibXML::XPathContext->new($self->{signature_node});
	$xpath->registerNs("secdsig", "http://www.w3.org/2000/09/xmldsig#");
	my $query = "./secdsig:SignedInfo";
	my @nodes = $xpath->findnodes($query);
	my $signInfoNode = $nodes[0];
	if ($signInfoNode) {
		my $xpath2 = XML::LibXML::XPathContext->new($signInfoNode);
		$xpath2->registerNs("secdsig", "http://www.w3.org/2000/09/xmldsig#");
		my $query2 = "./secdsig:CanonicalizationMethod";
		my @nodes2 = $xpath2->findnodes($query2);
		my $canonNode = $nodes2[0];  
		my @attr = $canonNode->attributes();
		my $canonicalmethod;
		for(my $j=0; $j < scalar(@attr) ; $j++){
			if($attr[$j]->nodeName eq "Algorithm"){
				$canonicalmethod = $attr[$j]->value;	
			}
		}
		$self->{signedInfo} = $self->canonicalizeData($signInfoNode, $canonicalmethod);
		#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "DEBUG: ".Dumper($self->{signedInfo}));
		return $self->{signedInfo};
	}
	return;
}


sub canonicalizeData{
	my $self = shift;
	my ( $node, $canonicalmethod ) = @_; 
	
	my $exclusive = 0;
	my $withComments = 0;
	if ($canonicalmethod eq "http://www.w3.org/TR/2001/REC-xml-c14n-20010315") {    
		$exclusive = 0;
		$withComments = 0;
	}
	
	if ($canonicalmethod eq "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments") {
		$withComments = 1;
	}
	
	if ($canonicalmethod eq "http://www.w3.org/2001/10/xml-exc-c14n#") {
		$exclusive = 1;
	}
	
	if ($canonicalmethod eq "http://www.w3.org/2001/10/xml-exc-c14n#WithComments") {
		$exclusive = 1;
		$withComments = 1;
	}
	
	if($exclusive){
		return $node->toStringEC14N($withComments);
	}else{
		return $node->toStringC14N($withComments)
	}
	
	return;
}


sub validate_reference{
	my $self = shift;

	if (!$self->{xml_as_dom}->isSameNode($self->{signature_node})) {
		$self->{signature_node}->parentNode->removeChild($self->{signature_node});
	}

	my $xpath = XML::LibXML::XPathContext->new($self->{signature_node});
	$xpath->registerNs("secdsig", "http://www.w3.org/2000/09/xmldsig#");
	my $query = "./secdsig:SignedInfo/secdsig:Reference";
	my @nodes = $xpath->findnodes($query);
	if(scalar(@nodes)==0){
		return;
	}
	
	$self->{validated_nodes} = ();

	for(my $i=0; $i < scalar(@nodes); $i++) {
		if(!$self->processRefNode($nodes[$i])){
			$self->{validated_nodes} = ();
			return;
		}
	}
	
	return 1;
}


sub processRefNode{
	my $self = shift;
	my ( $ref_node ) = @_;
	
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML DEBUG: ". $ref_node);
	my @attr = $ref_node->attributes();
	my $node_id = "";
	for(my $j=0; $j < scalar(@attr) ; $j++){
		if($attr[$j]->nodeName eq "URI"){
			$node_id = $attr[$j]->value;
			if(!(substr($node_id, 0, 1) eq "#")){
				# external url not supported
				return;
			}
			$node_id = substr($node_id, 1, length($node_id));
			#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message  => "SAML DEBUG: ". $node_id);
		}
	}
	
	my $xpath = XML::LibXML::XPathContext->new($self->{xml_as_dom});
	$xpath->registerNs("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
	$xpath->registerNs("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
	my $query = '//*[@ID="'. $node_id .'"]';
	my @nodes = $xpath->findnodes($query);
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML DEBUG: ". Dumper($nodes[0]));
	
	my $dataObject = $nodes[0];
	
	if(!$self->validateDigest($ref_node, $dataObject)){
		return;
	}
	
	$self->{validated_nodes}{$node_id} = $dataObject; 
	
	return 1;
}


sub validateDigest(){
	my $self = shift;
	my ( $ref_node, $data_object ) = @_;
	
	my $xpath = XML::LibXML::XPathContext->new($ref_node);
	$xpath->registerNs("secdsig", "http://www.w3.org/2000/09/xmldsig#");
	my $query = './secdsig:DigestMethod/@Algorithm';
	my @nodes = $xpath->findnodes($query);
	my $digestAlgorithm = $nodes[0]->textContent;
	
	my $data = $self->processTransforms($ref_node, $data_object);
	my $calculatedDigValue = $self->calculateDigest($digestAlgorithm, $data);
		
		# remove = paddng characters
		$calculatedDigValue =~ s/\n//g;
		
		my $query2 = "./secdsig:DigestValue";
		my @nodes2 = $xpath->findnodes($query2, $ref_node);
		my $digestValue = $nodes2[0]->textContent;
		
		# remove = paddng characters
		$digestValue =~ s/\=//g;
		
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "---". $data . "---");
	
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML DEBUG: val hash is ". $calculatedDigValue);
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML DEBUG: xml hash is ". $digestValue);
		
	
	if($calculatedDigValue  eq $digestValue){
		#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML DEBUG: digest are matching");
		return 1;
	}	
	
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML DEBUG: digest are not matching");
	return;
}

sub processTransforms(){
	my $self = shift;
	my ( $ref_node, $data_object ) = @_;
	
	return $self->canonicalizeData($data_object, "http://www.w3.org/2001/10/xml-exc-c14n#");
}

sub calculateDigest(){
	my $self = shift;
	my ( $digestAlgorithm, $data ) = @_;
	
	utf8::encode($data);
	
	if($digestAlgorithm eq "http://www.w3.org/2000/09/xmldsig#sha1"){
		return sha1_base64($data);
	}
	
	if($digestAlgorithm eq "http://www.w3.org/2001/04/xmlenc#sha256"){
		return sha256_base64($data);
	}
	
	if($digestAlgorithm eq "http://www.w3.org/2001/04/xmlenc#sha512"){
		return sha512_base64($data);
	}
	
	if($digestAlgorithm eq "http://www.w3.org/2001/04/xmlenc#ripemd160"){
		$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML error: ripemd160 digest not supported");
		return;
	}
	
	return;
}


sub locateKey(){
	my $self = shift;
	
	
	my $xpath = XML::LibXML::XPathContext->new($self->{signature_node});
	$xpath->registerNs("secdsig", "http://www.w3.org/2000/09/xmldsig#");
	my $query = './secdsig:SignedInfo/secdsig:SignatureMethod/@Algorithm';
	my @nodes = $xpath->findnodes($query);
	
	
	my $algorithm = $nodes[0]->textContent;
	if ($algorithm) {
		#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML DEBUG: ".$algorithm);
		$self->{key_sign_algo} = $algorithm;
		# $objKey = new XMLSecurityKey($algorithm, array('type'=>'public'));
		#return $objKey;
	}
}


sub verify_signature(){
	my $self = shift;
	
	my $xpath = XML::LibXML::XPathContext->new($self->{signature_node});
	$xpath->registerNs("secdsig", "http://www.w3.org/2000/09/xmldsig#");
	my $query = './secdsig:SignatureValue';
	my @nodes = $xpath->findnodes($query);
	my $sigValue = decode_base64($nodes[0]->textContent);
	
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML DEBUG: ". $self->{settings}{SSOx509Cert});
	
	my $x509 = Crypt::OpenSSL::X509->new_from_string($self->{settings}{SSOx509Cert}, Crypt::OpenSSL::X509::FORMAT_PEM);
	my $pubkey = Crypt::OpenSSL::RSA->new_public_key($x509->pubkey());
	switch($self->{key_sign_algo}) {
		case /rsa-sha256$/ { $pubkey->use_sha256_hash(); }
		case /rsa-sha384$/ { $pubkey->use_sha384_hash(); }
		case /rsa-sha512$/ { $pubkey->use_sha512_hash(); }
		else { $pubkey->use_sha1_hash(); }
	}

	my $valid = $pubkey->verify($self->{signed_info}, $sigValue);
	
	#$Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error', Message => "SAML DEBUG: Signature is ".$valid);
	
	return $valid;
}


sub validateNumAssertions(){
	my $self = shift;
		
	my @assertionNodes = $self->{xml_as_dom}->getElementsByTagName('saml:Assertion');
	return (scalar(@assertionNodes) == 1);
}


sub validateTimestamps(){
	my $self = shift;
		
	my @timestampNodes = $self->{xml_as_dom}->getElementsByTagName('saml:Conditions');
	for(my $i=0; $i < scalar(@timestampNodes) ; $i++){
		my @attr = $timestampNodes[$i]->attributes();
		
		for(my $j=0; $j < scalar(@attr) ; $j++){
			if(
				$attr[$j]->nodeName eq "NotBefore" && 
				(DateTime::Format::DateParse->parse_datetime($attr[$j]->value) - DateTime->now())->is_positive()   
			){
				return;
			}
			if(
				$attr[$j]->nodeName eq "NotOnOrAfter" && 
				!(DateTime::Format::DateParse->parse_datetime($attr[$j]->value) - DateTime->now())->is_positive()   
			){
				return;
			}
		}
	}
	return 1;
}


sub get_nameid{
	my $self = shift;
	
	my $xpath = XML::LibXML::XPathContext->new($self->{xml_as_dom});
	$xpath->registerNs("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
	$xpath->registerNs("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
	my $query = "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID";
	my @nodes = $xpath->findnodes($query);
	
	return $nodes[0]->toString();
}


sub get_attribute() {
	my $self = shift;
	my ( $name ) = @_;
	
	my $xpath = XML::LibXML::XPathContext->new($self->{xml_as_dom});
	$xpath->registerNs("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
	$xpath->registerNs("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
	my $query = '/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="'. $name .'"]/saml:AttributeValue';
	my @entries = $xpath->findnodes($query);

	if(scalar(@entries)> 0){
		if(scalar(@entries) > 1) {
			my @return = ();
			for(my $i=0; $i < scalar(@entries); $i++) {
					push(@return, $entries[$i]->textContent());
			}
			return @return;
		} else {
			return $entries[0]->textContent();
		}
	}else{
		return ;
	}
}

1;