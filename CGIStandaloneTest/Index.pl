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


use strict;
use warnings;

use CGI;


use FindBin qw($Bin);
use lib "$Bin/../";

use CGIStandaloneTest::Auth;


my $cgi = CGI->new();
my $saml2 = CGIStandaloneTest::Auth->new( $cgi );
$saml2->Run();

