package SF_form_secure;

=head1 COPYLEFT

 By: $|-|4X4_|=73}{ N.K.A (shakainc@tampabay.rr.com)
 File: SF_form_secure.pm
 Version: v 1.0 10/21/2006 13:37:55

 This file is a Perl Module.

=cut

=head1 NAME

 SF_form_secure Module

=head1 DESCRIPTION

 Data integrity of links and referer.
 Good URL anti-tampering methods.
 Must Provide a secret key.
 time stamp all made links to expire in 10 minutes.
 4 security levels, High, 2 Mediums and Low.
 Check referer encoding, and/or maching referer.
 Checks incoming QUERY_STRING encoding is correct. .

 This file does not have many hours of testing.
 Please Report all Bugs and report if all go's well!

=head1 SYNOPSIS

 Required!
 Perl 5.0 or up
 Digest::SHA1

 Usage:
 require SF_form_secure;

 Set page up for self encoding if encoding is missing
 '3' - is the action type
 $key - Must Provide a secret key.
 'op=testForm;module=Flex_Form' - to work, must provide a matching self link
 '' - not used for this action
form_secure::x_secure('3','','op=testForm;module=Flex_Form','');

 This makes encoded links for the next page
 Link encoding made expire in 10 min.
 1 - is the action type
 $key - Must Provide a secret key.
 'op=testForm2;module=Flex_Form' - The link to encode
 '' - not used for this action
my $secure_link = SF_form_secure::x_secure(1,$key,'op=testForm2;module=Flex_Forma','');
 example of $secure_link = 'op=testForm;module=Flex_Forma;Flex=e690dec564cf52fcfcc967a9d5c079a7687f87d1|1161373021';
 1161373021 date is bound in encoding.

 Full Security - To get to this area the referer must match the one given, the incoming link and past referer encoding must be correct.
 All encodings used expires in 10 min.
 2 - is the action type
 $key - Provide another key or blank will default to its own key.
 '1' - Check Referer encoding and date expires, Blank is off
 "http://www.domain.com/index.cgi?op=testForm;module=Flex_Form" - Match this Referer, Blank is off
my $secure_check = SF_form_secure::x_secure(2,$key,'1',"http://www.domain.com/index.cgi?op=testForm;module=Flex_Forma");
if (!$secure_check) {
print "Access Failure";
exit;
}

 Medium Security 1 - To get to this area the referer must match the one given and incoming link encoding must be correct.
 All encodings used expires in 10 min.
 2 - is the action type
 $key - Provide another key or blank will default to its own key.
 '' - Check Referer encoding and date expires, Blank is off
 "http://www.domain.com/index.cgi?op=testForm;module=Flex_Form" - Match this Referer, Blank is off
my $secure_check = SF_form_secure::x_secure(2,$key,'',"http://www.domain.com/index.cgi?op=testForm;module=Flex_Form");
if (!$secure_check) {
print "Access Failure";
exit;
}

 Medium Security 2 - To get to this area the referer encoding and incoming link encoding must be correct.
 All encodings used expires in 10 min.
 2 - is the action type
 $key - Provide another key or blank will default to its own key.
 '1' - Check Referer encoding and date expires, Blank is off
 '' - Match this Referer, Blank is off
my $secure_check = SF_form_secure::x_secure(2,$secure_code,'1','');
if (!$secure_check) {
print "Access Failure";
exit;
}

 Low Security - To get to this area the incoming link encoding must be correct.
 All encodings used expires in 10 min.
 2 - is the action type
 '' - Provide another key or blank will default to its own key.
 '' - 1 will Check Referer encoding and date expires, Blank is off
 '' - Match this Referer, Blank is off
my $secure_check = SF_form_secure::x_secure(2,$secure_code,'','');
if (!$secure_check) {
print "Access Failure";
exit;
}

 Note: To prevent others Members from using ones links
 provide your own key and format the provided key something like this
 $key = $key . $Member_Name;
 the new key format will need to be used for all actions

=head1 FUNCTIONS

 The function available from this package:

=cut

delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
use strict;
use Digest::SHA1 qw(sha1_hex);

=head2 x_secure()

 Main Function

=cut

sub x_secure {
my ($act, $code, $link, $ref) = @_;

# only uses other keys
if(!$code) {
return;
}
# ------------------------------------------------------------------------------
# return secure link (makes secure link)
# ------------------------------------------------------------------------------
 if ($act eq 1 && $link && $code) {
 # Plus 10 minutes
  my $exp = time + 600;
  my $security_key = sha1_hex($link,"$code$exp");

  $security_key = $link . ';Flex=' . $security_key . '|' . $exp;
  return $security_key;
 }
 elsif ($act eq 2 && $code) {
# ------------------------------------------------------------------------------
# return checked link (checks if link is good or bad.)
# ------------------------------------------------------------------------------

# Get date
my $date = time;

# Get Referer and link Query String
my $REF = $ENV{'HTTP_REFERER'};
my $QRY = $ENV{'QUERY_STRING'};
my $ref2 = $REF;
$ref2 =~ s/^(.*?)\?(.*?)$/$2/;

if ($link && $link == 1 || $ref) {
# Security issue 1
 if ($ref2 eq $QRY) {
  return;
 }
# Security issue 2
# May have problems, could be wrong.
 my $host_name = $ENV{'HTTP_HOST'} || '';
 if ($REF !~ m!^(.*?)\:\/\/$host_name((.*?)+)$!i) {
  return;
 }
 elsif (!$host_name) {
  return;
 }
}

# get referer codes
$REF =~ s/\;Flex\=(.*?)\|(.*?)$//;
my $ref_code = $1;
my $ref_date = $2;

# this can be uesd to check the propper Referer to go to this link.
# Need to supply the matching $ref veriable to use this or leave blank to not use.
if ($ref && $ref ne $REF) {
# bad code return home
 return;
}
# check the Referer code and date.
 if ($link && $link == 1) {
# Check inputs integrity
     if($ref_code !~ m!^([0-9a-z]+)$!i) {
     return;
     }
if (length($ref_code) < 40 || length($ref_code) > 40) {
return;
}
     if($ref_date !~ m!^([0-9]+)$!i) {
     return;
     }
if (length($ref_date) < 10 || length($ref_date) > 10) {
return;
}
# page expires
if ($ref_date < $date) {
# bad code returns nothing
 return;
}
$REF =~ s/^(.*?)\?(.*?)$/$2/;
 my $security_key = sha1_hex($REF,"$code$ref_date");
 if ($security_key ne $ref_code) {
# bad code returns nothing
  return;
 }
}
# get query codes
$QRY =~ s/\;Flex\=(.*?)\|(.*?)$//;
my $qry_code = $1;
my $qry_date = $2;
# Check inputs integrity
     if($qry_code !~ m!^([0-9a-z]+)$!i) {
     return;
     }
if (length($qry_code) < 40 || length($qry_code) > 40) {
return;
}

     if($qry_date !~ m!^([0-9]+)$!i) {
     return;
     }
if (length($qry_date) < 10 || length($qry_date) > 10) {
return;
}
# page expires
if ($qry_date < $date) {
# bad code returns nothing
 return;
}

# check the QUERY_STRING code and QUERY_STRING. (always on)
 my $security_key=sha1_hex($QRY,"$code$qry_date");
  if ($security_key ne $qry_code) {
   return;
  }
# looks good to x_secure
  return 1;
 }
 elsif ($act eq 3){
# ------------------------------------------------------------------------------
# Settup starting page
# ------------------------------------------------------------------------------

 my $QRY = $ENV{'QUERY_STRING'};

 if ($QRY !~ m!;Flex=(.+?)$!i && $QRY eq $link) {
 my $exp = time + 600;
 my $security_key = sha1_hex($QRY,"$code$exp");
 $security_key = $QRY . ';Flex=' . $security_key . '|' . $exp;

 return $security_key;
  }
 }
}

1;