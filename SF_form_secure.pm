package SF_form_secure;

delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
use strict;
use Digest::SHA1 qw(sha1_hex);
use vars qw($VERSION %x_error);

$VERSION = 3.0;

# Error List
%x_error = (
       a => 'Referer and Query String match.',
       b => 'Referer is to long.',
       c => 'Referer is not from HTTP Host.',
       e => 'Referers do not Match.',
       f => 'Bad code format.',
       h => 'Page expired.',
       i => 'Referer encoding is bad.',
       m => 'Query String encoding is bad.'
    );

# Main Function
sub x_secure {
my ($act, $code, $link, $ref, $exp, $ip_ct) = @_;

if (!$exp) {
    $exp = '';
}
# bound code to remote ip
if ($ip_ct eq 'ip') {
    $ip_ct = $ENV{REMOTE_ADDR};
}
else {
      $ip_ct = '';
      }
# ------------------------------------------------------------------------------
# return secure link (makes secure link)
# ------------------------------------------------------------------------------
 if ($act eq 1 && $link && $code) {
# Allow experation times 1 up to 99 minutes
  $exp = x_time_cal($exp);
  my $security_key = x_code_maker($code, $exp, $link, $ip_ct);
  $security_key = $link . ';Flex=' . $security_key . '|' . $exp;
  return $security_key;
 }
 elsif ($act eq 2 && $code) {
# ------------------------------------------------------------------------------
# return 1 for good link or nothing for bad.
# ------------------------------------------------------------------------------

# Get Referer and link Query String
my $REF = $ENV{'HTTP_REFERER'};
my $QRY = $ENV{'QUERY_STRING'};
my $ref2 = x_regex($REF);

if ($link && $link =~ m!^(1|3)$!i || $ref) {
my $host_name = $ENV{'HTTP_HOST'} || '';
# Security issue 1
 if ($ref2 eq $QRY) {
  return $x_error{a};
 }
# Security issue 2
 if (length($REF) > 1024) {
  return $x_error{b};
 }
 # Security issue 3
 if ($REF !~ m!^(http|https)\:\/\/$host_name((.*?)+)$!i) {
  return $x_error{c};
 }
}

# get referer codes
$REF =~ s/\;Flex\=(.*?)\|(.*?)$//;
my $ref_code = $1;
my $ref_date = $2;

# Mach Referer with one given.
if ($ref && $ref ne $REF) {
 return $x_error{e};
}

# check the Referer code and/or date.
 if ($link && ($link == 1 || $link == 3)) {

# Check input integrity
 my $ref_input = x_bad_input($ref_code, $ref_date);
     if($ref_input) {
     return $ref_input;
     }
# page expires
my $expir = x_code_expires($exp, $ref_date);
if ($expir) {
 return $expir;
}

$REF = x_regex($REF);
 my $security_key = x_code_maker($code, $ref_date, $REF, $ip_ct);
 if ($security_key ne $ref_code) {
  return $x_error{i};
 }
}
# check the query code and/or date.
if ($link && ($link == 2 || $link == 3)) {

# get query codes
$QRY =~ s/\;Flex\=(.*?)\|(.*?)$//;
my $qry_code = $1;
my $qry_date = $2;

# Check input integrity
 my $qry_input = x_bad_input($qry_code, $qry_date);
     if($qry_input) {
     return $qry_input;
     }
# page expires
my $expir = x_code_expires($exp, $qry_date);
if ($expir) {
 return $expir;
}
# check the QUERY_STRING code.
 my $security_key = x_code_maker($code, $qry_date, $QRY, $ip_ct);
  if ($security_key ne $qry_code) {
   return $x_error{m};
  }
}
# looks good to x_secure
  return 1;
 }
 elsif ($act eq 3 && $code){
# ------------------------------------------------------------------------------
# Settup starting page
# ------------------------------------------------------------------------------
# Returns The Query String with Encoding to be used in a redirect.
 my $QRY = $ENV{'QUERY_STRING'};
 if ($QRY !~ m!;Flex=(.+?)$!i && $QRY eq $link) {
 $exp = x_time_cal($exp);
 my $security_key = x_code_maker($code, $exp, $QRY, $ip_ct);
 $security_key = $QRY . ';Flex=' . $security_key . '|' . $exp;
 return $security_key;
  }
 }
}

sub x_code_expires {
my ($expdate,$datein) = @_;
my $date = time;
 if ($expdate && $expdate =~ m!^([0-9]+)$!i && length($expdate) <= 2 && $datein < $date) {
      return $x_error{h};
 }
}

sub x_regex {
my $regex = shift;
$regex =~ s/^(.*?)\?(.*?)$/$2/;
return $regex;
}

sub x_bad_input {
my ($codein, $datein) = @_;
     if($codein !~ m!^([0-9a-z]+)$!i) {
         return $x_error{f};
     }
     if (length($codein) < 40 || length($codein) > 40) {
         return $x_error{f};
     }
     if($datein !~ m!^([0-9]+)$!i) {
     return $x_error{f};
     }
     if (length($datein) < 10 || length($datein) > 10) {
         return $x_error{f};
     }
}

sub x_code_maker {
my ($codea, $datea, $QRYa, $ip_cta) = @_;
 $codea = $codea . $datea . $ip_cta;
 my $security_keya = sha1_hex($QRYa, $codea);
 return $security_keya;
}

sub x_time_cal {
my $limit = shift;
# Allow experation times 1 up to 99 minutes
if ($limit =~ m!^([0-9]+)$!i && length($limit) <= 2) {
  $limit = 60 * $limit;
  $limit = time + $limit;
  }
  else {
# No experation
  $limit = time;
  }
  return $limit;
}

1;
__END__

=head1 COPYLEFT

 By: $|-|4X4_|=73}{ N.K.A (sflex@cpan.org)
 File: SF_form_secure.pm
 Version: 3.0 10/22/2006 11:04:23

 This file is a Perl Module.

=head1 NAME

 SF_form_secure Module

=head1 DESCRIPTION

 Data integrity of link and referer data.
 Good URL anti-tampering methods.
 Must Provide a secret key.
 Controle the expiration funtion and minutes used 1 to 99, blank is off.
 Can use Remote IP in encoding.
 Many security level Combos 4 examples!
 Check referer encoding, and/or maching referer.
 Checks incoming QUERY_STRING encoding is correct.
 Returns the number 1 if Check is ok.
 Returns English Text if Check is Bad.

 This file does not have many hours of testing.
 Please Report all Bugs and report if all go's well!

=head1 IMPROVEMENTS

 v3.0 - 10/22/2006 11:04:23
 Fixed SYNOPSIS Text to reflect current script.
 Changed POD location to bottum of file with __END__.
 Added $VERSION and use vars qw($VERSION %x_error); to top of file.
 Removed my from %x_error.

 v2.1 - 10/22/2006 08:53:47
 Fixed version Time made in COPYLEFT and IMPROVEMENTS, to propper time.
 Fixed DESCRIPTION and SYNOPSIS Text to reflect current script.

 v2.0 - 10/22/2006 10:30:55
 Better regular expression for "# Security issue 3".
 Reports Text Errors.
 Controle the time stamp funtion and minutes used 1 to 99, blank is off.
 Use Remote IP in encoding.
 Added x_time_cal, x_code_make, x_regex, x_bad_input and x_code_expires to reduce script size.
 The new Changes Expand the security levels to allow many combos.
 Returns the number 1 if Check is ok.
 Returns English Text if Check is Bad.

=head1 SUPPORT

 1) Must Provide the same secret key for all action types.
 2) Must Provide the same  time and/or ip setting for all actions.

=head1 SYNOPSIS

 Required!
 Perl 5.0 or up
 Digest::SHA1

 Usage:

 Load the module
 require SF_form_secure;

 -------------------------------------------------------------------------------

 Set page up for self encoding if encoding is missing
 3 - is the action type
 $key - Must Provide a secret key.
 'op=testForm;module=Flex_Form' - to work, must provide a matching self link
 '' - not used for this action
 '' - Minutes code will expire in 1 to 99, blank is off..
 'ip' - use Remote IP in encoding, blank is off.

 my $sec_self = SF_form_secure::x_secure('3', $key, 'op=testForm;module=Flex_Forma', '', '', 'ip');
 if ($sec_self) {
 print "Location: http://www.domain.com/index.cgi?$sec_self\n\n";
 }
 -------------------------------------------------------------------------------

 This makes encoded links for the next page
 1 - is the action type
 $key - Must Provide a secret key.
 'op=testForm2;module=Flex_Form' - The link to encode
 '' - not used for this action
 '' - Minutes code will expire in 1 to 99, blank is off..
 'ip' - use Remote IP in encoding, blank is off.

 my $secure_link = SF_form_secure::x_secure(1, $key, 'op=testForm2;module=Flex_Forma', '', '', 'ip');

 example of $secure_link = 'op=testForm;module=Flex_Forma;Flex=e690dec564cf52fcfcc967a9d5c079a7687f87d1|1161373021';
 1161373021 date is bound in encoding.

 -------------------------------------------------------------------------------

 Full Security - To get to this area the referer must match the one given, the incoming link and past referer encoding must be correct.
 2 - is the action type
 $key - Must Provide a secret key.
 3 - 1 Check Referer encoding, 2 Check link encoding, 3 Check Both, Blank is off
 "http://www.domain.com/index.cgi?op=testForm;module=Flex_Form" - Match this Referer, Blank is off
 '' - Minutes code will expire in 1 to 99, blank is off..
 'ip' - use Remote IP in encoding, blank is off.

 my $secure_check = SF_form_secure::x_secure(2, $key, 3, "http://www.domain.com/index.cgi?op=testForm;module=Flex_Forma", '', 'ip');
 if ($secure_check ne 1) {
 print $secure_check;
 }

 -------------------------------------------------------------------------------

 Medium Security 1 - To get to this area the referer must match the one given and incoming link encoding must be correct.
 2 - is the action type
 $key - Must Provide a secret key.
 2 -  1 Check Referer encoding, 2 Check link encoding, 3 Check Both, Blank is off
 "http://www.domain.com/index.cgi?op=testForm;module=Flex_Form" - Match this Referer, Blank is off
 '' - Minutes code will expire in 1 to 99, blank is off..
 'ip' - use Remote IP in encoding, blank is off.

 my $secure_check = SF_form_secure::x_secure(2, $key, 2, "http://www.domain.com/index.cgi?op=testForm;module=Flex_Form", '', 'ip');
 if ($secure_check ne 1) {
 print $secure_check;
 }

 -------------------------------------------------------------------------------

 Medium Security 2 - To get to this area the referer encoding and incoming link encoding must be correct.
 2 - is the action type
 $key - Must Provide a secret key.
 3 -  1 Check Referer encoding, 2 Check link encoding, 3 Check Both, Blank is off
 '' - Match this Referer, Blank is off
 '' - Minutes code will expire in 1 to 99, blank is off..
 'ip' - use Remote IP in encoding, blank is off.

 my $secure_check = SF_form_secure::x_secure(2, $key, 3, '', '', 'ip');
 if ($secure_check ne 1) {
 print $secure_check;
 }

 -------------------------------------------------------------------------------

 Low Security - To get to this area the incoming link encoding must be correct.
 2 - is the action type
 $key - Must Provide a secret key.
 2 -  1 Check Referer encoding, 2 Check link encoding, 3 Check Both, Blank is off
 '' - Match this Referer, Blank is off
 '' - Minutes code will expire in 1 to 99, blank is off..
 'ip' - use Remote IP in encoding, blank is off.

 my $secure_check = SF_form_secure::x_secure(2, $key, 2, '', '', 'ip');
 if ($secure_check ne 1) {
 print $secure_check;
 }

 Note: To Provide a uniqe link others can not use
 Format the provided key something like this
 $key = $key . $Member_Name;
 and/or
 use the IP encoding
 the new key format and/or ip encoding will need to be used for all actions

=head1 FUNCTION

 The function available from this package:

=head2 x_secure()

 Main Function

=cut