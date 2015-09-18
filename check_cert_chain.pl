#!/usr/bin/perl -I/usr/local/nagios/libexec/ -I/opt/tools/lib -I/opt/msp/pkg/nrpe/cfg
use strict;
use warnings;
use IO::Socket::SSL;
use Data::Dumper;
use Net::SSLeay;
use Time::gmtime;
use Time::ParseDate;
use lib "/usr/local/nagios/libexec" ;
use utils qw(%ERRORS &print_revision &support);
use vars qw($PROGNAME);
use Getopt::Long;

use vars qw($HOST $HELP $PORT $DEBUG $TIMEOUT $WARNING $CRITICAL);
$TIMEOUT = 20;
$HOST = $HELP = $PORT = $DEBUG = "";

Getopt::Long::Configure('bundling');
GetOptions
        ("h"   => \$HELP, "help"       => \$HELP,
	 "H=s"  => \$HOST, "hostname=s" => \$HOST,
	 "P=s"  => \$PORT, "port" => \$PORT,
	 "w=s"  => \$WARNING, "warning=s" => \$WARNING,
	 "c=s"  => \$CRITICAL, "critical=s" => \$CRITICAL,
	 "T=s"  => \$TIMEOUT, "timeout=s" => \$TIMEOUT,
	 "D=s"  => \$DEBUG, "debug=s" => \$DEBUG);

$PROGNAME = "check_cert_chain";
sub print_help ();
sub print_usage ();


$ENV{'PATH'}='';
$ENV{'BASH_ENV'}='';
$ENV{'ENV'}='';

if ($HELP) {
  &print_help();
}

if (! defined($HOST) || $HOST eq "") {
  print "ERROR - No Host supplied. Try $PROGNAME --help for more information\n";
  print_usage();
  exit $ERRORS{'CRITICAL'};
}

if (! defined($PORT) || $PORT eq "") {
  $PORT = 443;
}

if ($DEBUG) {
  $IO::Socket::SSL::DEBUG = 3;
}

if (! defined($WARNING) || $WARNING eq "") {
  $WARNING = 60;
}

if (! defined($CRITICAL) || $CRITICAL eq "") {
  $CRITICAL = 10;
}

my ($v_mode, $sock, $buf);
my $host = $HOST;
my $port = $PORT;

our %hash = ();
our $certNo = 0;
our $errFlag;

$sock = IO::Socket::SSL->new( PeerAddr => $host,
                                   PeerPort => $port,
                                   Proto    => 'tcp',
                                   SSL_verify_mode => 0x01,
                                   SSL_verify_callback => sub {
                                                                 my ($ok,$ctx_store,$certname,$error,$cert) = @_;
                                                                 #print "OpenSSL Status: [ $ok ]\n\nCertificate Name: [ $certname ]\n\nError: [ $error ]\n";

                                                                 my  $from = Net::SSLeay::X509_get_notBefore($cert);
                                                                 $hash{$certname}{'notBefore'} = Net::SSLeay::P_ASN1_UTCTIME_put2string($from);

                                                                 my  $to   = Net::SSLeay::X509_get_notAfter($cert);
                                                                 $hash{$certname}{'notAfter'}  = Net::SSLeay::P_ASN1_UTCTIME_put2string($to);

                                                                 #print  "From: " . Net::SSLeay::P_ASN1_UTCTIME_put2string($from) . "\n";
                                                                 #print  "To: "   . Net::SSLeay::P_ASN1_UTCTIME_put2string($to) . "\n";
                                                                 #print "-----------------------------------------------------\n\n";
                                                                 return 1;
                                                              },
				  SSL_error_trap => sub {
								my($sock,$msg) = @_;
								$errFlag = 1;
							}
                                 );
# Did we get a socket connection?

if (! $sock) {
  if (!(($errFlag == 1) && ((scalar keys %hash) > 0 ))) {
    print "CRITICAL - unable to create socket: ", &IO::Socket::SSL::errstr, "\n";
    exit $ERRORS{'CRITICAL'};
  }
} else {
  $sock->close();
}

if ($DEBUG) {
 print "CertInfo: " . Dumper(\%hash) . "\n";
}

my $name;
my $msg;
my $check_status = 1;

foreach $name (keys %hash) {
#   print "Cert [ " . $name . " ] \n\n";
   my ($val, $days) = check_dates ($hash{$name}{'notBefore'}, $hash{$name}{'notAfter'});
   if ($days <= $CRITICAL ) {
    $check_status = 0;
  } elsif ($days <= $WARNING && $check_status != 0) {
    $check_status = 2;
  }
}

if ($check_status == 0) {
  print "$msg\n";
  exit $ERRORS{'CRITICAL'};
} elsif ($check_status == 2) {
  print "$msg\n";
  exit $ERRORS{'WARNING'};
} else {
  print "$msg\n";
  exit $ERRORS{'OK'};
}

sub check_dates {
        my $valid = 1;
        my ( $date_before, $date_after ) = @_;

        my $date_before_epoch = parsedate($date_before);
        my $date_after_epoch  = parsedate($date_after);
        my $date_now_epoch    = time();

        # number of days
        my $daysleft = sprintf("%.f", ($date_after_epoch - $date_now_epoch) /(24 * 60 * 60 ));

        if ( $date_before_epoch > $date_now_epoch ) {
                $msg .= "Certificate not yet valid, ";
                $valid = 0;
        } elsif ( $date_after_epoch <= ( $date_now_epoch + ($CRITICAL * 24 * 60 * 60 ) ) ) {
                $msg .= "Critical - Certificate expired [days left: $daysleft], ";
                $valid = 0;
        } elsif ( $date_after_epoch <= ( $date_now_epoch + ( $WARNING * 24 * 60 * 60 ) ) ) {
                $msg .=  "Warning - Certificate expires in $WARNING days or less [days left: $daysleft], ";
		$valid = 2;
        } else {
                $msg .= "OK - Certificate valid [days left: $daysleft], ";
		$valid = 1;
        }
   return($valid, $daysleft);
}



sub print_usage () {
        print "Usage: $PROGNAME -H <host> [-P <port>] [-T TIMEOUT] [-D DEBUG]\n";
}

sub print_help () {
        print_revision($PROGNAME,'$Revision: 1.0 $');
        print "\n";
        print_usage();
        print "\n";
        print "<host> = Host to check cert chain\n";
	print "<port> = Port number to check.  Default is 443\n";
	print "<warning> = Warning.  Default is 60 days\n";
	print "<critical> = Critical.  Default is 10 seconds\n";
	print "<timeout> = Timeout.  Default is 20 seconds\n";
	print "<debug> = Debug mode\n";
}
