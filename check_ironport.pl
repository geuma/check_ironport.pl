#!/usr/bin/perl -w
#
# check_ironport.pl
# Copyright (C) 2011-2013 Stefan Heumader <stefan@heumader.at>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

use strict;
use warnings;

use File::Basename;
use Getopt::Long;
use Net::SNMP;

# Main values
my $PROGNAME = basename($0);
my $VERSION = '1.0';
my $TIMEOUT = 5;
my $DEBUG = 0;

# Nagios exit states
my %states = (
	OK       =>  0,
	WARNING  =>  1,
	CRITICAL =>  2,
	UNKNOWN  =>  3,
);

# Nagios state names
my %state_names = (
	0 => 'OK',
	1 => 'WARNING',
	2 => 'CRITICAL',
	3 => 'UNKNOWN',
);

# SNMP Data
my %oids = (
	# SYSTEM
	'perCentMemoryUtilization'			=> '1.3.6.1.4.1.15497.1.1.1.1',
	'perCentCPUUtilization'				=> '1.3.6.1.4.1.15497.1.1.1.2',
	'memoryAvailabilityStatus' 			=> '1.3.6.1.4.1.15497.1.1.1.7', 	# 1 OK, 2 WARNING, 3 CRITICAL
	'openFilesOrSockets'				=> '1.3.6.1.4.1.15497.1.1.1.19',

	# POWER SUPPLY
	'powerSupplyRedundancy' 			=> '1.3.6.1.4.1.15497.1.1.1.8.1.3', 	# 1 OK, 2 NOT OK
	'powerSupplyStatus'				=> '1.3.6.1.4.1.15497.1.1.1.8.1.2', 	# 1 NOT INSTALLED, 2 HEALTHY, 3 NoAC, 4 FAULTY

	# RAID
	'raidStatus'					=> '1.3.6.1.4.1.15497.1.1.1.18.1.2', 	# 1 HEALTHY, 2 FAILURE, 3 REBUILD
	'raidLastError'					=> '1.3.6.1.4.1.15497.1.1.1.18.1.4',

	# ENVIRONMENT
	'degreesCelsius'				=> '1.3.6.1.4.1.15497.1.1.1.9.1.2',

	# FEATURE KEYS & UPDATES
	'keySecondsUntilExpire'				=> '1.3.6.1.4.1.15497.1.1.1.12.1.2', 	# seconds to expire

	# MAIL SPECIFIC
	'c-workQueueMessages'				=> '1.3.6.1.4.1.15497.1.1.1.11', 	# amount of emails in workqueue
	'c-queueAvailabilityStatus' 			=> '1.3.6.1.4.1.15497.1.1.1.5', 	# 1 OK, 2 WARNING, 3 CRITICAL
	'c-resourceConservationReason' 			=> '1.3.6.1.4.1.15497.1.1.1.6',		# 1 OK, 2 MEMORY; 3 QUEUE SHORTAGE, 4 QUEUE FULL
	'c-perCentQueueUtilization'			=> '1.3.6.1.4.1.15497.1.1.1.4',
	'c-oldestMessageAge'				=> '1.3.6.1.4.1.15497.1.1.1.14', 	# seconds of oldest message in queue
	'c-mailTransferThreads'				=> '1.3.6.1.4.1.15497.1.1.1.20',
);

my $o_verb = undef;
my $o_help = undef;
my $o_version = undef;
my $o_host = undef;
my $o_port = 161;
my $o_community = undef;
my $o_snmpversion = undef;
my $o_timeout = 5;
my $o_warn = undef;
my $o_crit = undef;
my $o_category = undef;
my $o_licence = undef;
my @licence_categories = ();

# FUNCTIONS

sub p_version ()
{
	print "$PROGNAME version: $VERSION\n";
}

sub p_usage ()
{
	print "$PROGNAME usage: $0 [-v] -H <host> [-s <snmpversion>] -C <SNMPv12 Community|SNMPv3 password> [-p <port>] -w <warning_level> -c <critical_level> [-t <timeout>] [-V] -x <category> [-l <comma seperated licence items>]\n";
}

sub p_help ()
{
	print "\ncheck_ironport.pl - SNMP Ironport monitor PlugIn for Nagios in version $VERSION\n";
	print "Copyright (C) 2011-2013 Stefan Heumader <stefan\@heumader.at>\n\n";
	p_usage();
	print <<EOF;

-h, --help
	print this help message
-V, --version
	prints version number of Nagios PlugIn
-v, --verbose
	print extra debug informations
-H, --hostname=HOST
	name or IP address of host to check
-C, --community=COMMUNITY NAME
	SNMPv2 community name for the host's SNMP agent
	SNMPv3 user password
-P, --port=PORT
	SNMP port (default 161)
-s, --snmpversion=VERSION
	SNMP version (default 2)
-w, --warn=INTEGER
	warning threshold (necessary)
-c, --crit=INTEGER
	critical threshold (necessary)
-x, --category=STRING
	defines which information should be read (...)
-l, --licence=STRING
	comma septerated list of licence items
EOF
}

sub verbose ($)
{
	my $a = $_[0];
	print "$a\n" if defined($o_verb);
}

sub check_options ()
{
	Getopt::Long::Configure ("bundling");
	GetOptions(
		'v' 	=> \$o_verb,		'verbose'	=> \$o_verb,
		'h' 	=> \$o_help,		'help'		=> \$o_help,
		'V' 	=> \$o_version,		'version'	=> \$o_version,
		'H:s'	=> \$o_host,		'hostname:s'	=> \$o_host,
		'p:i'	=> \$o_port,		'port:i'	=> \$o_port,
		'C:s'	=> \$o_community,	'community:s'	=> \$o_community,
		's:i'   => \$o_snmpversion,	'snmpversion:i'	=> \$o_snmpversion,
		't:i'   => \$o_timeout,		'timeout:i'	=> \$o_timeout,
		'w:s'	=> \$o_warn,		'warn:s'	=> \$o_warn,
		'c:s'	=> \$o_crit,		'critical:s'	=> \$o_crit,
		'x:s'	=> \$o_category,	'category:s'	=> \$o_category,
		'l:s'	=> \$o_licence,		'licence:s'	=> \$o_licence,
	);

	if (defined($o_help))
	{
		p_help();
		exit $states{"UNKNOWN"};
	}

	if (defined($o_version))
	{
		p_version();
		exit $states{"UNKNOWN"};
	}

	unless (defined($o_host))
	{
		print "No host specified!\n";
		p_usage();
		exit $states{"UNKNOWN"};
	}

	unless (defined($o_community))
	{
		print "No community string specified!\n";
		p_usage();
		exit $states{"UNKNOWN"};
	}

	if (defined($o_snmpversion))
	{
		if ($o_snmpversion != 1 && $o_snmpversion != 2 && $o_snmpversion != 3)
		{
			print "Invalid SNMP version specified!\n";
			p_usage();
			exit $states{"UNKNOWN"};
		}
	}
	else
	{
		$o_snmpversion = 2;
	}

	if ($o_category eq 'keySecondsUntilExpire' && defined($o_licence))
	{
		@licence_categories = split(',', $o_licence);
	}
	elsif ($o_category eq 'keySecondsUntilExpire' && !defined($o_licence))
	{
		print "No licence keys specified!\n";
		p_usage();
		exit $states{"UNKNOWN"};
	}

	unless (defined($o_warn) && defined($o_crit))
	{
		print "No warning or critical thresholds specified!\n";
		p_usage();
		exit $states{"UNKNOWN"};
	}

	# delete % characters if any
	$o_warn =~ s/\%//g;
	$o_crit =~ s/\%//g;

	# validate category input
	my $valid_cat = 0;
	foreach (keys %oids)
	{
		if ($o_category eq $_)
		{
			$valid_cat = 1;
		}
	}
	unless ($valid_cat)
	{
	        print "Invalid category specified!\n";
		p_usage();
		exit $states{"UNKNOWN"};
	}
}

# MAIN

check_options();

if (defined($TIMEOUT))
{
	verbose("Alarm at $TIMEOUT + 5");
	alarm($TIMEOUT+5);
}
else
{
	verbose("No timeout defined!\nAlarm at $o_timeout + 10");
	alarm ($o_timeout+10);
}

# Connect to Host
my %snmpconfig = (
	-hostname => $o_host,
	-version => $o_snmpversion,
	-port => $o_port,
	-timeout => $o_timeout,
);
if ($o_snmpversion == 1 || $o_snmpversion == 2)
{
	$snmpconfig{'-community'} = $o_community;
}
elsif ($o_snmpversion == 3)
{
	$snmpconfig{'-username'} = 'v3get';
	$snmpconfig{'-authpassword'} = $o_community;
}
my ($session, $error) = Net::SNMP->session(%snmpconfig);

unless (defined($session))
{
	print ("ERROR: opening SNMP session: $error\n");
	exit $states{'UNKNOWN'};
}

if ($DEBUG)
{
	my $mask = 0x02;
	$mask = $session->debug([$mask]);
}

# Read Result
my $result = $session->get_table(
	-baseoid => $oids{$o_category}
);

unless (defined($result))
{
	print "ERROR: ".$session->error()."\n";
	$session->close;
	exit $states{'UNKNOWN'};
}

my $value = 0;
my @results = ();
foreach (keys %$result)
{
	verbose("OID: $_, Desc: $$result{$_}");
	unless ($$result{$_} eq "endOfMibView")
	{
		if ($o_category eq 'raidLastError')
		{
			$value = $$result{$_} if $$result{$_} ne 'No Errors';
		}
		elsif ($o_category eq 'keySecondsUntilExpire')
		{
			my $tmp = $$result{$_};
			my @results = grep(/$tmp/, @licence_categories);
			$value = 9999999; # we need to set it to a really high value ...
			if (grep(/$tmp/, @licence_categories))
			{
				my $new_oid = $_;
				$new_oid =~ s/1.3.6.1.4.1.15497.1.1.1.12.1.2/1.3.6.1.4.1.15497.1.1.1.12.1.4/;

				my $result2 = $session->get_request(
					-varbindlist => [$new_oid,],
				);
				foreach (keys %$result2)
				{
					verbose("OID: $_, Desc: $$result2{$_}");
				}
				$$result2{$new_oid} = int($$result2{$new_oid}/86400);
				print STDERR  $$result2{$new_oid}."\n";
				$value = $$result2{$new_oid} if $$result2{$new_oid} < $value;
			}
		}
		else
		{
			$value = $$result{$_} if $$result{$_} > $value;
		}
	}
}
$session->close;

my $exit_code = $states{"OK"};
if ($o_category eq 'raidLastError')
{
	if ($value eq 'No Errors' || $value eq 'ACTIVE' || $value eq '0')
	{
		print "SNMP $o_category OK: $value\n";
		$exit_code = $states{"OK"};
	}
	else
	{
		print "SNMP $o_category CRITICAL: $value\n";
		$exit_code = $states{'CRITICAL'};
	}
}
elsif ($o_category eq 'keySecondsUntilExpire')
{
	if ($value > $o_warn)
	{
		print "SNMP $o_category OK: $value > $o_warn\n";
	}
	elsif ($value > $o_crit)
	{
		print "SNMP $o_category WARNING: $value > $o_crit\n";
		$exit_code = $states{'WARNING'};
	}
	else
	{
		print "SNMP $o_category CRITICAL: $value < $o_crit\n";
		$exit_code = $states{'CRITICAL'};
	}
}
elsif ($o_category eq 'memoryAvailabilityStatus' || $o_category eq 'c-queueAvailabilityStatus')
{
	if ($value == 1)
	{
		print "SNMP $o_category OK: $value = 1\n";
	}
	elsif ($value == 2)
	{
		print "SNMP $o_category WARNING: $value = 2\n";
		$exit_code = $states{'WARNING'};
	}
	elsif ($value == 3)
	{
		print "SNMP $o_category CRITICAL: $value = 3\n";
		$exit_code = $states{'CRITICAL'};
	}
}
elsif ($o_category eq 'powerSupplyRedundancy')
{
	if ($value == 1)
	{
		print "SNMP $o_category OK: $value = 1\n";
	}
	elsif ($value == 2)
	{
		print "SNMP $o_category CRITICAL: $value = 2\n";
		$exit_code = $states{'CRITICAL'};
	}
}
elsif ($o_category eq 'c-resourceConservationReason')
{
	if ($value == 1)
	{
		print "SNMP $o_category OK: $value = 1\n";
	}
	elsif ($value == 2 || $value == 3)
	{
		print "SNMP $o_category WARNING: $value = 2 (MEMORY)\n" if $value == 2;
		print "SNMP $o_category WARNING: $value = 3 (QUEUE SHORTAGE)\n" if $value == 3;
		$exit_code = $states{'WARNING'};
	}
	elsif ($value == 4)
	{
		print "SNMP $o_category CRITICAL: $value = 4 (QUEUE FULL)\n";
		$exit_code = $states{'CRITICAL'};
	}
}
elsif ($o_category eq 'raidStatus')
{
	if ($value == 1)
	{
		print "SNMP $o_category OK: $value = 1\n";
	}
	elsif ($value == 2)
	{
		print "SNMP $o_category CRITICAL: $value = 2 (FAILURE)\n";
		$exit_code = $states{'CRITICAL'};
	}
	elsif ($value == 3)
	{
		print "SNMP $o_category WARNING: $value = 3 (REBUILD)\n";
		$exit_code = $states{'WARNING'};
	}
}
elsif ($o_category eq 'powerSupplyStatus')
{
	if ($value == 2)
	{
		print "SNMP $o_category OK: $value = 2 (HEALTHY)\n";
	}
	elsif ($value == 3)
	{
		print "SNMP $o_category WARNING: $value = 3 (NoAC)\n";
		$exit_code = $states{'WARNING'};
	}
	elsif ($value == 4)
	{
		print "SNMP $o_category CRITICAL: $value = 4 (FAULTY)\n";
		$exit_code = $states{'CRITICAL'};
	}
}
else
{
	if ($value > $o_crit)
	{
		print "SNMP $o_category CRITICAL: $value > $o_crit|$o_category=$value;$o_warn;$o_crit\n";
		$exit_code = $states{'CRITICAL'};
	}
	elsif ($value > $o_warn)
	{
		print "SNMP $o_category WARNING: $value > $o_warn|$o_category=$value;$o_warn;$o_crit\n";
		$exit_code = $states{'WARNING'};
	}
	else
	{
		print "SNMP $o_category OK: $value < $o_warn|$o_category=$value;$o_warn;$o_crit\n";
	}
}
exit $exit_code;
