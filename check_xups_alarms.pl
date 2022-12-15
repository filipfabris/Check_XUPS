#!/usr/bin/perl -w

use strict;
use SNMP;
use Net::SNMP qw(SNMP_VERSION_1);
use Getopt::Std;

use constant MIB_UPS_ALARMS => '1.3.6.1.4.1.534.1.7';

use constant EXAMPLE => "\n\n".
    "Example:\n".
    "\n".
    "./check_xups_alarms.pl -H 192.168.0.1 -w 1..4,11 -c 5..10 -C pass\n".
    "\n".
    "It checks host  192.168.0.1 (UPS-MIB SNMP compliant device) looking for any active alarm\n".
    "present in both warning and critical lists.\n".
    "Plugin returns CRITICAL one or more alarms with id 5 to 10 are active,\n".
    "and WARNING if one or more alarms with id 1, 2, 3, 4 or 11 are active.\n".
    "In both two cases a list of active alarm ids and descriptions is returned.\n".
    "In other case it returns OK if check has been successfully performed.";

my %options=();
getopts("H:C:p:t:w:c:hu", \%options);

my $Result;
my $Output;

# Nagios exit codes
my $OKAY        = 0;
my $WARNING     = 1;
my $CRITICAL    = 2;
my $UNKNOWN     = 3;

# Command arguments and defaults
my $snmp_host           = $options{H};
my $snmp_community      = $options{C};
my $snmp_port           = $options{p} || 161;   # SNMP port default is 161
my $connection_timeout  = $options{t} || 10;    # Connection timeout default 10s
my $default_error       = (!defined $options{u}) ? $CRITICAL : $UNKNOWN;
my $high_precision      = (defined $options{h}) ? 1 : 0;
my $critical            = $options{c};
my $warning             = $options{w};
my $session;
my $error;
my $exitCode;


# APCs have a maximum length of 15 characters for snmp community strings
if(defined $snmp_community) {$snmp_community = substr($snmp_community,0,15);}

# If we don't have the needed command line arguments exit with UNKNOWN.
if(!defined $options{H} || !defined $options{C}){
	print "Not all required options were specified.\n\n";
    exit $UNKNOWN;
}

# Setup the SNMP session
($session, $error) = Net::SNMP->session(
    -hostname   => $snmp_host,
    -community  => $snmp_community,
    -timeout    => $connection_timeout,
    -port       => $snmp_port,
    -translate  => [-timeticks => 0x0]
);

# If we cannot build the SMTP session, error and exit
if (!defined $session) {
    my $output_header = ($default_error == $CRITICAL) ? "CRITICAL" : "UNKNOWN";
    printf "$output_header: %s\n", $error;
    exit $default_error;
}

if (&CheckArguments($error)) {
    # Argument checking passed
    $Result = &PerformCheck($Output);
	print "$Output \n";
	print "$Result \n";
	exit $OKAY;
}
else {
    # Error checking arguments
    $Output = $error;
    $Result = $UNKNOWN;
	print "$Output \n";
	print "$Result \n";
	exit $UNKNOWN;
}

sub CheckArguments() {
    my @IfRange;
    my $ArgOK;
    my $ThresholdsFormat;
    my $WarningAlarm;
    my @WARange;
    my @WarningAlarms;
    my $WARangeLength;
    my $CriticalAlarm;
    my @CARange;
    my @CriticalAlarms;
    my $CARangeLength;

    #Check Warnings Alarms Number
    if ($warning =~ /^(\d+|\d+\.\.\d+)(,(\d+|\d+\.\.\d+))*$/) { #One or more digits
        @WarningAlarms = split(/,/, $warning);
        foreach $WarningAlarm(@WarningAlarms) {
            @WARange = split(/\.\./, $WarningAlarm);
            $WARangeLength = @WARange;
            if ($WARangeLength > 1){ #It is an alarm range
                if ($WARange[0] >= $WARange[1]){
                    $_[0] = "Invalid warning alarm range.The first number must be lower than the second one.";
                    return 0;
                }
                else{
                    if ($WARange[0] < 0 || $WARange[0] > 65535 || $WARange[1] < 0 || $WARange[1] > 65535 ) {
                        $_[0] = "Invalid warning alarm number";
                        return 0;
                    }
                }
            }
            else{ #It is an Alarm Id
                if ($WarningAlarm < 0 || $WarningAlarm > 65535) {
                    $_[0] = "Invalid warning alarm number";
                    return 0;
                }
            }
        }
    }
    else{
        $_[0] = "Invalid warning alarm expression";
        return 0;
    }

    #Check Critical Alarms Number
    if ($critical =~ /^(\d+|\d+\.\.\d+)(,(\d+|\d+\.\.\d+))*$/) { #One or more digits
        @CriticalAlarms = split(/,/, $critical);
        foreach $CriticalAlarm(@CriticalAlarms) {
            @CARange = split(/\.\./, $CriticalAlarm);
            $CARangeLength = @CARange;
            if ($CARangeLength > 1){ # It is an alarm range
                if ($CARange[0] >= $CARange[1]){
                    $_[0] = "Invalid critical alarm range.The first number must be lower than the second one.";
                    return 0;
                }
                else{
                    if ($CARange[0] < 0 || $CARange[0] > 65535 || $CARange[1] < 0 || $CARange[1] > 65535 ) {
                        $_[0] = "Invalid critical alarm number";
                        return 0;
                    }
                }
            }
            else{ # It is an Alarm Id
                if ($CriticalAlarm < 0 || $CriticalAlarm > 65535) {
                    $_[0] = "Invalid critical alarm number";
                    return 0;
                }
            }
        }
    }
    else{
        $_[0] = "Invalid critical alarm expression";
        return 0;
    }

    return 1;
}


# Performs whole check:
# Input: Nagios Plugin object
# Output: Plugin output string
# Return value: Plugin return value

sub PerformCheck() {
    my $OID_UpsAlarmsPresent =   MIB_UPS_ALARMS . '.1.0';
    my $OID_UpsAlarmsTable =   MIB_UPS_ALARMS . '.2';

    my $SNMPSession;
    my $SNMPError;
    my @descriptionOId;
    my $alarmId;

    my $PluginOutput;
    my $PluginReturnValue = $UNKNOWN;
    my @RangeWarningAlarms;
    my @RangeCriticalAlarms;

    ($SNMPSession, $SNMPError) = Net::SNMP->session(
        -hostname   => $snmp_host,
        -community  => $snmp_community,
        -timeout    => $connection_timeout,
        -port       => $snmp_port,
    );

    if (!defined($SNMPSession)) {
        $PluginOutput = "Error '$SNMPError' starting SNMP session";
    }
    else {
        my $RequestResult = $SNMPSession->get_request(-varbindlist => [ $OID_UpsAlarmsPresent]);
        if (! defined $RequestResult) {
            # SNMP query error
            $PluginOutput = "Error '$SNMPError' retrieving info ".
                "from agent ${snmp_host}:${snmp_port} "
        }
        else{
            my $upsAlarmsPresent = $RequestResult->{$OID_UpsAlarmsPresent};
            if ($upsAlarmsPresent == 0){
                # If no alarms presents everything is ok and plugin finishes
                $PluginReturnValue = $OKAY;
                $PluginOutput = "No active alarms";
            }
            else {
                # One or more alarms are active
                my $WarningOutput = '';
                my $CriticalOutput = '';
                my @WarningAlarms = split(/,/, $warning);
                my @CriticalAlarms = split(/,/, $critical);
                my $AlarmsTable = $SNMPSession->get_table(-baseoid =>$OID_UpsAlarmsTable);
                #$Data::Dumper::Pair = " : ";
                #print Dumper($AlarmsTable);
                my $AlarmsActive="";
                my @AlarmMessages;
                my $description;

                #Extracted from XUPS-MIB
                $AlarmMessages[1]=" ";
                $AlarmMessages[2]=" ";
                $AlarmMessages[3]="UPS On Battery";
                $AlarmMessages[4]="LowBattery";
                $AlarmMessages[5]="UtilityPowerRestored";
                $AlarmMessages[6]="ReturnFromLowBattery";
                $AlarmMessages[7]="OutputOverload";
                $AlarmMessages[8]="Power Supply Fault";
                $AlarmMessages[9]="BatteryDischarged";
                $AlarmMessages[10]="InverterFailure";
                $AlarmMessages[11]="OnBypass";
                $AlarmMessages[12]="BypassNotAvailable";
                $AlarmMessages[13]="OutputOff";
                $AlarmMessages[14]="Input power Fault";
                $AlarmMessages[15]="BuildingAlarm";
                $AlarmMessages[16]="ShutdownImminent";
                $AlarmMessages[17]="OnInverter";
                $AlarmMessages[18]=" ";
                $AlarmMessages[19]=" ";
                $AlarmMessages[20]="BreakerOpen";
                $AlarmMessages[21]="AlarmEntryAdded";
                $AlarmMessages[22]="AlarmEntryRemoved";
                $AlarmMessages[23]="BatteryNeedService";
                $AlarmMessages[24]="OutputOffAsRequested";
                $AlarmMessages[25]="DiagnosticTestFailed";
                $AlarmMessages[26]="CommunicationsLost";
                $AlarmMessages[27]="UpsShutdownPending";
                $AlarmMessages[28]="AlarmTestInProgress";
                $AlarmMessages[29]="Temperature Fault";
                $AlarmMessages[30]="LossOfRedundancy";
                $AlarmMessages[31]="InternalTempBad";
                $AlarmMessages[32]="ChargerFailed";
                $AlarmMessages[33]="FanFailure";
                $AlarmMessages[34]="FuseFailure";
                $AlarmMessages[35]="PowerSwitchBad";
                $AlarmMessages[36]="ModuleFailure";
                $AlarmMessages[37]="OnAlternatePowerSource";
                $AlarmMessages[38]="AltPowerNotAvailable";
                $AlarmMessages[39]="UPS Fault";
                $AlarmMessages[40]="RemoteTempBad";
                $AlarmMessages[41]="RemoteHumidityBad";

                while(my ($k,$v)=each(%{$AlarmsTable})) {
                    if ($k =~ /1\.3\.6\.1\.4\.1\.534\.1\.7\.2\.1\.2/i) {
                        @descriptionOId = split(/\./, $$AlarmsTable{$k});

                        $alarmId = $descriptionOId[$#descriptionOId];
                        #if ($alarmId!="") {$AlarmsActive .= "$alarmId, ";}
                        $description="";
                        # Check if the alarm is a WellKnownAlarms to add description
                        if ($alarmId <= $#AlarmMessages){
                            $description = "$AlarmMessages[$alarmId]"
                        }
                        # Check if alarmId is one value of the criticalAlarm array or if it is in a range of the array
                        for (my $j=0; $j <=$#CriticalAlarms; $j++) {
                            @RangeCriticalAlarms = split(/\.\./, $CriticalAlarms[$j]);
                            if( $#RangeCriticalAlarms ) {
                                # Checking range
                                if( $alarmId >= $RangeCriticalAlarms[0] && $alarmId <= $RangeCriticalAlarms[1] ) {
                                    $CriticalOutput .= "$description ";
                                }
                            }
                            else{
                                if ( $alarmId == $RangeCriticalAlarms[0] ){
                                    $CriticalOutput .= "$description ";
                                }
                            }
                        }

                        if ($CriticalOutput eq '') {
                            # No critical alarms present, search warning alarms
                            for (my $j=0; $j <=$#WarningAlarms; $j++) {
                                @RangeWarningAlarms = split(/\.\./, $WarningAlarms[$j]);
                                if( $#RangeWarningAlarms ) {
                                    #Checking range
                                    if( $alarmId >= $RangeWarningAlarms[0] && $alarmId <=$RangeWarningAlarms[1] ) {
                                        $WarningOutput .= "$description ";
                                    }
                                }
                                else {
                                    if ($alarmId == $RangeWarningAlarms[0] ) {
                                        $WarningOutput .= "$description ";
                                    }
                                }
                            }
                        }
                    }
                }
                if ( $CriticalOutput ne '' ) {
                    $PluginReturnValue = $CRITICAL;
                    $PluginOutput = $CriticalOutput;
                }
                elsif ( $WarningOutput ne '' ) {
                    $PluginReturnValue = $WARNING;
                    $PluginOutput = $WarningOutput;
                }
                else {
                    $PluginReturnValue = $OKAY;
                    substr($AlarmsActive,-2)='';#erases last comma and blank
                    $AlarmsActive="(".$AlarmsActive.")";
                    $PluginOutput = "No active Alarms";
                    # $PluginOutput = "Alarms active $AlarmsActive"." but not set in check lists";
                }
            }
        }

        # Close SNMP session
        $SNMPSession->close();
    }

    #Return result
    $_[0] = $PluginOutput;
    return $PluginReturnValue;
}




sub query_oid {
    # This function will poll the active SNMP session and return the value
    # of the OID specified. Only inputs are OID. Will use global $session
    # variable for the session.
    my $oid = $_[0];
    my $response = $session->get_request(-varbindlist => [ $oid ],);

    # If there was a problem querying the OID error out and exit
    if (!defined $response) {
        my $output_header = ($default_error == $CRITICAL) ? "CRITICAL" : "UNKNOWN";
        printf "$output_header: %s\n", $session->error();
        $session->close();
        exit $default_error;
    }

    return $response->{$oid};
}

# The end. We shouldn't get here, but in case we do exit unknown
print "UNKNOWN: Unknown script error\n";
exit $UNKNOWN;
