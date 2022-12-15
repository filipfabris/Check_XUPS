#! /usr/bin/python

from pysnmp import hlapi
import getopt
import sys
import re

# Define oids
MIB_UPS_ALARMS = "1.3.6.1.4.1.534.1.7"


class CheckXUPS:
    help = """ Usage:
            -H  Address of hostname of UPS (required)
            -C  SNMP community string (required)
            -l  Command (optional, see command list)
            -p  SNMP port (optional, defaults to port 161)
            -c critical alarms
            -w warning alarms

            Commands (supplied with -l argument):
            
                manufacturer
                    manufacturer details

            Example:
            ./check_xups_alarms.py -H 10.xxx.xxxx.xx -C pass -w 1..4,11 -c 5..10
            """
    OKAY = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3

    def __init__(self):
        self.snmp_host = None
        self.snmp_community = None
        self.snmp_port = None
        self.warnings = None
        self.critical = None

        self.exitCode = None
        self.outputValue = None

        self.setup()

    def setup(self):
        argv = sys.argv[1:]
        # print(argv)

        try:
            opts, args = getopt.getopt(argv, "H:C:l:p:t:w:c:hu")
        except getopt.GetoptError as err:
            print(str(err).upper())
            return

        for opt, arg in opts:
            if opt in ['-H']:
                self.snmp_host = arg
            elif opt in ['-C']:
                self.snmp_community = hlapi.CommunityData(arg)
            elif opt in ['-p']:
                self.snmp_port = arg
            elif opt in ['-c']:
                self.critical = arg
            elif opt in ['-w']:
                self.warnings = arg

        if self.snmp_host is None or self.snmp_community is None:
            print("snmp_host -H or snmp_community -C is not defined")
            exit(1)

        if self.warnings is None or self.critical is None:
            print("alarms are not defined")
            print(self.help)
            exit(2)

        self.execute()

    def execute(self):

        if self.checkArguments():

            self.performCheck()

            if self.exitCode == self.CRITICAL:
                print("CRITICAL")
                # Do something
            elif self.exitCode == self.WARNING:
                print("WARNING")
                # Do something
            elif self.exitCode == self.OKAY:
                print("OKAY")
                # Nothing to do

            print(self.outputValue)
            return

    def checkArguments(self):
        if re.findall('^(\d+|\d+\.\.\d+)(,(\d+|\d+\.\.\d+))*$', self.warnings):
            WarningAlarms = re.split(',', self.warnings)
            self.warnings = []
            for element in WarningAlarms:
                WARange = re.split('\.\.', element)
                WARange = [int(numeric_string) for numeric_string in WARange]  # Convert to integers
                if len(WARange) > 1:  # It is an alarm range
                    if WARange[0] > WARange[1]:
                        print("Invalid warning alarm range.The first number must be lower than the second one.")
                        return 0
                    else:
                        if WARange[0] < 0 or WARange[0] > 65535 or WARange[1] < 0 or WARange[1] > 65535:
                            print("Invalid warning alarm number")
                            return 0
                    # Dobar unos
                    for x in range(WARange[0], WARange[1]):
                        self.warnings.append(x)
                else:  # It is an AlarmId
                    element = int(element)  # Convert to integer
                    if element < 0 or element > 65535:
                        print("Invalid warning alarm number")
                        return 0
                    self.warnings.append(element)

            if re.findall('^(\d+|\d+\.\.\d+)(,(\d+|\d+\.\.\d+))*$', self.critical):
                CriticalAlarms = re.split(',', self.critical)
                self.critical = []
                for element in CriticalAlarms:
                    CRange = re.split('\.\.', element)
                    CRange = [int(numeric_string) for numeric_string in CRange]  # Convert to integers
                    if len(CRange) > 1:  # It is an alarm range
                        if CRange[0] > CRange[1]:
                            print("Invalid warning alarm range.The first number must be lower than the second one.")
                            return 0
                        else:
                            if CRange[0] < 0 or CRange[0] > 65535 or CRange[1] < 0 or CRange[1] > 65535:
                                print("Invalid warning alarm number")
                                return 0
                        # Dobar unos
                        for x in range(CRange[0], CRange[1]):
                            self.critical.append(x)
                    else:  # It is an AlarmId
                        element = int(element)  # Convert to integer
                        if element < 0 or element > 65535:
                            print("Invalid warning alarm number")
                            return 0
                        self.critical.append(element)
        return 1

    def performCheck(self):
        OID_UpsAlarmsPresent = MIB_UPS_ALARMS + '.1.0'
        OID_UpsAlarmsTable = MIB_UPS_ALARMS + '.2'

        # Vraca dictionary OID: broj alarma
        RequestResult = self.get(self.snmp_host, [OID_UpsAlarmsPresent], self.snmp_community)

        presentAlarm = RequestResult[OID_UpsAlarmsPresent]

        if presentAlarm == 0:
            #If no alarms presents everything is ok and plugin finishes
            self.exitCode = self.OKAY
            self.outputValue = "No active alarms"
            return
        else:
            # Extracted from XUPS-MIB
            AlarmMessagesDitc = {1: "", 2: "", 3: "UPS On Battery", 4: "LowBattery", 5: "UtilityPowerRestored",
                                 6: "ReturnFromLowBattery", 7: "OutputOverload", 8: "Power Supply Fault",
                                 9: "BatteryDischarged", 10: "InverterFailure", 11: "OnBypass",
                                 12: "BypassNotAvailable", 13: "OutputOff", 14: "Input power Fault",
                                 15: "BuildingAlarm", 16: "ShutdownImminent", 17: "OnInverter", 18: "", 19: "",
                                 20: "BreakerOpen", 21: "AlarmEntryAdded", 22: "AlarmEntryRemoved",
                                 23: "BatteryNeedService", 24: "OutputOffAsRequested", 25: "DiagnosticTestFailed",
                                 26: "CommunicationsLost", 27: "UpsShutdownPending", 28: "AlarmTestInProgress",
                                 29: "Temperature Fault", 30: "LossOfRedundancy", 31: "InternalTempBad",
                                 32: "ChargerFailed", 33: "FanFailure", 34: "FuseFailure", 35: "PowerSwitchBad",
                                 36: "ModuleFailure", 37: "OnAlternatePowerSource", 38: "AltPowerNotAvailable",
                                 39: "UPS Fault", 40: "RemoteTempBad", 41: "RemoteHumidityBad"}

            AlarmsTable = self.get(self.snmp_host, [OID_UpsAlarmsTable], self.snmp_community)
            foundWaring = 0
            foundCritical = 0
            description = ""

            for elem in AlarmsTable.keys():

                key = re.findall('1.3.6.1.4.1.534.1.7.2.1.(\d)', elem)
                key = 3
                if key: #Exists not null
                    key = int(key)

                    if key in self.critical:
                        desc = "CRITICAL ALARM: " + AlarmMessagesDitc[key] + "OID: " + elem + "\n"
                        description += desc
                        foundCritical = 1

                    elif key in self.warnings:
                        desc = "WARNING ALARM: " + AlarmMessagesDitc[key] + "OID: " + elem + "\n"
                        description += desc
                        foundWaring = 1

            if foundCritical == 1:
                self.exitCode = self.CRITICAL
            elif foundWaring == 1:
                self.exitCode = self.WARNING
            else:
                self.exitCode = self.OKAY
                description = "No active Alarms"

            self.outputValue = description

            return

    @staticmethod
    def construct_object_types(list_of_oids):
        object_types = []
        for oid in list_of_oids:
            object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
        return object_types

    @staticmethod
    def cast(value):
        try:
            return int(value)
        except (ValueError, TypeError):
            try:
                return float(value)
            except (ValueError, TypeError):
                try:
                    return str(value)
                except (ValueError, TypeError):
                    pass
        return value

    def fetch(self, handler, count):
        result = []
        for i in range(count):
            try:
                error_indication, error_status, error_index, var_binds = next(handler)
                if not error_indication and not error_status:
                    items = {}
                    for var_bind in var_binds:
                        items[str(var_bind[0])] = self.cast(var_bind[1])
                    result.append(items)
                else:
                    raise RuntimeError('Got SNMP error: {0}'.format(error_indication))
            except StopIteration:
                break
        return result

    def get(self, target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
        handler = hlapi.getCmd(
            engine,
            credentials,
            hlapi.UdpTransportTarget((target, port)),
            context,
            *self.construct_object_types(oids)
        )
        return self.fetch(handler, 1)[0]


def main():
    apc = CheckXUPS()


if __name__ == "__main__":
    main()
