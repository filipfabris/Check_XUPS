# Check_XUPS

Starting script for checking Backup power UPS Alarms 

## Usage:
```
check_xups_alarms.py -H host_ip -C community_password -w warning_alarms -c critical_alarms
```

Example input:
```
check_apc.py -H xx.xxx.xxx.xx -w 1..3,11 -c 5,22 -C xxxxxxx
or
check_apc.pl -H xx.xxx.xxx.xx -w 1..3,11 -c 5,22 -C xxxxxxx
```

Example output:
```
No active alarms
0
```

## Perl and Python script

### Python
1.) Step\
`Define OID_UpsAlarmsPresent and OID_UpsAlarmsTable variable\`
OID_UpsAlarmsPresent = MIB_UPS_ALARMS + '.1.0'\
OID_UpsAlarmsTable = MIB_UPS_ALARMS + '.2'\`

### Perl
#### Modification of `check_apc.pl` from [Nagios Exchange](https://exchange.nagios.org/directory/Plugins/Hardware/UPS/APC/check_apc-2Epl/details)
1.) Step\
`Define OID_UpsAlarmsPresent and OID_UpsAlarmsTable variable\`
my $OID_UpsAlarmsPresent =   MIB_UPS_ALARMS . '.1.0';\
my $OID_UpsAlarmsTable =   MIB_UPS_ALARMS . '.2';\`

