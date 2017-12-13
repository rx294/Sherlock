# CAR_2016_03_002: Create Remote Process via WMIC

# Adversaries may use Windows Management Instrumentation (WMI) to move laterally,
# by launching executables remotely. The analytic CAR-2014-12-001: Remotely
# Launched Executables via WMI describes how to detect these processes with
# network traffic monitoring and process monitoring on the target host. However,
# if the command line utility wmic.exe is used on the source host, then it can
# additionally be detected on an analytic.
# The command line on the source host is constructed into something like wmic.exe
# /node:"<hostname>" process call create "<command line>". It is possible to also
# connect via IP address, in which case the string "<hostname>" would instead
# look like IP Address.

# Pseudocode

# Looks for instances of wmic.exe as well as the substrings in the command line
# * process call create
# * /node:

# processes = search Process:Create
# wmic = filter processes where (exe == "wmic.exe" and command_line == "* process call create *" and command_line == "* /node:*")
# output wmic


TECHNIQUES = ['Windows Management Instrumentation   ']
TACTICS = ['Execution']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2016_03_002():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where(col('event_data.Image').rlike("wmic.exe") & \
                                             col('event_data.CommandLine').rlike("(?=.* process call create )(?=.* /node:)"))
        return events