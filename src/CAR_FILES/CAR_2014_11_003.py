# CAR-2014-11-003: Debuggers for Accessibility Applications

# The Windows Registry location "HKLM\Software\Microsoft\Windows
# NT\CurrentVersion\Image File Execution Options" allows for parameters to be set
# for applications during execution. One feature used by malicious actors is the
# "Debugger" option. When a key has this value enabled, a Debugging command line
# can be specified. Windows will launch the Debugging command line, and pass the
# original command line in as an argument.
# Adversaries can set a Debugger for Accessibility Applications. The analytic
# looks for the original command line as an argument to the Debugger.
# When the strings "sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", and
# "Magnify.exe" are detected in the arguments, but not as the main executable, it
# is very likely that a Debugger is set.

TECHNIQUES = ['Accessibility Features']
TACTICS = ['Execution', 'Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2014_11_003():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where(col('event_data.CommandLine').rlike("$.* .*(sethc|utilman|osk|narrator|magnify)\.exe"))
        return events