# CAR_2013_05_004: Execution with AT

# In order to gain persistence, privilege escalation, or remote execution, an
# adversary may use the Windows built-in command AT (at.exe) to schedule a
# command to be run at a specified time, date, and even host. This method has
# been used by adversaries and administrators alike. Its use may lead to
# detection of compromised hosts and compromised users if it is used to move
# laterally.
# The built-in Windows tool schtasks.exe (CAR-2013-08-001: Execution with
# schtasks) offers greater flexibility when creating, modifying, and enumerating
# tasks. For these reasons, schtasks.exe is more commonly used by administrators,
# tools/scripts, and power users.

# Pseudocode
# Instances of the process at.exe running imply the querying or creation of
# tasks. Although the command_line is not essential for the analytic to run, it
# is critical when identifying the command that was scheduled.

# process = search Process:Create
# at = filter process where (exe == "at.exe")
# output at

TECHNIQUES = ['Scheduled Task']
TACTICS = ['Execution', 'Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2013_05_004():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where((col('event_data.Image') == "C:\\Windows\\System32\\at.exe"))
        return events