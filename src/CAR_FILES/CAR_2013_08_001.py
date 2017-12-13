# CAR_2013_08_001: Execution with schtasks
# The Windows built-in tool schtasks.exe provides the creation, modification, and
# running of scheduled tasks on a local or remote computer. It is provided as a
# more flexible alternative to at.exe, described in CAR-2013-05-004: Execution
# with AT. Although used by adversaries, the tool is also legitimately used by
# administrators, scripts, and software configurations.
# The scheduled tasks tool can be used to gain persistence and can be used in
# combination with a lateral movement technique to remotely gain execution

# Pseudocode
# Look for instances of schtasks.exe running as processes. The command_line field
# is necessary to disambiguate between types of schtasks commands. These include
# the flags /create, /run, /query, /delete, /change, and /end.

# process = search Process:Create
# schtasks = filter process where (exe == "schtasks.exe")
# output schtasks


TECHNIQUES = ['Scheduled Task']
TACTICS = ['Execution', 'Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2013_08_001():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where((col('event_data.Image') == "C:\\Windows\\System32\\schtasks.exe"))
        return events