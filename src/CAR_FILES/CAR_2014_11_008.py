# CAR_2014_11_008: Command Launched from WinLogon

# An adversary can use accessibility features (Ease of Access), such as
# StickyKeys or Utilman, to launch a command shell from the logon screen and gain
# SYSTEM access. Since an adversary does not have physical access to the machine,
# this technique must be run within Remote Desktop. To prevent an adversary from
# getting to the login screen without first authenticating, Network-Level
# Authentication (NLA) must be enabled.
# If a debugger is set up for one of the accessibility features, then it will
# intercept the process launch of the feature and instead execute a new command
# line. This analytic looks for instances of cmd.exe or powershell.exe launched
# directly from the logon process, winlogon.exe. It should be used in tandem with
# CAR-2014-11-003: Debuggers for Accessibility Applications, which detects the
# accessibility programs in the command line.

# Pseudocode
# Look for instances of processes where the parent executable is winlogon.exe and the 
# child is an instance of a command prompt.

# processes = search Process:Create
# winlogon_cmd = filter processes where (parent_exe == "winlogon.exe" and exe == "cmd.exe")
# output winlogon_cmd


TECHNIQUES = ['Accessibility Features']
TACTICS = ['Execution', 'Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2014_11_008():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where(col('event_data.Image').rlike("cmd.exe|powershell.exe"))
        events = events.where((col('event_data.ParentImage').rlike("winlogon.exe")))
        return events

