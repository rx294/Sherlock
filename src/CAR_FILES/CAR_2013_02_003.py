# CAR-2013-02-003: Processes Spawning cmd.exe

# The Windows Command Prompt (cmd.exe) is a utility that provides a command line
# interface to Windows operating systems. It provides the ability to run
# additional programs and also has several built-in commands such as dir,
# copy,mkdir, and type, as well as batch scripts (.bat).
# Typically, when a user runs a command prompt, the parent process is
# explorer.exe or another instance of the prompt. There may be automated
# programs, logon scripts, or administrative tools that launch instances of the
# command prompt in order to run scripts or other built-in commands. Spawning the
# process cmd.exe from certain parents may be more indicative of malice.
# For example, if Adobe Reader or Outlook launches a command shell, this may
# suggest that a malicious document has been loaded and should be investigated.
# Thus, by looking for abnormal parent processes of cmd.exe, it may be possible
# to detect adversaries.



TECHNIQUES = ['Command-Line Interface']
TACTICS = ['Execution']
DURATION_MINS = 60*6

from pyspark.sql.functions import *

class CAR_2013_02_003():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where((col('event_data.Image') == 'C:\Windows\System32\cmd.exe'))
        events = events.where((col('event_data.ParentImage') != "C:\\Windows\\explorer.exe"))
        return events
