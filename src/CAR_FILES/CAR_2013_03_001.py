# CAR_2013_03_001: Reg.exe called from Command Shell

# Registry modifications are often essential in establishing persistence via
# known Windows mechanisms. Many legitimate modifications are done graphically
# via regedit.exe or by using the corresponding channels, or even calling the
# Registry APIs directly.
# The built-in utility reg.exe provides a command-line interface to the registry,
# so that queries and modifications can be performed from a shell, such as
# cmd.exe.
# When a user is responsible for these actions, the parent of cmd.exe will likely
# be explorer.exe. Occasionally, power users and administrators write scripts
# that do this behavior as well, but likely from a different process tree. These
# background scripts must be learned so they can be tuned out accordingly.

TECHNIQUES = ['Query Registry','Modify Registry','Registry Run Keys / Start Folder','Service Registry Permissions Weakness']
TACTICS = ['Discovery','Defense Evasion','Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2013_03_001():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)

        events = process_create_events.where((col('event_data.Image') == 'C:\\Windows\\System32\\cmd.exe') & \
                                             (col('event_data.ParentImage') != 'C:\Windows\explorer.exe'))

        process_ids = list(set([int(i.process_id) for i in events.select('process_id').collect()]))

        events = sysmon_df.where((col('event_data.Image') == "C:\\Windows\\System32\\reg.exe") & \
                                 (col('event_data.ParentProcessId').isin(process_ids)))
        return events
