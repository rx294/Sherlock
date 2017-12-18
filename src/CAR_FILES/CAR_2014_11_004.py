# CAR_2014_11_004: Remote PowerShell Sessions

# According to ATT&CK, PowerShell can be used over WinRM to remotely run commands 
# on a host. When a remote PowerShell session starts, svchost.exe executes 
# wsmprovhost.exe

TECHNIQUES = ['New Service']
TACTICS = ['Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2014_11_004():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where((col('event_data.Image').rlike("wsmprovhost.exe")))
        events = events.where((col('event_data.ParentImage').rlike("svchost.exe")))
        return events
