# CAR_2013_05_003: SMB Write Request


TECHNIQUES = ['Remote File Copy','Windows Admin Shares','Legitimate Credentials']
TACTICS = ['Command and Control', 'Lateral Movement','Defense Evasion', 'Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2013_05_003():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        network_events = sysmon_df.where(col('event_id') == 3)
        events = network_events.where(col('event_data.DestinationPort') == 445)
        return events
