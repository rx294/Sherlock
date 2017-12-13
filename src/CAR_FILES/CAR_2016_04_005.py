# CAR_2016_04_005: Remote Desktop Logon

# A remote desktop logon, through RDP, may be typical of a system administrator
# or IT support, but only from select workstations. Monitoring remote desktop
# logons and comparing to known/approved originating systems can detect lateral
# movement of an adversary.

# Pseudocode
# Look in the system logs for remote logons using RDP

# [EventCode] == 4624 and
# [AuthenticationPackageName] == 'Negotiate' and
# [Severity] == "Information" and
# [LogonType] == 10

TECHNIQUES = ['Legitimate Credentials']
TACTICS = ['Lateral Movement']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2016_04_005():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        security_df = self.df.where(col('log_name') == 'Security')
        events = security_df.where(col('event_id') == 4624)
        events = security_df.where(col('event_data.LogonType') != 10 & \
                                   col('level') == "Information" & \
                                   col('event_data.AuthenticationPackageName') == "Negotiate")
        return events
