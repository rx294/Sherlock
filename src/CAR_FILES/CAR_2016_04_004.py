# CAR_2016_04_004: Successful Local Account Login

# The successful use of Pass The Hash for lateral movement between workstations
# would trigger event ID 4624, with an event level of Information, from the
# security log. This behavior would be a LogonType of 3 using NTLM authentication
# where it is not a domain logon and not the ANONYMOUS LOGON account.

# Pseudocode
# This analytic will look for remote logins, using a non domain login, from one 
# host to another, using NTL authentication where the account is not "ANONYMOUS LOGON"

# EventCode == 4624 and [target_user_name] != "ANONYMOUS LOGON" and
# [authentication_package_name] == "NTLM"

TECHNIQUES = ['Pass the Hash']
TACTICS = ['Lateral Movement']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2016_04_004():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        security_df = self.df.where(col('log_name') == 'Security')
        events = security_df.where(col('event_id') == 4624)
        events = security_df.where(col('event_data.TargetUserName') != "ANONYMOUS LOGON" & \
                                   col('event_data.AuthenticationPackageName') == "NTLM")
        return events