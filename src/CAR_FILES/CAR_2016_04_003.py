# CAR_2016_04_003: User Activity from Stopping Windows Defensive Services

# Spyware and malware remain a serious problem and Microsoft developed security
# services, Windows Defender and Windows Firewall, to combat this threat. In the
# event Windows Defender or Windows Firewall is turned off, administrators should
# correct the issue immediately to prevent the possibility of infection or
# further infection and investigate to determine if caused by crash or user
# manipulation.

# Pseudocode
# Windows Event code 7036 from the System log identifies if a service has stopped 
# or started. This analytic looks for "Windows Defender" or "Windows Firewall" that 
# has stopped.

# log_name == "System" AND
# event_code == "7036"
# param1 in ["Windows Defender", "Windows Firewall"] AND
# param2 == "stopped"


TECHNIQUES = ['Indicator Blocking']
TACTICS = ['Defense Evasion']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2016_04_003():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        PARAMS   = [
            "Windows Defender",
            "Windows Firewall"
        ]
        regexes = '(?:%s)' % '|'.join(PARAMS)
        system_df = self.df.where(col('log_name') == 'System')
        system_events = system_df.where(col('event_id') == 7036)

        events = system_events.where(col('event_data.param2') == 'stopped') \
                              .where(col('event_data.param1').rlike(regexes))
        return events