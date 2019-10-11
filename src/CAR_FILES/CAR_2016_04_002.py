# CAR_2016_04_002: User Activity from Clearing Event Logs

# It is unlikely that event log data would be cleared during normal operations,
# and it is likely that malicious attackers may try to cover their tracks by
# clearing an event log. When an event log gets cleared, it is suspicious.
# Alerting when a "Clear Event Log" is generated could point to this intruder
# technique. Centrally collecting events has the added benefit of making it much
# harder for attackers to cover their tracks. Event Forwarding permits sources to
# forward multiple copies of a collected event to multiple collectors, thus
# enabling redundant event collection. Using a redundant event collection model
# can minimize the single point of failure risk.

TECHNIQUES = ['Indicator Blocking']
TACTICS = ['Defense Evasion']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2016_04_002():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        SYSTEM_LOG_EVENT_IDS   = [104]
        SECURITY_LOG_EVENT_IDS = [1100, 1102]

        system_df = self.df.where(col('log_name') == 'System')
        security_df = self.df.where(col('log_name') == 'Security')

        system_events = system_df.where(col('event_id').isin(SYSTEM_LOG_EVENT_IDS))
        security_events = security_df.where(col('event_id').isin(SECURITY_LOG_EVENT_IDS))

        events = system_events.union(security_events)
        return events
