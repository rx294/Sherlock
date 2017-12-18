# CAR_2016_03_001: Host Discovery Commands

# When entering on a host for the first time, an adversary may try to discover
# information about the host. There are several built-in Windows commands that
# can be used to learn about the software configurations, active users,
# administrators, and networking configuration. These commands should be
# monitored to identify when an adversary is learning information about the
# system and environment. The information returned may impact choices an
# adversary can make when establishing persistence, escalating privileges, or
# moving laterally.
# Because these commands are built in, they may be run frequently by power users
# or even by normal users. Thus, an analytic looking at this information should
# have well-defined white- or blacklists, and should consider looking at an
# anomaly detection approach, so that this information can be learned dynamically.

TECHNIQUES = ['Account Discovery','Permission Groups','Local Network Configuration',
              'System Information','System Owner/User','Process Discovery',
              'System Service Discovery']

TACTICS = ['Discovery']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2016_03_001():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        discovery_command = [
            "hostname.exe",
            "ipconfig.exe",
            "net.exe",
            "quser.exe",
            "qwinsta.exe",
            "systeminfo.exe",
            "tasklist.exe",
            "whoami.exe"
        ]
        regexes = '(?:%s)' % '|'.join(discovery_command)
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)

        info_events = process_create_events.where(col('event_data.Image').rlike(regexes))

        sc_events = process_create_events.where(col('event_data.Image').rlike('sc.exe') &\
                                                col('event_data.CommandLine').rlike('(?: query| qc)'))
        events = info_events.union(sc_events)
        return events






