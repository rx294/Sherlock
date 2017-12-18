# CAR_2014_07_001: Service Search Path Interception

# According to ATT&CK, an adversary may escalate privileges by intercepting the
# search path for legitimately installed services. As a result, Windows will
# launch the target executable instead of the desired binary and command line.
# This can be done when there are spaces in the binary path and the path is
# unquoted. Search path interception should never happen legitimately and will
# likely be the result of an adversary abusing a system misconfiguration. With a
# few regular expressions, it is possible to identify the execution of services
# with intercepted search paths.

TECHNIQUES = ['Path Interception']
TACTICS = ['Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *
from pyspark.sql.types import *

class CAR_2014_07_001():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)

        unquoted_services = process_create_events.where((col('event_data.CommandLine').rlike('^\\".*') == False) &\
                                                         (col('event_data.CommandLine').rlike('.* .*')))

        intercepted_service = process_create_events.where((col('event_data.Image').rlike('.* .*') == False) &\
                                                         (col('event_data.Image').rlike('exe') == False))
        events = intercepted_service
        return events