# CAR_2013_07_005: Command Line Usage of Archiving Software
# Before exfiltrating data that an adversary has collected, it is very likely
# that a compressed archive will be created, so that transfer times are minimized
# and fewer files are transmitted. There is variety between the tools used to
# compress data, but the command line usage and context of archiving tools, such
# as ZIP, RAR, and 7ZIP, should be monitored.

# Pseudocode
# This analytic looks for the command line argument a , which is used by RAR.
# However, there may be other programs that have this as a legitimate argument
# and may need to be filtered out.

# processes = search Process:Create
# rar_argument = filter processes where (command_line == "* a *")
# output rar_argument

TECHNIQUE = ['Masquerading']
TACTICS = ['Defense Evasion']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2014_04_003():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def regex_filter(x):
        regexs = ['.* a .*']
        if x and x.strip():
            for r in regexs:
                if re.match(r, x, re.IGNORECASE):
                    return True
        return False

    def analyze(self):
        regex_udf = udf(regex_filter, BooleanType())
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where(regex_udf('event_data.CommandLine'))
        return events