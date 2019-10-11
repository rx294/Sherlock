# CAR_2013_05_002: Suspicious Run Locations
# In Windows, files should never execute out of certain directory locations. Any
# of these locations may exist for a variety of reasons, and executables may be
# present in the directory but should not execute. As a result, some defenders
# make the mistake of ignoring these directories and assuming that a process will
# never run from one. There are known TTPs that have taken advantage of this fact
# to go undetected. This fact should inform defenders to monitor these
# directories more closely, knowing that they should never contain running
# processes.

TECHNIQUES = ['Masquerading']
TACTICS = ['Defense Evasion']
DURATION_MINS = 30

from pyspark.sql.functions import *
from pyspark.sql.types import *
import re

class CAR_2013_05_002():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        suspicious_locations = [
        'C:\\\\RECYCLER\\\\.*',
        'C:\\\\SystemVolumeInformation\\\\.*',
        'C:\\\\Windows\\\\Tasks\\\\.*',
        'C:\\\\Windows\\\\debug\\\\.*'
        ]
        regexes = '(?:%s)' % '|'.join(suspicious_locations)
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where(col('event_data.Image').rlike(regexes))
        return events