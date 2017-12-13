# CAR_2013_05_002: Suspicious Run Locations

TECHNIQUES = ['Masquerading']
TACTICS = ['Defense Evasion']
DURATION_MINS = 30

from pyspark.sql.functions import *
import re

class CAR_2013_05_002():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def is_suspicious(image_path):
        ''' List of suspicious commands '''
        suspicious_locations = [
        'C:\\\\RECYCLER\\\\.*',
        'C:\\\\SystemVolumeInformation\\\\.*',
        'C:\\\\Windows\\\\Tasks\\\\.*',
        'C:\\\\Windows\\\\debug\\\\.*']
        try:
            regexes = '(?:%s)' % '|'.join(suspicious_locations)
            if re.match(regexes, image_path, re.IGNORECASE):
                return True
            return False
        except:
            return False

    def analyze(self):
        is_suspicious_udf = udf(is_suspicious, BooleanType())

        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where(is_suspicious_udf(col('event_data.Image')))
        return events