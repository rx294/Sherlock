# CAR_2014_11_006: Windows Remote Management (WinRM)
# When a Windows Remote Management connection is opened, the client sends HTTP
# requests to port 5985 for HTTP or 5986 for HTTPS on the target host. Each
# HTTP(S) request to the URI "/wsman" is called, and other information is set in
# the headers. Depending on the operation, the HTTP method may vary (i.e., GET,
# POST, etc.).
# This analytic would detect Remote PowerShell, as well as other communications
# that rely on WinRM. Additionally, it outputs the executable on the client host,
# the connection information, and the hostname of the target host.

# Pseudocode
# Look for network connections to port 5985 and 5986. To really decipher what is
# going on, these outputs should be fed into something that can do packet
# analysis.

# flow = search Flow:Start
# winrm = filter flow where (dest_port == 5985)
# winrm_s = filter flow where (dest_port == 5986)
# output winrm, winrm_s

TECHNIQUES = ['Windows Remote Management']
TACTICS = ['Lateral Movement']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2014_11_006():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        network_events = sysmon_df.where(col('event_id') == 3)
        events = network_events.where((col('event_data.DestinationPort') == 5985) | \
                                      (col('event_data.DestinationPort') == 5986))
        return events