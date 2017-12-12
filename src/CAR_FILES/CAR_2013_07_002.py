# CAR_2013_07_002: RDP Connection Detection
# The Remote Desktop Protocol (RDP), built in to Microsoft operating systems,
# allows a user to remotely log in to the desktop of another host. It allows for
# interactive access of the running windows, and forwards key presses, mouse
# clicks, etc. Network administrators, power users, and end-users may use RDP for
# day-to-day operations. From an adversary's perspective, RDP provides a means to
# laterally move to a new host. Determining which RDP connections correspond to
# adversary activity can be a difficult problem in highly dynamic environments,
# but will be useful in identifying the scope of a compromise.

# Pseudocode

# flow_start = search Flow:Start
# flow_end = search Flow:End
# rdp_start = filter flow_start where (port == "3389")
# rdp_end = filter flow_start where (port == "3389")
# rdp = group flow_start, flow_end by src_ip, src_port, dest_ip, dest_port
# output rdp


TECHNIQUE = ['Remote Desktop Protocol']
TACTICS = ['Lateral Movement']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2013_07_002():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        network_events = sysmon_df.where(col('event_id') == 3)
        events = network_events.where((col('event_data.DestinationPort') == 3389) & \
                                      (col('event_data.SourcePort') == 3389))
        return events