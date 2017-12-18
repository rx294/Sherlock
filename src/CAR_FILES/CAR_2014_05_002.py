# CAR_2014_05_002: Services launching Cmd

# Windows runs the Service Control Manager (SCM) within the process services.exe.
# Windows launches services as independent processes or DLL loads within a
# svchost.exe group. To be a legitimate service, a process (or DLL) must have the
# appropriate service entry point SvcMain. If an application does not have the
# entry point, then it will timeout (default is 30 seconds) and the process will
# be killed.
# To survive the timeout, adversaries and red teams can create services that
# direct to cmd.exe with the flag /c, followed by the desired command. The /c
# flag causes the command shell to run a command and immediately exit. As a
# result, the desired program will remain running and it will report an error
# starting the service. This analytic will catch that command prompt instance
# that is used to launch the actual malicious executable.
# Additionally, the children and descendants of services.exe will run as a SYSTEM
# user by default. Thus, services are a convenient way for an adversary to gain
# Persistence and Privilege Escalation.

# Pseudocode

# Returns all processes named "cmd.exe" that have "services.exe" as a parent
# process. Because this should never happen, the /c flag is redundant in the
# search.

# process = search Process:Create
# cmd = filter process where (exe == "cmd.exe" and parent_exe == "services.exe")
# output cmd


TECHNIQUES = ['New Service']
TACTICS = ['Persistence', 'Privilege Escalation']
DURATION_MINS = 30

from pyspark.sql.functions import *

class CAR_2014_05_002():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        events = process_create_events.where(col('event_data.Image').rlike("services.exe"))
        events = events.where(col('event_data.Image').rlike("cmd.exe"))
        return events
