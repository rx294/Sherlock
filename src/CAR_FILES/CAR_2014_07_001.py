# CAR_2014_07_001: Service Search Path Interception

# According to ATT&CK, an adversary may escalate privileges by intercepting the
# search path for legitimately installed services. As a result, Windows will
# launch the target executable instead of the desired binary and command line.
# This can be done when there are spaces in the binary path and the path is
# unquoted. Search path interception should never happen legitimately and will
# likely be the result of an adversary abusing a system misconfiguration. With a
# few regular expressions, it is possible to identify the execution of services
# with intercepted search paths.

# Pseudocode

# Look over all service creations that have a quoted path for the first argument.
# Assuming these still have an absolute path, look for cases in which the command
# line has a space, but the exe field is not part of the command line. This would
# indicate that a different process was intended, but the path was intercepted at
# an earlier space.

# process = search Process:Create
# services = filter processes where (parent_exe == "services.exe")
# unquoted_services = filter services where (command_line != "\"*" and command_line == "* *")
# intercepted_service = filter unquoted_service where (image_path != "* *" and exe not in command_line)
# output intercepted_service

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

        def regex_filter(x,regex):
            regex = ['.* a .*']
            if x and x.strip():
                if re.match(regex, x, re.IGNORECASE):
                    return True
            return False

        regex_udf = udf(regex_filter, BooleanType())
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)

        unquoted_services = process_create_events.where((not regex_udf(col('event_data.CommandLine'),'^\\".*')) &\
                                                        regex_udf(col('event_data.CommandLine'),'.* .*'))

        intercepted_service = unquoted_services.where((not regex_udf(col('event_data.Image'),'.* .*')) &\
                                                      (not regex_udf(col('event_data.Image'),'exe')))
        events = intercepted_service
        return events







