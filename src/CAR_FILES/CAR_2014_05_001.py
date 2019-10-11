# CAR_2014_05_001: RPC Activity

# Microsoft Windows uses its implementation of Distributed Computing
# Environment/Remote Procedure Call (DCE/RPC), which it calls Microsoft RPC, to
# call certain APIs remotely.
# A Remote Procedure Call is initiated by communicating to the RPC Endpoint
# Mapper, which exists as the Windows service RpcEptMapper and listens on the
# port 135/tcp. The endpoint mapper resolves a requested endpoint/interface and
# responds to the client with the port that the service is listening on. Since
# the RPC endpoints are assigned ports when the services start, these ports are
# dynamically assigned from 49152 to 65535. The connection to the endpoint mapper
# then terminates and the client program can communicate directly with the
# requested service.
# RPC is a legitimate functionality of Windows that allows remote interaction
# with a variety of services. For a Windows environment to be properly
# configured, several programs use RPC to communicate legitimately with servers.
# The background and benign RPC activity may be enormous, but must be learned,
# especially peer-to-peer RPC between workstations, which is often indicative of
# Lateral Movement.
# According to ATT&CK, adversaries frequently use RPC connections to remotely

TECHNIQUES = ['Legitimate Credentials','Remote Services']
TACTICS = ['Defense Evasion', 'Persistence', 'Privilege Escalation','Lateral Movement']
DURATION_MINS = 30

from pyspark.sql.functions import *
from pyspark.sql.types import *
import datetime
from datetime import timedelta

class CAR_2014_05_001():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(self):
        sysmon_df = self.df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        network_events = sysmon_df.where(col('event_id') == 3)
        rpc_mapper = network_events.where(col('event_data.DestinationPort') == 135)

        rpc_endpoint = network_events.where((col('event_data.DestinationPort') >= 49152) &\
                                            (col('event_data.SourcePort') >= 49152))

        rpc_endpoint = rpc_endpoint.select(col('@timestamp').alias("time"), \
                                           col('event_data.SourceIp').alias("src_ip"),  \
                                           col('event_data.DestinationIp').alias("dest_ip"))

        rpc =  rpc_mapper.join(rpc_endpoint, (rpc_mapper.event_data.SourceIp      == rpc_endpoint.src_ip) & \
                                             (rpc_mapper.event_data.DestinationIp == rpc_endpoint.dest_ip))

        timeframe =  udf (lambda time: time + datetime.timedelta(minutes = 2), DateType())
        rpc = rpc.where(col('@timestamp') < col('time')) \
                 .where(col('time') < timeframe(col('@timestamp')))
        events = rpc.drop('time','src_ip','dest_ip')
        return events














