from pyspark.sql import SparkSession
from pyspark.sql import Row
from pyspark.sql import functions
from pyspark.sql.functions import *
from pyspark.sql.functions import array, create_map, structDD
from pyspark.sql.functions import lit
import numpy as np
from pyspark.sql.types import *


spark = SparkSession.builder.appName("elastic").getOrCreate()
es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog")
es_df.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')

es_df.printSchema()

sysmon_df = es_df.where(es_df.log_name == 'Microsoft-Windows-Sysmon/Operational')
test_df = sysmon_df.where(es_df.event_id == 6)

test_df.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").save("index/type")  

def conv_dfarray(list):
    return array([lit(i) for i in list])


# CAR-2013-02-003: Processes Spawning cmd.exe
TECHNIQUE = array(lit('Command-Line Interface'))
TACTICS = array([lit('Execution'),lit('Test')])

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
events = sysmon_df.where((col('event_data.Image') == 'C:\Windows\System32\cmd.exe') &(col('event_data.ParentImage') != 'C:\Windows\explorer.exe'))
events = events.withColumn("Technique", TECHNIQUE).withColumn("Tactics", TACTICS)
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')



# CAR-2013-03-001: Reg.exe called from Command Shell
TECHNIQUE = ['Query Registry','Modify Registry','Registry Run Keys / Start Folder','Service Registry Permissions Weakness']
TACTICS = ['Discovery','Defense Evasion','Persistence', 'Privilege Escalation']

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')

# collect cmd.exe with parent other than explorer.exe
events = sysmon_df.where((col('event_data.Image') == 'C:\\Windows\\System32\\cmd.exe') &(col('event_data.ParentImage') != 'C:\Windows\explorer.exe'))
# collect process_ids from the able dataframe
process_ids = list(set([int(i.process_id) for i in events.select('process_id').collect()]))
#check if any instance of reg.exe is parented by the above process ids
events = sysmon_df.where((col('event_data.Image') == "C:\\Windows\\System32\\reg.exe") & (col('event_data.ParentProcessId').isin(process_ids)))
events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')


# CAR-2013-05-002: Suspicious Run Locations
import re

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

is_suspicious_udf = udf(is_suspicious, BooleanType())

TECHNIQUE = ['Masquerading']
TACTICS = ['Defense Evasion']

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')

# collect cmd.exe with parent other than explorer.exe
events = sysmon_df.where(is_suspicious_udf(col('event_data.Image')) & (col('event_id') == 1))

events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')



# CAR-2013-05-003: SMB Write Request
TECHNIQUE = ['Remote File Copy','Windows Admin Shares','Legitimate Credentials']
TACTICS = ['Command and Control', 'Lateral Movement','Defense Evasion', 'Persistence', 'Privilege Escalation']

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
network_events = sysmon_df.where(col('event_id') == 3)
events = network_events.where(col('event_data.DestinationPort') == 445)

events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')


# CAR-2013-05-004: Execution with AT
TECHNIQUE = ['Scheduled Task']
TACTICS = ['Execution', 'Persistence', 'Privilege Escalation']

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
process_create_events = sysmon_df.where(col('event_id') == 1)
events = process_create_events.where((col('event_data.Image') == "C:\\Windows\\System32\\at.exe"))

events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')


# CAR-2013-07-002: RDP Connection Detection
TECHNIQUE = ['Remote Desktop Protocol']
TACTICS = ['Lateral Movement']

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
network_events = sysmon_df.where(col('event_id') == 3)
events = network_events.where((col('event_data.DestinationPort') == 3389) & (col('event_data.SourcePort') == 3389))

events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')

# CAR-2013-07-005: Command Line Usage of Archiving Software
TECHNIQUE = ['Masquerading']
TACTICS = ['Defense Evasion']

# regex_filter =  udf (lambda x: re.search(r".+ a .+", x), BooleanType())

def regex_filter(x):
    regexs = ['.* a .*']
    
    if x and x.strip():
        for r in regexs:
            if re.match(r, x, re.IGNORECASE):
                return True
    return False 
    
    
filter_udf = udf(regex_filter, BooleanType())

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
process_create_events = sysmon_df.where(col('event_id') == 1)
events = process_create_events.where(filter_udf('event_data.CommandLine'))

events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')


# CAR-2013-08-001: Execution with schtasks
TECHNIQUE = ['Scheduled Task']
TACTICS = ['Execution', 'Persistence', 'Privilege Escalation']

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
process_create_events = sysmon_df.where(col('event_id') == 1)
events = process_create_events.where((col('event_data.Image') == "C:\\Windows\\System32\\schtasks.exe"))

events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')

# CAR-2014-03-006: RunDLL32.exe monitoring
TECHNIQUE = ['Rundll32']
TACTICS = ['Defense Evasion', 'Execution']

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
process_create_events = sysmon_df.where(col('event_id') == 1)
events = process_create_events.where((col('event_data.Image') == "C:\\Windows\\System32\\rundll32.exe"))

events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')


# CAR-2014-04-003: Powershell Execution
TECHNIQUE = ['PowerShell','Scripting']
TACTICS = ['Defense Evasion', 'Execution']

es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
sysmon_df = es_df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
process_create_events = sysmon_df.where(col('event_id') == 1)
ps_events = process_create_events.where((col('event_data.Image') == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
events = process_create_events.where((col('event_data.ParentImage') != "C:\\Windows\\explorer.exe"))

events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')

