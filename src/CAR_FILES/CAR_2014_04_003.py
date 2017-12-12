# CAR_2014_04_003: Powershell Execution

# PowerShell is a scripting environment included with Windows that is used by both
# attackers and administrators. Execution of PowerShell scripts in most Windows
# versions is opaque and not typically secured by antivirus which makes using
# PowerShell an easy way to circumvent security measures. This analytic detects
# execution of PowerShell scripts.

# Pseudocode
# Look for versions of PowerShell that were not launched interactively.

# process = search Process:Create
# powershell = filter process where (exe == "powershell.exe" AND parent_exe != "explorer.exe" )
# output powershell

TECHNIQUES = ['PowerShell','Scripting']
TACTICS = ['Defense Evasion', 'Execution']
DURATION_MINS = 60*6

class CAR_2014_04_003():
    def __init__(self):
        self.time = 0
        self.duration = DURATION_MINS
        self.tactics = TACTICS
        self.techniques = TECHNIQUES
        self.df = 0

    def analyze(df):
        sysmon_df = df.where(col('log_name') == 'Microsoft-Windows-Sysmon/Operational')
        process_create_events = sysmon_df.where(col('event_id') == 1)
        ps_events = process_create_events.where((col('event_data.Image') == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
        events = ps_events.where((col('event_data.ParentImage') != "C:\\Windows\\explorer.exe"))
        return events


# es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')





# events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
# events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')


