from importlib import import_module
import time
import glob, os,sys
import datetime
from datetime import timedelta
from pyspark.sql import SparkSession
from pyspark.sql import Row
from pyspark.sql import functions
from pyspark.sql.functions import *
from pyspark.sql.types import *

# Analytic file folder
CAR_DIR = 'CAR_FILES'
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),CAR_DIR))

# Elasticsearch connection details
ES_IP = '192.168.1.198'
ES_PORT = '9200'

# Index and type on elasticsearch where the windows log files are collected
ES_WINLOG_INDEX = "winlogbeat*"
ES_WINLOG_TYPE = "wineventlog"

# Index and type on elasticsearch where the analyzed logs files are collected
ES_ANALYTICS_INDEX = "aptds_analytics"
ES_ANALYTICS_TYPE = "wineventlog"

# ELasticsearch log write mode
WRITE_MODE = 'append'

# Wait time duration in secords while waiting to be ready to run the next analytic
WAIT_SECONDS = 15

# Time from which the logs are to be analyzed
DAYS_OFFSET = 19
START_TIME = datetime.datetime.now() + datetime.timedelta(days = -DAYS_OFFSET)

#Spark settings
LOG_LEVEL = 'ERROR'
APP_NAME = "APTDS"
MASTER_CONF = "local"

spark = SparkSession.builder.appName(APP_NAME) \
                            .master(MASTER_CONF) \
                            .getOrCreate()

spark.sparkContext.setLogLevel(LOG_LEVEL)

# collect logs from winlog index as a dataframe
def get_es_df():
    resource = ES_WINLOG_INDEX + '/' + ES_WINLOG_TYPE
    es_df = spark.read.format("org.elasticsearch.spark.sql") \
                      .option("es.nodes", ES_IP) \
                      .option("es.port", ES_PORT) \
                      .load(resource)
    es_df = es_df.drop('tags').drop('keywords') # Prevent Schema Errors
    return es_df

# convert TECHNIQUES and TATICS list to a dataframe array
def conv_dfarray(list):
    return array([lit(i) for i in list])

# write analyzed logs to analytic index
def write_es_df(events_df):
    resource = ES_ANALYTICS_INDEX + '/' + ES_ANALYTICS_TYPE
    log_names = events_df.select('log_name').distinct().collect()
    for i in log_names:
        events = events_df.where(col('log_name') == i.log_name)
        events.write.format("org.elasticsearch.spark.sql") \
                    .option("es.nodes", ES_IP) \
                    .option("es.port", ES_PORT) \
                    .mode(WRITE_MODE) \
                    .save(resource)

# check if its ready to run the next analytic
def is_ready(time,duration):
    current_time = datetime.datetime.now()
    time_delta =  datetime.timedelta(minutes = duration)
    return (time + time_delta) < current_time

# Load all analytic code from the analytic folder
def load_cars():
    car_list = []
    os.chdir(CAR_DIR)
    sys.path.append(os.path.abspath(__file__))
    sys.path.append('./'+CAR_DIR)
    for file in glob.glob("*.py"):
        file_name = os.path.split(file)[-1].split('.')[0]
        mod = import_module(file_name)
        met = getattr(mod, file_name)()
        car_list.append(met)
    return car_list



if __name__ == '__main__':
    print ("Welcome to Advanced Persistent Threat  Detection System ")
    print('''
 __      __       .__                                  __                                                                                   
/  \    /  \ ____ |  |   ____  ____   _____   ____   _/  |_  ____                                                                           
\   \/\/   // __ \|  | _/ ___\/  _ \ /     \_/ __ \  \   __\/  _ \                                                                          
 \        /\  ___/|  |_\  \__(  <_> )  Y Y  \  ___/   |  | (  <_> )                                                                         
  \__/\  /  \___  >____/\___  >____/|__|_|  /\___  >  |__|  \____/                                                                          
       \/       \/          \/            \/     \/                                                                                         
   _____ _____________________   ________          __                 __  .__                  _________               __                   
  /  _  \\______   \__    ___/   \______ \   _____/  |_  ____   _____/  |_|__| ____   ____    /   _____/__.__. _______/  |_  ____   _____   
 /  /_\  \|     ___/ |    |       |    |  \_/ __ \   __\/ __ \_/ ___\   __\  |/  _ \ /    \   \_____  <   |  |/  ___/\   __\/ __ \ /     \  
/    |    \    |     |    |       |    `   \  ___/|  | \  ___/\  \___|  | |  (  <_> )   |  \  /        \___  |\___ \  |  | \  ___/|  Y Y  \ 
\____|__  /____|     |____|      /_______  /\___  >__|  \___  >\___  >__| |__|\____/|___|  / /_______  / ____/____  > |__|  \___  >__|_|  / 
        \/                               \/     \/          \/     \/                    \/          \/\/         \/            \/      \/  
    ''')

    # Load all analytic code
    cars = load_cars()

    start_time = START_TIME

    # The CAR analytic code defines its on timeslice duration
    # Hence all all CARs are initialized with a startime as the runtime
    # and run once its complete timeslice comes to timeframe
    # is_ready() decides if it is ready to be run
    # initizalize time for all cars to starttime
    for car in cars:
        car.time = start_time

    while True:
        es_df = get_es_df()
        for car in cars:
            if is_ready(car.time,car.duration):
                print('Running: '+ car.__module__)
                starttime = car.time
                time_delta =  datetime.timedelta(minutes = car.duration)
                endtime = car.time + time_delta

                # get timeslice
                timeslice_df = es_df.where((col('@timestamp') >= starttime) & \
                                           (col('@timestamp') <= endtime)) 
                # run CAR analytic with appropriate timeslice
                car.df = timeslice_df
                events = car.analyze()
                # Add appropriate Technique & Tactics classifcation.
                events = events.withColumn("Technique", conv_dfarray(car.techniques))
                events = events.withColumn("Tactics", conv_dfarray(car.tactics))
                # write to ES
                write_es_df(events)
                car.time = endtime
            else:
                # wait to be ready
                print('Waiting to be ready...')
                time.sleep(WAIT_SECONDS)

