from importlib import import_module
import time
import datetime
from datetime import timedelta
import glob, os,sys
from pyspark.sql import SparkSession
from pyspark.sql import Row
from pyspark.sql import functions
from pyspark.sql.functions import *
from pyspark.sql.functions import array, create_map
from pyspark.sql.functions import lit
import numpy as np
from pyspark.sql.types import *
import itertools
import time
sys.path.append('/usr/zeppelin/Advanced-Persistent-Threat-Detection/src/CAR_FILES')

CAR_DIR = 'CAR_FILES'

ES_IP = '192.168.1.198'
ES_PORT = '9200'

ES_WINLOG_INDEX = "winlogbeat*"
ES_WINLOG_TYPE = "wineventlog"

ES_ANALYTICS_INDEX = "test5"
ES_ANALYTICS_TYPE = "wineventlog"
WRITE_MODE = 'append'

# es_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog").drop('tags')
# events = events.withColumn("Technique", conv_dfarray(TECHNIQUE)).withColumn("Tactics", conv_dfarray(TACTICS))
# events.write.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").mode("overwrite").save('test/wineventlog')
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),CAR_DIR))

spark = SparkSession.builder.appName("MITRE_Analytics").getOrCreate()

def get_es_df():
    resource = ES_WINLOG_INDEX + '/' + ES_WINLOG_TYPE
    es_df = spark.read.format("org.elasticsearch.spark.sql") \
                      .option("es.nodes", ES_IP) \
                      .option("es.port", ES_PORT) \
                      .load(resource)
    es_df = es_df.drop('tags').drop('keywords') # Prevent Schema Errors
    return es_df

def conv_dfarray(list):
    return array([lit(i) for i in list])

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
    # events_df.write.format("org.elasticsearch.spark.sql") \
    #                .option("es.nodes", ES_IP) \
    #                .option("es.port", ES_PORT) \
    #                .mode(WRITE_MODE) \
    #                .save(resource)

def is_ready(time,duration):
    current_time = datetime.datetime.now()
    time_delta =  datetime.timedelta(minutes = duration)
    return (time + time_delta) < current_time

def load_tests():
    test_list = []
    os.chdir(CAR_DIR)
    # sys.path.append(os.path.abspath(__file__))
    # sys.path.append('./'+CAR_DIR)
    for file in glob.glob("*.py"):
        file_name = os.path.split(file)[-1].split('.')[0]
        mod = import_module(file_name)
        met = getattr(mod, file_name)()
        test_list.append(met)
    return test_list



if __name__ == '__main__':
    print ("hello")

    # es_df = get_es_df()
    tests = load_tests()
    start_time = datetime.datetime.now() + datetime.timedelta(days = -10)
    # endtime = datetime.datetime.now() + datetime.timedelta(days = -1)

    # initizalize time for all test to starttime
    for test in tests:
        test.time = start_time

    for test in tests:
        test.time = start_time
    for test in itertools.cycle(tests):
        es_df = get_es_df()
        if is_ready(test.time,test.duration):
            print('ready')
            starttime = test.time
            time_delta =  datetime.timedelta(minutes = test.duration)
            endtime = test.time + time_delta

            timeslice_df = es_df.where((col('@timestamp') >= starttime) & \
                                       (col('@timestamp') <= endtime)) 
            test.df = timeslice_df
            events = test.analyze()
            events = events.withColumn("Technique", conv_dfarray(test.techniques))
            events = events.withColumn("Tactics", conv_dfarray(test.tactics))
            write_es_df(events)
            test.time = endtime
        # time.sleep(30)

# sysmon_df.where((col('@timestamp') >= starttime) & (col('@timestamp') <= endtime)).show()

