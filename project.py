from pyspark import SparkContext, SparkConf
conf = SparkConf().setAppName("ESTest")
sc = SparkContext(conf=conf)
es_read_conf = {
    "es.nodes" : "192.168.1.198",
    "es.port" : "9200",
    "es.resource" : "winlogbeat*/wineventlog"
} 


es_rdd = sc.newAPIHadoopRDD(
inputFormatClass="org.elasticsearch.hadoop.mr.EsInputFormat",
keyClass="org.apache.hadoop.io.NullWritable", 
valueClass="org.elasticsearch.hadoop.mr.LinkedMapWritable", 
conf=es_read_conf)

doc = es_rdd.first()[1]

print("\n\n\n\n\n")
print(doc)
print("\n\n\n\n\n")

rdd = sc.newAPIHadoopRDD("org.elasticsearch.hadoop.mr.EsInputFormat",\
    "org.apache.hadoop.io.NullWritable", "org.elasticsearch.hadoop.mr.LinkedMapWritable", conf=conf)

    # for field in doc:
    #     value_counts = es_rdd.map(lambda item: item[1][field])
    #     value_counts = value_counts.map(lambda word: (word, 1))
    #     value_counts = value_counts.reduceByKey(lambda a, b: a+b)
    #     value_counts = value_counts.filter(lambda item: item[1] > 1)
    #     value_counts = value_counts.map(lambda item: ('key', { 
    #         'field': field, 
    #         'val': item[0], 
    #         'count': item[1] 
    #     }))
    #     value_counts.saveAsNewAPIHadoopFile(
    #         path='-', 
    #         outputFormatClass="org.elasticsearch.hadoop.mr.EsOutputFormat",
    #         keyClass="org.apache.hadoop.io.NullWritable", 
    #         valueClass="org.elasticsearch.hadoop.mr.LinkedMapWritable", 
    #         conf=es_write_conf)

pyspark --jars jars/elasticsearch-hadoop-6.0.1/dist/elasticsearch-hadoop-6.0.1.jar \
            --conf spark.es.nodes="192.168.1.198" \
            --conf spark.es.port="9200" \
            --conf spark.es.resource="winlogbeat*/wineventlog"

conf = SparkConf().setAppName("WriteToES2")
sc = SparkContext(conf=conf)
sqlContext = SQLContext(sc)
es_df = sqlContext.read.format("org.elasticsearch.spark.sql").load("winlogbeat*/wineventlog")

val df = sqlContext.read.format("org.elasticsearch.spark.sql").load("winlogbeat*/wineventlog")


val conf = new SparkConf().setAppName("ReadFromES")
val sc = new SparkContext(conf)
val sqlContext = new org.apache.spark.sql.SQLContext(sc)
val es_df=spark.read.format("org.elasticsearch.spark.sql").load("winlogbeat*/wineventlog")
println(es_df.count())



pyspark --jars jars/elasticsearch-hadoop-6.0.1/dist/elasticsearch-hadoop-6.0.1.jar             --conf spark.es.nodes="192.168.1.198"             --conf spark.es.port="9200"
es_df=spark.read.format("org.elasticsearch.spark.sql").load("winlogbeat*/wineventlog")

wes_df=spark.read.format("org.elasticsearch.spark.sql").option("es.nodes","192.168.1.198").load("winlogbeat*/wineventlog")

import org.elasticsearch.spark._
// load elasticsearch index into spark rdd
val fbeat_rdd = sc.esRDD("winlogbeat*/wineventlog")


(datetime.datetime.now() - datetime.datetime(2017, 11, 1, 15, 57, 7, 89000)).seconds