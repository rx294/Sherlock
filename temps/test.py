tactics = [
['Persistence'],
['Persistence'],
['Persistence'],
['Privilege Escalation'],
['Persistence'],
['Persistence'],
['Privilege Escalation'],
['Privilege Escalation'],
['Privilege Escalation'],
['Privilege Escalation'],
['Defense Evasion'],
['Defense Evasion'],
['Defense Evasion'],
['Defense Evasion'],
['Defense Evasion'],
['Credential Access'],
['Defense Evasion'],
['Credential Access'],
['Discovery'],
['Credential Access'],
['Credential Access'],
['Discovery'],
['Discovery'],
['Discovery'],
['Discovery'],
['Discovery'],
['Lateral Movement'],
['Lateral Movement'],
['Lateral Movement'],
['Lateral Movement'],
['Lateral Movement'],
['Execution'],
['Lateral Movement'],
['Lateral Movement'],
['Execution'],
['Execution'],
['Collection'],
['Execution'],
['Collection'],
['Collection'],
['Collection'],
['Exfiltration'],
['Collection'],
['Exfiltration'],
['Exfiltration'],
['Exfiltration'],
['Command and Control'],
['Exfiltration'],
['Command and Control'],
['Command and Control'],
['Exfiltration'],
['Command and Control'],
]



technique = [
['Cron Job'],
['Local Port Monitor'],
['Shortcut Modification'],
['Path Interception'],
['Startup Items'],
['Startup Items'],
['Path Interception'],
['Local Port Monitor'],
['DLL Injection'],
['AppInit DLLs'],
['Binary Padding'],
['Binary Padding'],
['Binary Padding'],
['Binary Padding'],
['Binary Padding'],
['Input Prompt'],
['Clear Command History'],
['Input Prompt'],
['File and Directory Discovery'],
['Create Account'],
['Create Account'],
['Query Registry'],
['Query Registry'],
['File and Directory Discovery'],
['Network Service Scanning'],
['Process Discovery'],
['Remote Services'],
['Remote Services'],
['Remote Services'],
['Remote Services'],
['Remote Services'],
['Rundll32'],
['Remote File Copy'],
['Pass the Hash'],
['Rundll32'],
['Rundll32'],
['Screen Capture'],
['PowerShell'],
['Input Capture'],
['Data Staged'],
['Clipboard Data'],
['Exfiltration'],
['Clipboard Data'],
['Data Compressed'],
['Data Compressed'],
['Data Encrypted'],
['Uncommonly Used Port'],
['Scheduled Transfer'],
['Command-Line Interface'],
['Command-Line Interface'],
['Data Compressed'],
['Web Service'],
]

import json
import random
import time
import datetime
#prompt the user for a file to import
filename = "sample.json"

#Read JSON data into the datastore variable
if filename:
    with open(filename, 'r') as f:
        datastore = json.load(f)

#Use the new datastore datastructure
# print datastore[0]['_source']
dataList = []
for x in datastore:
    dataList.append(x['_source'])
o_dataList = dataList
# print json.dumps(dataList[0])
timeslice = 0
current_time = long(time.time()*1000)
# print datetime.datetime.fromtimestamp(current_time/1000).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


t_index = 0
for x in dataList:
    time = current_time + timeslice + random.randint(60000, 60000*60)
    x["@timestamp"] = time
    del x['event_data']['UtcTime']
    timeslice = timeslice + 3600000
    x["Tactics"] = tactics[t_index]
    x["Technique"] = technique[t_index]
    t_index = t_index + 1
    del x["message"]


for x in dataList:
    print datetime.datetime.fromtimestamp(x["@timestamp"]/1000).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

index = {"index":{}}
f= open("processed.json","w+")

for x in dataList:
    json.dumps(dataList[0])
    f.write("%s\r\n" % json.dumps(index))
    f.write("%s\r\n" % json.dumps(x))

t_index = 0
s_dataList = []
t_host = 'WIN-U1E6SADQQ8H'
timeslice = 0
for x in range(0,8):
    r_index = random.randint(0, 49)
    temp = o_dataList[r_index]
    time = current_time + timeslice + random.randint(60000, 60000*60)
    temp["@timestamp"] = time
    # del temp['event_data']['UtcTime']
    timeslice = timeslice + 3600000*2
    temp["Tactics"] = tactics[r_index]
    temp["Technique"] = technique[r_index]
    t_index = t_index + 1
    # del temp["message"]
    temp['beat']['hostname'] = t_host
    temp['beat']['name'] = t_host
    temp['beat']['UtcTime'] = t_host
    temp['computer_name'] = t_host
    temp['host'] = t_host
    s_dataList.append(temp)

for x in s_dataList:
    json.dumps(dataList[0])
    f.write("%s\r\n" % json.dumps(index))
    f.write("%s\r\n" % json.dumps(x))

t_index = 0
t_dataList = []
t_host = 'WIN-U1E6SADQQ1Z'
timeslice = 0
for x in range(0,5):
    r_index = random.randint(0, 49)
    temp = o_dataList[r_index]
    time = current_time + timeslice + random.randint(60000, 60000*60)
    temp["@timestamp"] = time
    # del temp['event_data']['UtcTime']
    timeslice = timeslice + 3600000*3
    temp["Tactics"] = tactics[r_index]
    temp["Technique"] = technique[r_index]
    t_index = t_index + 1
    # del temp["message"]
    temp['beat']['hostname'] = t_host
    temp['beat']['name'] = t_host
    temp['beat']['UtcTime'] = t_host
    temp['computer_name'] = t_host
    temp['host'] = t_host
    t_dataList.append(temp)

for x in t_dataList:
    json.dumps(dataList[0])
    f.write("%s\r\n" % json.dumps(index))
    f.write("%s\r\n" % json.dumps(x))

    # f.write("%s\r\n" % {"index":{}})
# datetime.datetime.fromtimestamp(int(time.time())).strftime('%Y-%m-%d %H:%M:%S')

# /home/rxman/Documents/processed.json

# curl -H 'Content-Type: application/x-ndjson' -XPOST '192.168.1.198:9200/analytics/wineventlog/_bulk?pretty' --data-binary @processed.json
# hr = 3600000
# min = 60000
