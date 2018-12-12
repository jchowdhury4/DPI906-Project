#! python
import json
import subprocess
import requests
import hashlib
import os
import time

headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"
  }

#Initializes the lists for each type of anomoly found in the system.
proc_anomolies = []
start_anomolies = []
service_anomolies = []

#Saves contents of system baseline files to constants.
#These files must be in the same directory as osquery.py.
#They were generated using the queries:

#osqueryi --json "SELECT DISTINCT proc.path, hash.md5 FROM processes AS proc INNER JOIN hash ON proc.path = hash.path;"
with open('proc_baseline.json', 'r') as proc_data:
	PROCBASELINE = json.load(proc_data)

#osqueryi --json "SELECT DISTINCT start.path, hash.md5 FROM startup_items AS start INNER JOIN hash ON hash.path = start.path;"
with open('start_baseline.json', 'r') as start_data:
	STARTBASELINE = json.load(start_data)

#osqueryi --json "SELECT DISTINCT serv.path, hash.md5 FROM services AS serv INNER JOIN hash ON serv.path = hash.path;"
with open('serv_baseline.json', 'r') as serv_data:
	SERVBASELINE = json.load(serv_data)

#Creates new lists by querying the processes, startup_items, and services tables in OSQuery to compare with baselines.
proclist = json.loads(subprocess.check_output('osqueryi --json "SELECT DISTINCT proc.path, hash.md5 FROM processes AS proc INNER JOIN hash ON proc.path = hash.path;"').decode('ascii'))

startlist = json.loads(subprocess.check_output('osqueryi --json "SELECT DISTINCT start.path, hash.md5 FROM startup_items AS start INNER JOIN hash ON hash.path = start.path;"').decode('ascii'))

servicelist = json.loads(subprocess.check_output('osqueryi --json "SELECT DISTINCT serv.path, hash.md5 FROM services AS serv INNER JOIN hash ON serv.path = hash.path;"').decode('ascii'))

#Adds path-hash pair if same pair is not found in the baseline constants.
for n in proclist :
    if n not in PROCBASELINE:
    	print("new proc")
    	proc_anomolies.append(n)
for n in startlist :
    if n not in STARTBASELINE:
    	print("new start")
    	start_anomolies.append(n)
for n in servicelist :
    if n not in SERVBASELINE:
    	print("new service")
    	service_anomolies.append(n)

#Sends hashes of anomalies to Virustotal for analysis. Returns list of malicious hashes.
def sendHashes(jsonlist, file_hash) :
	malhashes = []
	count = 0
	for n in jsonlist :
		file_hash.append(n["md5"])
		count += 1
		if count == 3 or jsonlist.index(n) == len(jsonlist)-1 :
			params = {'apikey': '4fb64512ba49309f391509307be456cc7cbb8253a3ce5cedd1d9b3c3582af9ac', 'resource': ','.join(file_hash)}
			count = 0
			file_hash = []
			response = requests.get('https://virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
			for d in response.json():
				try:
					if d['positives'] > 0:
						malhashes.append(d['md5'])
				except:
					pass
			if jsonlist.index(n) < len(jsonlist)-1 :
				time.sleep(60)
	return malhashes

#Variable which stores the list of malicious hashes returned by the sendHashes function.
malhashes = sendHashes(proc_anomolies, [])

#Queries the processes table and hash table to find the path for files whose hashes identified them as malicious.
malfiles = json.loads(subprocess.check_output('osqueryi --json "SELECT proc.path, hash.md5 FROM process AS proc INNER JOIN hash ON proc.uid = hash.uid WHERE hash.md5 IN' + str(malhashes) + '"').decode('ascii'))

#Prints the list of malicious file paths.
print(malfiles)