from scapy.all import *
from scapy_http import http
import re
import logging                       
import graypy
from threading import Thread
import threading  
import subprocess
import requests
import os
import time
import json
import ipaddress
from uuid import getnode as get_mac

#The Lock function initializes the thread lock queue for multi-threading
lock = threading.Lock()

#Initializes an instance of the logger to the variable my_logger
my_logger = logging.getLogger('test_logger')                       
my_logger.setLevel(logging.WARNING)

#This is the handler for the Graylog Server. The IP address and port must me changed according to the user's own configuration.
handler = graypy.GELFHandler('192.168.0.25', 12201)  

#This initializes a handler to the logger
my_logger.addHandler(handler)

#Filter which will be used to exclude all remote addresses found by Scapy which are MAC addresses
mac = ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2))

#Initializes the list for IPs to skip analysis
clean_list = []

#Initializes the list for IPs to queue for analysis
check_list = []

#Uses the osqueryi function to find the associated pid, remote IP, and port.
def osquery_Kill(ip,port):
#Outputs query in json format and cleans up strings.
    query = 'osqueryi --json "SELECT sock.pid,proc.name FROM process_open_sockets as sock INNER JOIN processes AS proc ON proc.pid = sock.pid where sock.remote_address = \'{}\' and sock.local_port = \'{}\';"'.format(ip,port)
    res = json.loads(subprocess.check_output(query).decode('ascii'))
#Kills pid if the resource is found in the query (if res exists). Prints the name of the file responsible and the IP it was connecting to. If the name is not found, the process is still killed.
    if res:
        kill = "taskkill /F /PID {}".format(res[0]['pid'])
        subprocess.check_output(kill)
        print(res[0]['name'], "killed due to malicious communication to remote host:", ip)
    else:
        print("Process Dead, process name not found")
	
#Set of functions which are responsible for:
##managing the VirusTotal Queue (3 requests/min)
##sending IPs to virustotal for analysis
##Calling osquery_Kill to kill pid associated with malicious IPs
def check_IP():
    global check_list
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip,  My Python requests library example client or username"
    }
	
    sentTime = 0
    sentCount = 0
    queueOpen = True

#Parses the json report returned by a VirusTotal analysis.
#Finds first instance of a non-zero threat(positives/total) value. This can be adjusted to a greater value.
#Returns the threat value or 0.
    def parse_ip_report(report):
        for i in report:
            if type(report[i]) is list and len(report[i]) > 0:
                for j in report[i]:
                    if type(j) is dict and 'positives' in j and 'total' in j and j['positives'] > 0 and j['total'] > 0:
                        threat = j['positives'] / j['total']
                        return threat
        return 0

#Sends remote IPs captured by Scapy to VirusTotal
    def sendIP():
        global check_list
        global clean_list

#The IP and port pair that will be sent is always the first element in the check_list array.
        ip = check_list[0][0]
        port = check_list[0][1]

#The parameters sent along with the request are one IP address and the API key.
#If API key is expired, new API key must be obtained by creating a new user on virustotal.com.
        params = {'ip':ip,'apikey': '3cbca5edaccf0e9e75ae2ac3da367000439ac414caeb4adea933d3304661fe16'}
        response = requests.get('https://virustotal.com/vtapi/v2/ip-address/report', params=params, headers=headers)
#The first element of the check_list array is deleted based on thread lock order.
        with lock:
            del check_list[0]

#If the threat value returend by the parse_ip_report function is 0, it is a safe IP.
        if parse_ip_report(response.json()) <= 0.00:
            print("\nVirusTotal Scan: Negative")
            clean_list.append(ip)
#If it is greater than 0, the pid of the file communicating with the process is killed with the osquery_Kill function.
        else:
            print("\nVirusTotal Scan: MALWARE COMMUNICATION DETECTED TO:", ip) #(More Info:", response.json()['permalink'], ")")
            osquery_Kill(ip,port)

#This while loop is responsible for continually calling the sendIP() and waiting the appropriate amount of time for the VirusTotal queue to reset again.
    while 1:
        if check_list:
            if queueOpen:
                queueOpen = False
                sendIP()
                sentTime = time.time()
                sentCount = 1
            elif sentCount < 3:
                sendIP()
                sentCount += 1
            else:
                wait = 61-(time.time()-sentTime)
                time.sleep(wait)
                queueOpen = True				

#This function parses each packet captured by Scapy's sniff function to append the destination IP and source port to the check_list. Filters out private, whitelisted, and already queued IP addresses.
def packet_callback(packet):
    if re.search(re.compile(r"\.255$"),packet[0][1].dst) is None and packet[0][1].dst not in clean_list:
        if packet[0][1].dst and packet[Ether].dst != mac:
            try:
                with lock:
                    if [packet[0][1].dst,packet[TCP].sport] not in check_list and not ipaddress.ip_address(packet[0][1].dst).is_private:
                        check_list.append([packet[0][1].dst,packet[TCP].sport])
                        print(check_list)
            except:
                pass

#The main function which initializes
##the thread for continuous VirusTotal analysis
##the thread for packet sniffing all interfaces
def main():
    Thread(target=check_IP).start()
    print("Sniffing")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == '__main__':
    main()
