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

lock = threading.Lock()
my_logger = logging.getLogger('test_logger')                       
my_logger.setLevel(logging.WARNING)

handler = graypy.GELFHandler('192.168.0.25', 12201)                      
my_logger.addHandler(handler)

mac = ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2))

clean_list = []
check_list = []

whitelist = ['8.8.8.8', ]

def osquery_Kill(ip,port):
    query = 'osqueryi --json "SELECT sock.pid,proc.name FROM process_open_sockets as sock INNER JOIN processes AS proc ON proc.pid = sock.pid where sock.remote_address = \'{}\' and sock.local_port = \'{}\';"'.format(ip,port)
    res = json.loads(subprocess.check_output(query).decode('ascii'))
    if res:
        kill = "taskkill /F /PID {}".format(res[0]['pid'])
        subprocess.check_output(kill)
        print(res[0]['name'], "killed due to malicious communication to remote host:", ip)
    else:
        print("Process Dead, process name not found")
	

def check_IP():
    global check_list
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip,  My Python requests library example client or username"
    }
	
    sentTime = 0
    sentCount = 0
    queueOpen = True
	
    def parse_ip_report(report):
        positives = 0
        total = 0
        for i in report:
            if type(report[i]) is list and len(report[i]) > 0:
                for j in report[i]:
                    if type(j) is dict and 'positives' in j and 'total' in j and j['positives'] > 0 and j['total'] > 0:
                        threat = j['positives'] / j['total']
                        return threat
        return 0
    
    def sendIP():
        global check_list
        global clean_list
        ip = check_list[0][0]
        port = check_list[0][1]
			
        params = {'ip':ip,'apikey': '3cbca5edaccf0e9e75ae2ac3da367000439ac414caeb4adea933d3304661fe16'}
        response = requests.get('https://virustotal.com/vtapi/v2/ip-address/report', params=params, headers=headers)
        with lock:
            del check_list[0]

        if parse_ip_report(response.json()) <= 0.00:
            print("\nVirusTotal Scan: Negative")
            clean_list.append(ip)            
        else:
            print("\nVirusTotal Scan: MALWARE COMMUNICATION DETECTED TO:", ip) #(More Info:", response.json()['permalink'], ")")
            osquery_Kill(ip,port)
        #except:
        #    print("error")
        #    pass		
		
		#try:
        #    if response.json()['positives'] > 0:
        #        print("\nVirusTotal Scan: MALWARE DETECTED (More Info:", response.json()['permalink'], ")")
        #        osquery_Kill(IP,port)
        #    else:
        #        print("\nVirusTotal Scan: Negative")
        #        clean_list.append(ip)
        #except:
        #    pass
	
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
			    
				    
		 
	        
#def check_indicator(dst):
	#global clean_list
	#events = api.ip_events(dst)
	#if events['count'] > 0:
	#	Log = '{}\nDestination IP:{}\n{}\n{}'.format(events['results'][0]['title'], dst, events['results'][0]['details_url'], events['results'][0]['description'])
	#	my_logger.warning(Log)
	#else:
	#	clean_list.append(dst) 


def packet_callback(packet):
    #if packet[0][1].dst in indicators:
    #    check_indicator(packet[0][1].dst)
    #if packet.haslayer(http.HTTPRequest):
    #    url = get_url(packet)
    #    if url in url_list:
    #        check_indicator(url)   
    if re.search(re.compile(r"\.255$"),packet[0][1].dst) is None and packet[0][1].dst not in clean_list:
        if packet[0][1].dst and packet[Ether].dst != mac:
            #if packet.haslayer(http.HTTPRequest):
            #    url = get_url(packet)
            try: # packet[TCP].sport:
                with lock:
                    if [packet[0][1].dst,packet[TCP].sport] not in check_list and not ipaddress.ip_address(packet[0][1].dst).is_private:
                        check_list.append([packet[0][1].dst,packet[TCP].sport])
                        print(check_list)
            except:
                pass
            #Thread(target=check_indicator, args=packet[0][1].dst).start()



def main():
    Thread(target=check_IP).start()
    print("Sniffing")
    sniff(filter="ip", prn=packet_callback, store=0)
  

if __name__ == '__main__':
    main()
