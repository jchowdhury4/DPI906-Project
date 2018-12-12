DPI906 Project by jchowdhury4 and inijjer

This is the final submission for the DPI906 Project

## DPI906_Project_jchowdhury4_inijjer_kill_remote_communication.py

The main script which:

* Uses Scapy to create a list of IPs and source ports that are establishing remote communication from the host
* Analyses remote IPs using VirusTotal API
* Uses OSQuery to find PID associated with malicious remote IPs
* Kills processes which are connecting to malicious remote IPs

### DPI906_Project_jchowdhury4_inijjer_host_based_anomalies.py

Only uses OSQuery and baseline json files to:

* Query system state (paths to services, processes, and startup items as well as their respective hashes)
* Compare system state to baselines
* Analyze hashes of anomaly files with VirusTotal API
* Identify malicious files based on their hashes

## Authors

* **Joy Chowdhury**
* **Inderpal Nijjer**
