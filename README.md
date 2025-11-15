# A Day in the Life of a SOC Analyst, IOC Triage
## Date 09/16/2025
Recently, I received multiple suspicious files and logs from a coworker for triage. After analysis, several artifacts were confirmed as malicious including phishing campaigns, brute-force IPs, and domains linked to fraudulent activity

## Executive Summary
Threat actors continue to exploit email, brute-force attempts, and phishing domains to infiltrate organizations. As a SOC Analyst, part of my role is to validate and triage Indicators of Compromise (IOCs) shared by colleagues. This ensures we distinguish false positives from legitimate threats and take swift action to safeguard business operations.
During this investigation, multiple suspicious files and logs were analyzed. Several artifacts were confirmed as malicious, including phishing campaigns, brute-force IPs, and domains linked to fraudulent activities.

## "Possible IOC Samples. Please Review"
Inside the email, I find a list of suspicious artifacts gathered during system checks:
### . Download_Updated_Project_Files.eml
### .  PrimeSoft_auth.log
### .  PrimeSoft_firewall.log
### .  PrimeSoft_phishing.eml
### .  Reported_phish_nike.png
### .  Suspicious_email_shina.png
### .  Team_Building_Activity.eml


## Tech Stack
- **Kali Linux** – Investigation environment for IOC analysis
- **VirusTotal** – Malware/file hash checks & reputation lookups
- **AbuseIPDB** – IP enrichment, brute-force & abuse tracking
- **Hybrid Analysis** – Sandbox testing for suspicious files
- **MXToolbox** – Email header, DNS, and SMTP verification


## Investigation Flow
### STEP 1: Download_Updated_Project_Files.eml
<img src= "SOC_Analyst_images/soc_day_01.png" width= "600">
<img src= "SOC_Analyst_images/soc_day_02.png" width= "600">

On opening the file, it was found to be a suspicious phishing email campaign with the following IOCs 


Ip  =             209.85.216.41
                   10.13.154.136

Url  =                     htts://drive.google.com/uc?export=download&id=1bstuGMLer-fbJbcGG5JiqnlekTSKvq5y
                         
Sender  =      projectdpt@kanzalshamsprojectmgt.com

Receiver  =   nikefury@company.com

## Enrichment of IOCs
Ip    209.85.216.41  Suspicious {Virustotal, Anyrun, Abuseipdb}
<img src= "SOC_Analyst_images/soc_day_03.png" width= "600">
<img src= "SOC_Analyst_images/soc_day_04.png" width= "600">

Sender  =  projectdpt@kanzalshamsprojectmgt.com      
This domain is different from the receiver domain; if coming from the same organization, it has to be the same domain.

Receiver  =   nikefury@company.com

Email address: Malicious (phishing campaign), True Positive.

## Step 2: File Analysis [ PrimeSoft_phishing.eml]
<img src= "SOC_Analyst_images/soc_day_05.png" width= "600">
<img src= "SOC_Analyst_images/soc_day_06.png" width= "600">

 microsoftsecure-alert.com This domain is linked to this IP 185.220.101.1
 
Email address: Malicious (phishing campaign), True Positive

## Step3: File Analysis[Team_Building_Activity.eml]

On opening the file, it was found to be a suspicious phishing email with the following IOCs.

Ip   =    209.85.210.182

Url  =    http://theannoyingsite.com.

<img src= "SOC_Analyst_images/soc_day_08.png" width= "600">

## Enrichment of IOCs
Url =  http://theannoyingsite.com phishing and malicious, True Positive

<img src= "SOC_Analyst_images/soc_day_07.png" width= "600">
<img src= "SOC_Analyst_images/soc_day_09.png" width= "600">

Url =  http://theannoyingsite.com  malicious

Domain and IP Reputation Analysis

The domain theannoyingsite.com, created approximately seven years ago, has been flagged by 10 out of 94 security vendors as malicious.
MITRE ATT&CK™ mapping identified 44 indicators, associated with 24 attack techniques across 8 tactics, indicating a broad malicious footprint.

Further analysis showed that the domain is linked to the IP address 50.116.11.184, which has a High-Risk reputation. Recent activity suggests this IP has been involved in fraudulent or abusive behaviour, as confirmed by IPQS threat intelligence. Based on these findings, the site should be considered unsafe, and users are strongly advised not to access it.

Additionally, the sender and receiver domains in the email do not match, despite the message appearing to come from a teammate this is a common phishing red flag.

A separate IP identified in the investigation, 209.85.210.182, has also been classified as malicious, and this alert is assessed as a True Positive.

<img src= "SOC_Analyst_images/soc_day_010.png" width= "600">
Email: Malicious (phishing campaign), True Positive.

## Step4: File Analysis[PrimeSoft_auth.log]
<img src= "SOC_Analyst_images/soc_day_011.png" width= "600">

A long list of IPs was seen trying to intrude on the system with Failed password within the 48 hours.
<img src= "SOC_Analyst_images/soc_day_012.png" width= "600">

30 unique ip had Failed pasword.

<img src= "SOC_Analyst_images/soc_day_013.png" width= "600">.


30 unique ip had Connection closed.

<img src= "SOC_Analyst_images/soc_day_014.png" width= "600">. 


30 unique ip had Disconnected

<img src= "SOC_Analyst_images/soc_day_015.png" width= "600">


<img src= "SOC_Analyst_images/soc_day_016.png" width= "600">

5 unique ip had Accepted pasword
## Enrichment of  IOCs
These IPs with accepted passwords are all internal IPs and were all involved in brute force and port scanning activities

<img src= "SOC_Analyst_images/soc_day_017.png" width= "600">
 
<img src= "SOC_Analyst_images/soc_day_018.png" width= "600">

The following IP addresses have been identified as malicious and associated with brute-force attack activity:

64.113.32.26 — Flagged as malware-related and malicious by VirusTotal, AbuseIPDB, and Hybrid Analysis.

77.247.110.51 — Netherlands-based IP, reported as malicious by VirusTotal and AbuseIPDB.

5.188.206.130 — Bulgaria-based IP, classified as malicious and linked to brute-force attempts according to VirusTotal and AbuseIPDB.

These IPs which have been extracted from the prime_auth.log, IOC, demonstrate consistent malicious behavior across multiple threat-intelligence sources.

## Step5: File Analysis[PrimeSoft_firewall.log]

  A long list of IPs were blocked by the firewall, most of them were blocked multiple times within the 48 hours
  <img src= "SOC_Analyst_images/soc_day_022.png" width= "600">

  ## Enrichment  of  IOCs
  <img src= "SOC_Analyst_images/soc_day_023.png" width= "600">

 IP 103.152.220.58       country  Hong Kong, Domain Name is interstellarbd.net, suspicious
 IP 89.248.168.122      1/94 security vendor flagged this IP address as malicious(Virus Total)
 Country  Netherlands
 IP 77.247.110.51          1/94 security vendor flagged this IP address as malicious(Virus Total)
 It was first reported on June 17th, 2021, and the most recent report was 3 years ago
IP 77.247.110.51     was found in our database. This IP was reported 199 times (AbuseIPDB)
 Ip 45.155.205.233
IP 45.155.205.233  was found in our database and has been reported 1612 times (AbuseIPDB) Country  Russian Federation, 19/94 security vendors flagged this IP address as malicious(Virus Total)
 Ip  91.219.236.15  Country  Hungary/  was not found in most databases but is still suspicious, as one vendor has flagged it      as such (ArcSight threat intel.)
These IPs are malicious and are used for brute-force attacks

















Below is the full report. Please see the report below.

# Reprt 
[Report](https://github.com/osehale/A-Day-in-the-Life-of-a-SOC-Analyst-IOC-Triage/blob/main/A%20Day%20in%20the%20Life%20of%20a%20SOC%20Analyst_%20IOC%20Triage.pdf) 
 
