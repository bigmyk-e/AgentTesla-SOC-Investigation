# 🔍 SOC Incident Investigation — AgentTesla Phishing & Data Exfiltration

![Incident](https://img.shields.io/badge/Incident-INC--2024--1204--001-red)
![Severity](https://img.shields.io/badge/Severity-HIGH%20%2F%20CRITICAL-red)
![Malware](https://img.shields.io/badge/Malware-AgentTesla-orange)
![Status](https://img.shields.io/badge/Status-Completed-green)
![Phase](https://img.shields.io/badge/AltSchool%20Africa-Capstone%20Project-blue)

## Overview

This repository documents a full SOC Tier 2 incident investigation into an AgentTesla phishing and data exfiltration campaign. The investigation reconstructs the complete attack chain from initial phishing email delivery through to FTP-based credential exfiltration, using real malware samples and network packet captures.

**Analyst:** Michael Leramo  
**Role:** SOC Analyst Tier 2  
**Organisation (Scenario):** Globex Manufacturing Ltd  
**Incident Reference:** INC-2024-1204-001  
**Date of Incident:** 4 December 2024

-----

## Scenario

A staff member at Globex Manufacturing Ltd reported unusual workstation behaviour after opening an email attachment from an apparent supplier. The security team suspected a phishing-based malware infection. My job was to investigate the incident using the provided email file and packet capture, determine the full attack chain, and produce a professional SOC incident report.

-----

## Evidence Files

|File                                                |Type          |Description                       |
|----------------------------------------------------|--------------|----------------------------------|
|`2024-12-04-AgentTesla-variant-malspam-1251-UTC.eml`|Email         |Phishing email — Phase 1 analysis |
|`2024-12-04-AgentTesla-variant-using-FTP.pcap`      |Packet Capture|Network traffic — Phase 2 analysis|


> Dataset source: <https://tinyurl.com/AgentTesla>

-----

## Tools Used

|Tool                                             |Purpose                                      |
|-------------------------------------------------|---------------------------------------------|
|Mozilla Thunderbird                              |Email analysis and raw header extraction     |
|Sublime Text                                     |Raw EML file inspection                      |
|Linux Terminal (munpack, file, md5sum, sha256sum)|Attachment extraction and hashing            |
|Python (eioc.py)                                 |Automated IOC extraction from EML            |
|VirusTotal                                       |Malware identification and behaviour analysis|
|AbuseIPDB                                        |IP reputation and abuse history              |
|MXToolbox                                        |SPF, DKIM, DMARC verification                |
|WHOIS                                            |Domain registration lookup                   |
|CyberChef                                        |Base64 decoding of email header              |
|Wireshark                                        |PCAP analysis — DNS, FTP, network forensics  |

-----

## Phase 1 — Phishing Email Analysis

### Key Findings

**Email Authentication — All Three Controls Failed**

|Control|Result    |Details                                        |
|-------|----------|-----------------------------------------------|
|SPF    |Softfail ❌|94.141.120.32 not authorised for acronas.com.tr|
|DKIM   |None ❌    |No digital signature present                   |
|DMARC  |None ❌    |No enforcement policy configured               |

**Originating IP: 94.141.120.32**

- ISP: DGTL TECH UK LLP
- Location: Roubaix, Hauts-de-France, France
- AbuseIPDB: 57 reports from 39 sources — Port Scan, Hacking, Brute-Force
- Reports recorded on 2024-12-03 and 2024-12-02 — the days immediately before this attack

**Social Engineering**

- Supplier/vendor impersonation (Business Email Compromise)
- Fake Turkish company: Acron Su ve Çevre Teknolojileri A.S
- Professional tone — no urgency to bypass spam filters
- Grammar errors: “Dea Sir”, “We are Turkish company”

**Attachment Analysis**

|Property     |Value                                                             |
|-------------|------------------------------------------------------------------|
|Declared Type|application/x-tar (TAR archive)                                   |
|Actual Type  |RAR archive data, v4, os: Win32                                   |
|File Size    |780.11 KB (798,831 bytes)                                         |
|MD5          |`b7635c9cc63619099419c68a2bf0d390`                                |
|SHA1         |`98683c9ee69dd591473629d231aacb1020db91b4`                        |
|SHA256       |`5c98308c69c84a57214442e2cadc9f8f0fcdbab8e6050f9915ac336b6f1d59f0`|
|VirusTotal   |49/63 — trojan.msil/agenttesla                                    |
|Contents     |1 Windows PE executable (.exe)                                    |


> The file was deliberately mislabelled as a .TAR archive to evade security filters that block .RAR files. This was confirmed independently by both the Linux `file` command and VirusTotal.

-----

## Phase 2 — Network Traffic Analysis

### PCAP Summary

|Property           |Value          |
|-------------------|---------------|
|Total Packets      |182            |
|Unique IP Addresses|4              |
|Infected Host      |10.12.4.101    |
|Attacker FTP Server|192.254.225.136|

### Infected Host

|Property        |Value            |
|----------------|-----------------|
|IP Address      |10.12.4.101      |
|MAC Address     |00:0c:f1:f4:7b:e1|
|Windows Username|gary.strickman   |
|Windows Hostname|DESKTOP-VJCRXEB  |

### DNS Analysis

Only two domains were queried in the entire capture:

|Packet |Domain              |Resolved IP    |Timestamp    |Significance                                               |
|-------|--------------------|---------------|-------------|-----------------------------------------------------------|
|1      |api.ipify.org       |172.67.74.152  |t=0.000000   |AgentTesla IP fingerprinting — first action after execution|
|18-19  |ftp.ercolina-usa.com|192.254.225.136|t=6.122416   |Attacker FTP server lookup                                 |
|143-144|ftp.ercolina-usa.com|192.254.225.136|t=1211.312537|Second session — beaconing confirmed                       |

### FTP Analysis (Critical)

**FTP Server Details**

|Property |Value                                        |
|---------|---------------------------------------------|
|Server IP|192.254.225.136                              |
|Domain   |ftp.ercolina-usa.com (CNAME ercolina-usa.com)|
|Port     |21                                           |
|Software |Pure-FTPd [privsep] [TLS]                    |

**Stolen FTP Credentials (Cleartext)**

```
USERNAME: ben@ercolina-usa.com
PASSWORD: nXe0M-WkW&nJ
AUTH:     230 OK
```

**Files Exfiltrated**

|#|Filename                                                                           |Timestamp    |Speed      |Session   |
|-|-----------------------------------------------------------------------------------|-------------|-----------|----------|
|1|PW_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_20_57.html                         |t=7.158194   |4.39 KB/s  |Session&nbsp;1 |
|2|CO_Chrome_Default.txt_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_21_03.txt       |t=8.180679   |126.77 KB/s|Session 1 |
|3|CO_Edge_Chromium_Default.txt_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_21_04.txt|t=8.619721   |90.09 KB/s |Session 1 |
|4|KL_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_41_04.html                         |t=1212.249450|—          |Session 2 |

**File Prefix Key**

- `PW_` — Password dump (harvested system and application passwords)
- `CO_Chrome_` — Google Chrome saved credentials and cookies
- `CO_Edge_` — Microsoft Edge saved credentials and cookies
- `KL_` — Keylogger output (all keystrokes recorded over ~20 minutes)

-----

## Full Attack Timeline

|Step|Timestamp    |Event                                                                     |
|----|-------------|--------------------------------------------------------------------------|
|1   |12:51:16 UTC |Phishing email delivered from 94.141.120.32                               |
|2   |Unknown      |Victim opens email and extracts attachment                                |
|3   |Unknown      |Victim executes TECHNICAL SPECIFICATIONS.exe                              |
|4   |t=0.000000   |AgentTesla queries api.ipify.org — IP fingerprinting                      |
|5   |t=0.049–0.394|TLS connection to api.ipify.org established                               |
|6   |t=6.122416   |DNS query for ftp.ercolina-usa.com                                        |
|7   |t=6.317201   |TCP SYN to 192.254.225.136:21                                             |
|8   |t=6.478618   |FTP server banner received                                                |
|9   |t=6.480941   |USER [ben@ercolina-usa.com](mailto:ben@ercolina-usa.com) sent in cleartext|
|10  |t=6.559166   |PASS nXe0M-WkW&nJ sent in cleartext                                       |
|11  |t=6.750190   |Login successful — 230 OK                                                 |
|12  |t=7.158194   |PW_ passwords file uploaded                                               |
|13  |t=8.180679   |CO_Chrome_ credentials uploaded                                           |
|14  |t=8.619721   |CO_Edge_ credentials uploaded                                             |
|15  |t=8.700017   |Session 1 closed                                                          |
|16  |t=1211.312537|Second DNS query — malware beacons back                                   |
|17  |t=1211.370119|Session 2 FTP connection established                                      |
|18  |t=1212.249450|KL_ keylogger data uploaded                                               |
|19  |t=1212.425168|226 OK — all exfiltration complete                                        |
|20  |t=1212.478147|Final packet — capture ends                                               |

-----

## IOC Summary

|# |Type          |Value                                                                              |Phase   |
|--|--------------|-----------------------------------------------------------------------------------|--------|
|1 |Email         |[sertan@acronas.com.tr](mailto:sertan@acronas.com.tr)                              |Phase&nbsp;1|
|2 |IP            |94.141.120.32                                                                      |Phase 1 |
|3 |Domain        |acronas.com.tr                                                                     |Phase 1 |
|4 |File          |TECHNICAL SPECIFICATIONS.TAR                                                       |Phase 1 |
|5 |File          |TECHNICAL SPECIFICATIONS.exe                                                       |Phase 1 |
|6 |MD5           |b7635c9cc63619099419c68a2bf0d390                                                   |Phase 1 |
|7 |SHA1          |98683c9ee69dd591473629d231aacb1020db91b4                                           |Phase 1 |
|8 |SHA256        |5c98308c69c84a57214442e2cadc9f8f0fcdbab8e6050f9915ac336b6f1d59f0                   |Phase 1 |
|9 |Malware       |trojan.msil/agenttesla                                                             |Phase 1 |
|10|IP            |10.12.4.101                                                                        |Phase 2 |
|11|MAC           |00:0c:f1:f4:7b:e1                                                                  |Phase 2 |
|12|Hostname      |DESKTOP-VJCRXEB                                                                    |Phase 2 |
|13|Username      |gary.strickman                                                                     |Phase 2 |
|14|IP            |192.254.225.136                                                                    |Phase 2 |
|15|Domain        |ftp.ercolina-usa.com                                                               |Phase 2 |
|16|Domain        |api.ipify.org                                                                      |Phase 2 |
|17|FTP Credential|[ben@ercolina-usa.com](mailto:ben@ercolina-usa.com)                                |Phase 2 |
|18|FTP Credential|nXe0M-WkW&nJ                                                                       |Phase 2 |
|19|Exfil File    |PW_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_20_57.html                         |Phase 2 |
|20|Exfil File    |CO_Chrome_Default.txt_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_21_03.txt       |Phase 2 |
|21|Exfil File    |CO_Edge_Chromium_Default.txt_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_21_04.txt|Phase 2 | 
|22|Exfil File    |KL_gary.strickman-DESKTOP-VJCRXEB_2024_12_04_21_41_04.html                         |Phase 2 |
|23|Malware Family|trojan.msil/agenttesla                                                             |Both    |

-----

## Deliverables

| Document | Link |
|---|---|
| 📄 Phishing Analysis Report | [View PDF](Phase1%20Phishing%20Analysis%20Report.pdf) |
| 📄 Network Investigation Report | [View PDF](Phase2%20Network%20Investigation%20Report.pdf) |
| 📊 IOC Summary Table | [View Excel](IOC%20Summary%20Table%20AgentTesla.xlsx) |
| 📊 Executive Summary Slide Deck | [View PowerPoint](Executive_Summary_AgentTesla.pptx) |
| 📁 Screenshots Evidence | [View Folder](Screenshots/) |

-----

## Key Takeaways

- AgentTesla uses **api.ipify.org** for victim IP fingerprinting as its first network action after execution — a reliable behavioural IOC
- FTP transmits credentials and file contents in **cleartext** — passive PCAP analysis is sufficient to fully reconstruct the exfiltration
- The **file type mismatch** (RAR disguised as TAR) is a deliberate evasion technique — always verify actual file type independently using the `file` command or VirusTotal
- The **AbuseIPDB timeline correlation** (abuse reports on 2024-12-03, attack on 2024-12-04) suggests the sending IP was part of active attacker infrastructure
- **Persistent beaconing** confirmed by second FTP session — incident response must assume continued activity until the host is isolated

-----

## About

This investigation was completed as the final capstone project for the AltSchool Africa SOC Analyst programme.

🔗 Portfolio: [bigmyk-e.github.io](https://bigmyk-e.github.io)  
🐦 X: [@Bigmykeb](https://twitter.com/Bigmykeb)  
💼 LinkedIn: [Michael Leramo](https://www.linkedin.com/in/michael-leramo)
