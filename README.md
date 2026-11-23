# Project 2: Network Threat Hunting and IDS Detection Lab

## Project Overview
This project demonstrates network traffic analysis, threat hunting,
intrusion detection and custom alert generation in a controlled lab.

## Lab Environment
- Analysis and IDS machine: Kali Linux
- Target machine: Windows VM
- Network: Controlled virtual lab environment
- Private lab IP addresses have been anonymised in this public repository.

## Tools Used
- Wireshark
- Nmap
- Suricata 8.0.7
- Python 3.13.11
- Scapy 2.5.0

## Project Activities
1. Network packet analysis using Wireshark.
2. Controlled Nmap SYN scan against the Windows VM.
3. HTTP traffic generation with a custom User-Agent.
4. Custom Suricata IDS rule creation and testing.
5. Python-based TCP SYN scan detection.
6. Python-based HTTP User-Agent hunting.
7. Suricata EVE JSON alert analysis.

## Key Findings
- 2,000 TCP SYN packets observed.
- 1,000 unique destination ports identified.
- 198 Suricata alerts for the custom SYN scan rule.
- 1 alert for the custom HTTP User-Agent rule.
- 210 total Suricata alert events across 5 rules.

## MITRE ATT&CK
T1046 - Network Service Discovery.

## Zeek
Zeek Core 8.0.11 was installed and tested.
However, its runtime did not operate successfully in the
resource-constrained virtual machine. Zeek analysis was
therefore not included in the completed findings.

## Evidence
- evidence/pcaps/
- evidence/suricata/
- python-threat-hunting/

## Disclaimer
All scanning and detection activities were performed in a
controlled educational lab environment.
