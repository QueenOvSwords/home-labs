## Goal:

Detect port scanning by parsing logs and trigger `nftables` to block the source IP and create a cron job to automate this response. Show alternative method of port scan detection and response using `Fail2Ban`.

## Setup:

- Kali Linux 2024.3 virtual machine (Attacker)
- Ubuntu 24.04.2 LTS virtual machine (Target)
- VirtualBox Host-Only Network: `192.168.56.1/24`

## Attack:

I will be focusing on detecting SYN scans `-sS`, where the attacking machine will not complete the TCP handshake, instead sending a RST packet in response to the SYN-ACK packet sent from any open ports. 

I will be using T3 (Normal) Nmap timing `-T3`, behavior-based IDS is often needed to detect T0-T2 level scans.

I will also specify commonly used ports while scanning `-p`, which should be plenty to trigger detection of the scan.

`nmap -sS -T3 -p 21,22,23,25,53,80,110,135,139,443,445,3389 192.168.56.3`

## Manual Detection:

In order for port scanning to be detectable in logs, an `nftables` rule needs to be created. On the target Ubuntu machine, I used the below command to create a logging rule for incoming SYN scans.

`sudo nft add rule ip filter INPUT tcp flags syn log prefix "SYN_SCAN_ATTEMPT--"`

Next I performed the SYN scan from Kali on 12 common ports:

![](screenshots/port-scanning/nmap-scan.png)

Checking `/var/log/syslog` confirmed that the logging rules works, showing 12 log entries with the `"SYN_SCAN_ATTEMPT"` prefix and the port number that was scanned.

![](screenshots/port-scanning/manual-detection.png)