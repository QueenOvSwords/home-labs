#! /usr/bin/env python3

from collections import defaultdict
from datetime import datetime
import subprocess

BLOCKED_IPS_FILE = "blocked_ips.txt"
LOG_FILE = "/var/log/syslog"
LOG_PREFIX = "SYN_SCAN_ATTEMPT--"
SCAN_THRESHOLD = 10
SCAN_TIMEFRAME = 60

def block_ip(ip):
    # Block the IP with nftables
    cmd = ["sudo", "nft", "add", "element", "ip", "filter", "blocked_ips", f"{{ {ip} }}"]
    subprocess.run(cmd)

def count_recent_syns(ip_logs):
    ips_to_block = set()

    for ip, timestamps in ip_logs.items():
        # Count log entries from unique IPs in the chosen timeframe 
        count = 0
        
        for timestamp in timestamps: 
            timestamp = datetime.fromisoformat(timestamp.split("+")[0])
            
            if (datetime.now() - timestamp).total_seconds() <= SCAN_TIMEFRAME:
                count += 1
        # Add IP to block list if count has reached the chosen threshold
        if count >= SCAN_THRESHOLD:
            ips_to_block.add(ip)

    ips_to_block.add('1.3.4.3')
    return ips_to_block

def parse_logs():
    ip_logs = defaultdict(list)

    # Search entries of syslog for the SYS_SCAN_ATTEMPTS-- prefix
    with open(LOG_FILE, 'r') as file:
        for line in file:
            if LOG_PREFIX in line:
                # Add source IPs of each SYN scan log 
                for part in line.split():
                    if part.startswith("SRC="):
                        ip = part.split("=")[1]
                        # Add each timestamp of log entries from that IP to ip_logs defualtdict
                        ip_logs[ip].append(line.split()[0])
    
    return count_recent_syns(ip_logs)


def main():
    # Open or create a file to keep track of blocked IPs
    try:
        with open(BLOCKED_IPS_FILE, 'r') as file:
            already_blocked = set(line.strip() for line in file)
    except FileNotFoundError:
        already_blocked = set()
    
    # Parse logs and return any IPs conducting too many port scans
    ips_to_block = parse_logs()

    # Block the malicious IP addresses and write them to the blocked IPs file
    with open(BLOCKED_IPS_FILE, 'a') as file:
        for ip in ips_to_block:
            if ip not in already_blocked:
                block_ip(ip)
                file.write(f"{ip}\n")


if __name__ == "__main__":
    main()
