#!/usr/bin/env python3
import json
import random
import time
import sys
from datetime import datetime, timedelta

# Configuration
output_file = sys.argv[1] if len(sys.argv) > 1 else "cowrie2.json"
num_records = int(sys.argv[2]) if len(sys.argv) > 2 else 100
attack_ips = ["123.45.67.89", "98.76.54.32", "111.222.333.444", "55.66.77.88"]
usernames = ["admin", "root", "user", "oracle", "test", "ubuntu"]
passwords = ["password", "123456", "admin", "root", "qwerty", "letmein"]
events = ["scan", "login attempt"]
protocols = ["ssh", "telnet"]
ports = [22, 23, 2222, 2223]

# Generate data with controlled duplicates
with open(output_file, "w") as f:
    # Start time - 1 hour ago
    current_time = datetime.now() - timedelta(hours=1)
    
    for i in range(num_records):
        timestamp = current_time.isoformat()
        
        # Advance time by 30-60 seconds
        current_time += timedelta(seconds=random.randint(30, 60))
        
        # Select random or fixed values
        ip = attack_ips[i % len(attack_ips)]  # Cycle through IPs for duplicates
        event_type = events[i % len(events)]  # Alternate between scan and login
        
        # Create record
        record = {
            "src_ip": ip,
            "event": event_type,
            "@timestamp": timestamp,
            "honeypot": "cowrie"
        }
        
        # Add event-specific fields
        if event_type == "login attempt":
            record["username"] = usernames[random.randint(0, len(usernames)-1)]
            record["password"] = passwords[random.randint(0, len(passwords)-1)]
            record["protocol"] = protocols[random.randint(0, len(protocols)-1)]
            
        elif event_type == "scan":
            # Every 3rd scan will have port info, others will be generic
            if i % 3 == 0:
                record["dst_port"] = random.choice(ports)
                record["protocol"] = random.choice(protocols)
        
        # Write to file
        f.write(json.dumps(record) + "\n")
        
        # Create exact duplicates every 5th record (with different timestamps)
        if i > 0 and i % 5 == 0:
            for j in range(3):  # Create 3 duplicates
                dup_record = record.copy()
                dup_record["@timestamp"] = (current_time + timedelta(seconds=j+1)).isoformat()
                f.write(json.dumps(dup_record) + "\n")

print(f"Generated {num_records} records (plus duplicates) in {output_file}")
