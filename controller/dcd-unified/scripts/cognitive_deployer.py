#!/usr/bin/env python3

import os
import json
import time
import logging
import hashlib
from datetime import datetime
from dynamic_response import DynamicResponseManager
from prometheus_client import start_http_server, Counter
from collections import defaultdict

# Logging config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cognitive_deployer")

# Paths to honeypot logs
COWRIE_LOG = "/home/student/dcd-unified/data/cowrie/logs/cowrie.json"
DIONAEA_LOG = "/home/student/dcd-unified/data/dionaea/logs/dionaea.json"
ELASTICPOT_LOG = "/home/student/dcd-unified/data/elasticpot/logs/elasticpot.json"

# Metrics
DUPLICATE_EVENTS = Counter('duplicate_events', 'Number of duplicate events detected', ['ip', 'bias'])
PROCESSED_EVENTS = Counter('processed_events', 'Number of events processed', ['ip', 'bias'])
COOLDOWN_SKIPS = Counter('cooldown_skips', 'Number of events skipped due to cooldown', ['ip'])

# Cache to avoid repeated triggers
seen_events = {}  # Map event_id -> timestamp when first seen
event_counts = defaultdict(int)  # Count occurrences of each event
cooldown_cache = {}  # Track last response time per IP

# Dynamic response engine
response_manager = DynamicResponseManager()


def wait_for_services():
    import socket
    import requests
    import docker

    logger.info("Waiting for Elasticsearch and Docker to become available...")
    while True:
        try:
            requests.get("http://localhost:9200")
            docker.from_env().ping()
            logger.info("Elasticsearch and Docker are reachable")
            break
        except Exception:
            logger.warning("[!] Waiting on services...")
            time.sleep(5)


def extract_attacker_ip(log_line):
    try:
        data = json.loads(log_line)
        return data.get("src_ip") or data.get("remote_host") or "0.0.0.0"
    except:
        return "0.0.0.0"


def generate_event_id(log_line, bias):
    """Generate a more reliable unique identifier for events"""
    # Use SHA-256 hash for better uniqueness than the built-in hash()
    return hashlib.sha256(f"{bias}:{log_line}".encode()).hexdigest()


def handle_trigger(log_line, bias):
    ip = extract_attacker_ip(log_line)
    now = time.time()
    
    # Generate a reliable unique identifier for this event
    event_id = generate_event_id(log_line, bias)
    
    # Check if we've seen this exact event before
    if event_id in seen_events:
        # Update the count for this event
        event_counts[event_id] += 1
        
        # Log more detailed information about repeated events
        time_since_first = now - seen_events[event_id]
        logger.warning(f"[DUPLICATE] Event seen {event_counts[event_id]} times from {ip} with bias {bias}. "
                      f"First occurrence: {time_since_first:.1f} seconds ago")
        
        DUPLICATE_EVENTS.labels(ip=ip, bias=bias).inc()
        return
    
    # Record this as a new event with timestamp
    seen_events[event_id] = now
    event_counts[event_id] = 1
    
    # Cooldown logic: suppress frequent responses from same IP
    if ip in cooldown_cache and (now - cooldown_cache[ip]) < 15:
        logger.info(f"[Cooldown] Skipping repeated trigger for {ip}, last trigger was {now - cooldown_cache[ip]:.1f}s ago")
        COOLDOWN_SKIPS.labels(ip=ip).inc()
        return

    # Update cooldown timestamp and process event
    cooldown_cache[ip] = now
    
    logger.info(f"[Trigger] New event: Bias={bias}, Attacker={ip}, EventID={event_id[:8]}...")
    PROCESSED_EVENTS.labels(ip=ip, bias=bias).inc()
    
    response_manager.trigger_honeypot(bias, ip)
    response_manager.apply_response(bias, ip)


def monitor_logs():
    logger.info("[+] Starting behavioral log monitor")

    # Track file positions
    file_positions = {
        COWRIE_LOG: 0,
        DIONAEA_LOG: 0,
        ELASTICPOT_LOG: 0
    }

    # Debug counters
    iteration_count = 0
    total_lines_processed = 0

    while True:
        iteration_count += 1
        lines_this_iteration = 0
        
        for path, bias in [(COWRIE_LOG, "anchoring"), (DIONAEA_LOG, "confirmation"), (ELASTICPOT_LOG, "overconfidence")]:
            if not os.path.exists(path):
                continue

            try:
                with open(path, "r") as f:
                    f.seek(file_positions[path])
                    for line in f:
                        lines_this_iteration += 1
                        total_lines_processed += 1
                        
                        if not line.strip():
                            continue
                            
                        if "ftpd" in line or "login attempt" in line or "exploit" in line:
                            logger.info(f"[PROCESSING] Found relevant line: {line.strip()[:100]}...")
                            handle_trigger(line.strip(), bias)
                            
                    file_positions[path] = f.tell()
            except Exception as e:
                logger.warning(f"[!] Failed to process {path}: {e}")

        # Log statistics periodically
        if iteration_count % 10 == 0:
            logger.info(f"[STATS] Total iterations: {iteration_count}, "
                       f"Total lines processed: {total_lines_processed}, "
                       f"Unique events: {len(seen_events)}, "
                       f"Cooldown IPs: {len(cooldown_cache)}")
            
            # Log top duplicated events if we have any
            if event_counts:
                top_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                logger.info(f"[STATS] Top duplicated events: {', '.join([f'{event_id[:8]}... ({count})' for event_id, count in top_events])}")
        
        response_manager.scale_down_honeypots()
        time.sleep(10)



if __name__ == "__main__":
    start_http_server(8000)
    wait_for_services()
    monitor_logs()
