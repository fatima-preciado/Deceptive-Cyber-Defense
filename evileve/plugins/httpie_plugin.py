"""
HTTPie Plugin for EvilEVE Attacker Framework

This plugin launches httpie against a target IP and returns structured output.
It inspects headers and HTTP response for common deception signs and queues follow-up tools if necessary.
"""

import subprocess
import time
import os
from pathlib import Path

def run_httpie_probe(target_ip, log_dir="logs/httpie"):
    """
    Launches an httpie GET request to the target IP.

    Args:
        target_ip (str): Target IP address.
        log_dir (str): Directory for output logs.

    Returns:
        dict: Results including output, timestamp, and deception hints.
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    log_path = os.path.join(log_dir, f"httpie_{target_ip}_{timestamp}.log")

    cmd = ["http", f"http://{target_ip}", "--headers"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        stdout = result.stdout
        stderr = result.stderr

        deception_signs = any(keyword in stdout.lower() for keyword in ["honeypot", "fake", "decoy"])
        followups = []
        if "apache" in stdout.lower() or "nginx" in stdout.lower():
            followups.append("sqlmap")

        return {
            "tool": "httpie",
            "target": target_ip,
            "timestamp": timestamp,
            "stdout": stdout,
            "stderr": stderr,
            "deception_triggered": deception_signs,
            "followups": followups,
            "log_path": log_path,
            "launched": True
        }

    except Exception as e:
        return {
            "tool": "httpie",
            "target": target_ip,
            "timestamp": timestamp,
            "stdout": "",
            "stderr": str(e),
            "deception_triggered": False,
            "followups": [],
            "log_path": log_path,
            "launched": False,
            "error": str(e)
        }

