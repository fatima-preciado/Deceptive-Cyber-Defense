# plugins/curl_plugin.py

import os
import time
import subprocess
from pathlib import Path

def run_curl_header_probe(target_url, log_dir="logs/curl"):
    """
    Executes a curl -I request to fetch headers from a target URL.

    Args:
        target_url (str): URL to probe (e.g., http://example.com)
        log_dir (str): Directory to store logs

    Returns:
        dict: Parsed header info and potential tool suggestions
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    log_path = os.path.join(log_dir, f"curl_{timestamp}.log")

    cmd = ["curl", "-I", target_url]

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10)
        decoded = output.decode("utf-8", errors="ignore")

        with open(log_path, "w") as f:
            f.write(decoded)

        suggestions = []
        deception_flags = []

        headers = decoded.lower()
        if "php" in headers or "x-powered-by: php" in headers:
            suggestions.append("sqlmap")
        if "apache" in headers or "nginx" in headers or "iis" in headers:
            suggestions.append("nmap")
        if "honeypot" in headers or "fake" in headers:
            deception_flags.append("suspicious-server-header")

        return {
            "target": target_url,
            "log": log_path,
            "headers": decoded,
            "suggestions": suggestions,
            "deception_flags": deception_flags
        }

    except subprocess.CalledProcessError as e:
        return {"error": f"curl failed: {e}", "target": target_url}
    except Exception as e:
        return {"error": f"Unexpected error: {e}", "target": target_url}
