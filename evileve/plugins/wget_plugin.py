# plugins/wget_plugin.py

"""
Wget Plugin for EvilEVE Attacker Simulation

Performs HTTP/HTTPS request and logs headers/content to detect simple deception
and suggest follow-up tools based on discovered keywords.
"""

import subprocess
import time
import os

def run_wget_probe(target_ip, log_dir="logs/wget"):
    """
    Executes wget to probe the target and logs output headers/content.

    Args:
        target_ip (str): Target IP address.
        log_dir (str): Output directory for logs.

    Returns:
        dict: Plugin result with tool metadata, deception signals, and follow-ups.
    """
    os.makedirs(log_dir, exist_ok=True)
    timestamp = int(time.time())
    log_path = os.path.join(log_dir, f"wget_{target_ip}_{timestamp}.log")

    result = {
        "tool": "wget",
        "args": [target_ip],
        "pid": None,
        "launched": False,
        "timestamp": timestamp,
        "stdout_snippet": "",
        "stderr_snippet": "",
        "monitored_status": "plugin",
        "exit_code": None,
        "deception_triggered": False,
        "plugin_errors": [],
        "plugin_warnings": [],
    }

    try:
        cmd = ["wget", f"http://{target_ip}", "-O", "-", "--timeout=5"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        result["launched"] = True
        result["exit_code"] = proc.returncode
        result["stdout_snippet"] = proc.stdout[:1000]
        result["stderr_snippet"] = proc.stderr[:500]

        # Save log
        with open(log_path, "w") as f:
            f.write(proc.stdout)

        # Deception clues
        if any(x in proc.stdout.lower() for x in ["honeypot", "default apache", "fake", "trap"]):
            result["deception_triggered"] = True

        # Follow-up hints
        followups = []
        if "php" in proc.stdout.lower():
            followups.append("sqlmap")
        if "login" in proc.stdout.lower():
            followups.append("hydra")
        if followups:
            result["wget_followups"] = followups

    except subprocess.TimeoutExpired:
        result["plugin_errors"].append("Wget timeout")
    except Exception as e:
        result["plugin_errors"].append(f"Wget failed: {e}")
        result["log_warning"] = str(e)

    return result
