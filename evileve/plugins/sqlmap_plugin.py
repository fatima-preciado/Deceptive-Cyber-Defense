# plugins/sqlmap_plugin.py

import os
import time
import subprocess
from pathlib import Path
from plugins.utils.errors import safe_open


def run_sqlmap_attack(target_url, output_dir="logs/sqlmap", level=1):
    """
    Launches a SQLMap scan in background using nohup.

    Args:
        target_url (str): The target URL to scan (e.g., http://example.com/index.php?id=1).
        output_dir (str): Directory where logs will be stored.
        level (int): Intensity level (1–5) for SQLMap scan.

    Returns:
        dict: Metadata about the launched scan, including log file and timestamp.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    log_path = os.path.join(output_dir, f"sqlmap_{timestamp}.log")

    cmd = [
        "nohup", "sqlmap",
        "-u", target_url,
        "--batch",
        "--level", str(level),
        "--risk", "1",
        "--random-agent",
        "--output-dir", output_dir
    ]

    result = {
        "tool": "sqlmap",
        "target": target_url,
        "log": log_path,
        "timestamp": timestamp,
        "launched": False,
        "error": None
    }

    try:
        with safe_open(log_path, "w") as logfile:
            subprocess.Popen(
                cmd,
                stdout=logfile,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setpgrp
            )
        result["launched"] = True
        print(f"[sqlmap_plugin] SQLMap launched for: {target_url}")
    except Exception as e:
        result["error"] = f"SQLMap failed: {e}"
        print(f"[sqlmap_plugin] Launch failed: {e}")

    return result


def parse_sqlmap_log(log_path):
    """
    Parses SQLMap log output to detect success, warnings, or errors.

    Args:
        log_path (str): Path to the SQLMap log file.

    Returns:
        dict: Summary containing flags like 'vulnerable', 'errors', 'warnings'.
    """
    result = {
        "vulnerable": False,
        "errors": [],
        "warnings": [],
        "log_path": log_path
    }

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line_lower = line.lower()

                if "sql injection vulnerability" in line_lower:
                    result["vulnerable"] = True

                if "[error]" in line_lower or "traceback" in line_lower:
                    result["errors"].append(line.strip())

                if "[warning]" in line_lower:
                    result["warnings"].append(line.strip())

    except Exception as e:
        result["errors"].append(f"Log parsing failed: {e}")

    return result
