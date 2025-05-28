# plugins/hydra_plugin.py
# to test if files exist:
# ls /usr/share/wordlists/rockyou.txt
# ls /usr/share/seclists/Usernames/top-usernames-shortlist.txt
# if not:
# sudo apt install seclists
# gzip -d /usr/share/wordlists/rockyou.txt.gz


# plugins/hydra_plugin.py

import os
import time
import subprocess
from pathlib import Path
from plugins.utils.errors import safe_open

def run_hydra_attack(
    target_ip,
    service="ssh",
    login_file="/usr/share/wordlists/usernames.txt",
    pass_file="/usr/share/wordlists/rockyou.txt",
    log_dir="logs/hydra"
):
    """
    Launches Hydra brute-force tool against a target IP/service using specified wordlists.

    Args:
        target_ip (str): The IP address of the target.
        service (str): Service to attack (e.g., ssh, ftp).
        login_file (str): Path to the usernames wordlist.
        pass_file (str): Path to the passwords wordlist.
        log_dir (str): Directory for log file output.

    Returns:
        dict: Metadata about the scan including log path and error status if any.
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    log_path = os.path.join(log_dir, f"hydra_{target_ip}_{timestamp}.log")

    # Create fallback wordlists if missing
    if not os.path.exists(login_file):
        try:
            with open(login_file, "w") as f:
                f.write("root\nadmin\nguest\n")
        except Exception as e:
            return {"error": f"Failed to write fallback login_file: {e}"}

    if not os.path.exists(pass_file):
        try:
            with open(pass_file, "w") as f:
                f.write("123456\npassword\nadmin\n")
        except Exception as e:
            return {"error": f"Failed to write fallback pass_file: {e}"}

    cmd = [
        "nohup", "hydra",
        "-L", login_file,
        "-P", pass_file,
        target_ip, service,
        "-o", log_path
    ]

    result = {
        "log": log_path,
        "target": target_ip,
        "service": service,
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
        print(f"[hydra_plugin] Hydra attack launched on {target_ip}:{service}, log → {log_path}")
    except Exception as e:
        result["error"] = f"Hydra failed: {e}"
        print(f"[hydra_plugin] Error launching Hydra: {e}")

    return result

# Optional standalone test
if __name__ == "__main__":
    print(run_hydra_attack("10.0.0.81"))




