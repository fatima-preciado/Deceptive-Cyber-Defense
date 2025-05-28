import os
import json
from pathlib import Path
from datetime import datetime

PLUGIN_ERROR_LOG = os.path.expanduser("~/.evilEVE/logs/plugin_errors.jsonl")


def log_plugin_error(attacker: str, phase: str, tool: str, error_msg: str, context: dict = None):
    """
    Appends a plugin error entry to the plugin error log.

    Args:
        attacker (str): Attacker name or profile.
        phase (str): MITRE phase where the error occurred.
        tool (str): The plugin/tool involved (e.g., metasploit, ghidra).
        error_msg (str): Description of the error or exception.
        context (dict): Optional additional details (e.g., input params).
    """
    Path(os.path.dirname(PLUGIN_ERROR_LOG)).mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now().isoformat(),
        "attacker": attacker,
        "phase": phase,
        "tool": tool,
        "error": error_msg,
        "context": context or {}
    }

    try:
        with open(PLUGIN_ERROR_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[plugin_errors] Failed to write plugin error: {e}")


def summarize_plugin_errors(log_path=PLUGIN_ERROR_LOG):
    """
    Prints a summary of plugin errors from the log.

    Args:
        log_path (str): Path to the plugin error log file.
    """
    if not os.path.exists(log_path):
        print("[plugin_errors] No plugin errors were logged.")
        return

    try:
        with open(log_path) as f:
            entries = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        print(f"[plugin_errors] Could not parse plugin error log: {e}")
        return

    if not entries:
        print("[plugin_errors] No plugin errors found.")
        return

    print("\n=== Plugin Error Summary ===")
    for entry in entries:
        print(f"[{entry['timestamp']}] Phase: {entry['phase']} | Tool: {entry['tool']} | Error: {entry['error']}")
