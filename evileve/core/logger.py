# /core/logger.py

import os
import json
from datetime import datetime
from collections import Counter
from pathlib import Path
from plugins.utils.errors import safe_open, safe_write_jsonl
import logging
from logging.handlers import RotatingFileHandler

# Centralized logging root
EVILEVE_HOME = os.path.expanduser("~/.evilEVE")
PHASE_LOG_DIR = os.path.join(EVILEVE_HOME, "logs/phase_runs")
TOOL_LOG_DIR = os.path.join(EVILEVE_HOME, "logs/tool_runs")
CSV_LOG_FILE = os.path.join(EVILEVE_HOME, "logs/attack_log.csv")
SUMMARY_REPORT_DIR = os.path.join(EVILEVE_HOME, "reports")

def ensure_log_dirs():
    base_dir = os.path.expanduser("~/.evilEVE")
    for subdir in ["logs", "logs/tool_runs", "logs/phase_runs", "reports"]:
        path = os.path.join(base_dir, subdir)
        os.makedirs(path, mode=0o750, exist_ok=True)

def get_rotating_logger(name, logfile, level=logging.INFO, max_bytes=5 * 1024 * 1024, backup_count=3):
    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    handler = RotatingFileHandler(logfile, maxBytes=max_bytes, backupCount=backup_count)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


def log_attack(attacker, tool, target_ip, phase, result):
    """
    Appends a line to the central CSV log of attacks.
    """
    os.makedirs(os.path.dirname(CSV_LOG_FILE), exist_ok=True)
    traits = attacker.get("current_psychology", {})

    f = safe_open(CSV_LOG_FILE, "a")
    if f:
        f.write(f"{datetime.now()},{attacker['id']},{attacker['name']},{tool},{target_ip},{phase},"
                f"{result['success']},{attacker.get('suspicion', 0)},{traits.get('confidence', 0)},"
                f"{traits.get('frustration', 0)},{traits.get('self_doubt', 0)},{result['exit_code']}\n")
        f.close()


def log_phase_result_jsonl(attacker_name, result, out_dir=PHASE_LOG_DIR):
    """
    Appends the result of a simulate_phase() call to a .jsonl log file for analysis.
    """
    from copy import deepcopy
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    filepath = Path(out_dir) / f"{attacker_name}_phases.jsonl"

    traits = deepcopy(result.get("psych_state", {}))
    result_clean = {k: v for k, v in result.items() if k != "psych_state"}
    result_clean.update(traits)

    safe_write_jsonl(filepath, result_clean)


def log_tool_event_jsonl(entry, out_dir=TOOL_LOG_DIR):
    """
    Logs tool execution details such as PID, tool name, args, status, and exit code.
    Each line is a JSON record.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    filepath = Path(out_dir) / "tool_run.jsonl"

    safe_write_jsonl(filepath, entry)


def finalize_summary(attacker, num_phases=0):
    traits = attacker.get("current_psychology", {})
    print("\nSummary of Simulation:")
    print(f"   Phases simulated: {num_phases}")
    print(f"   Tools used: {attacker.get('tools_used', [])}")
    print(f"   Time wasted: {attacker.get('metrics', {}).get('time_wasted', 0)} seconds")
    print(f"   Failed attempts: {sum(attacker.get('failed_attempts', {}).values())}")
    print(f"   Confidence: {traits.get('confidence', 'N/A')}")
    print(f"   Frustration: {traits.get('frustration', 'N/A')}")
    print(f"   Self-doubt: {traits.get('self_doubt', 'N/A')}")
    print(f"   Suspicion: {attacker.get('suspicion', 'N/A')}")


def export_summary_report(attacker, num_phases, out_dir=SUMMARY_REPORT_DIR):
    """
    Outputs a markdown summary report of simulation results for an attacker profile.
    """
    name = attacker["name"]
    os.makedirs(out_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{name}_summary_{timestamp}.md"
    filepath = os.path.join(out_dir, filename)

    traits = attacker.get("current_psychology", {})
    metrics = attacker.get("metrics", {})
    tools_used = attacker.get("tools_used", [])
    tool_counts = Counter(tools_used)
    skill = attacker.get("skill", "?")

    f = safe_open(filepath, "w")
    if not f:
        return

    f.write(f"# EvilEVE Summary Report: {name}\n")
    f.write(f"**Date:** {timestamp}\n")
    f.write(f"**MITRE Phases Simulated:** {num_phases}\n\n")

    f.write("## Final Psychological Profile\n")
    for trait, value in traits.items():
        f.write(f"- **{trait.capitalize()}**: {value}\n")
    f.write(f"- **Suspicion**: {attacker.get('suspicion', '?')}\n")
    f.write(f"- **Skill Level**: {skill}\n\n")

    f.write("## Performance Summary\n")
    f.write(f"- **Total Tools Used**: {len(tools_used)}\n")
    f.write(f"- **Time Wasted**: {metrics.get('time_wasted', 0)} seconds\n")
    f.write(f"- **Failed Attempts**: {metrics.get('false_actions', 0)}\n\n")

    f.write("## Tool Usage Frequency\n")
    if tool_counts:
        for tool, count in tool_counts.most_common():
            f.write(f"- {tool}: {count} use(s)\n")
    else:
        f.write("No tools used.\n")

    f.close()
    print(f" Summary report written to: {filepath}")


