#!/usr/bin/env python3
"""
analyze_phase_log.py — EvilEVE Phase Log Analyzer

Usage Examples:
  python3 analyze_phase_log.py --log logs/phase_runs/Eve_phases.jsonl
  python3 analyze_phase_log.py --log_dir logs/phase_runs --export_csv out/{name}_summary.csv --export_matrix out/{name}_matrix.csv

Arguments:
  --log             Analyze a single .jsonl phase log file.
  --log_dir         Batch process all .jsonl files in a directory.
  --export_csv      Export raw summary to CSV (use {name} in filename).
  --export_matrix   Export bias-tool matrix to CSV (use {name} in filename).
"""

import argparse
import json
import csv
from collections import Counter
from pathlib import Path

def load_jsonl(path):
    with open(path, "r") as f:
        return [json.loads(line.strip()) for line in f if line.strip()]

def summarize(log_data):
    phases = len(log_data)
    tools = [entry["tool"] for entry in log_data if entry.get("tool")]
    biases = [entry["bias"] for entry in log_data if entry.get("bias")]
    exit_codes = [entry["exit_code"] for entry in log_data if entry.get("exit_code") is not None]
    success_count = sum(1 for entry in log_data if entry.get("success") is True)
    failure_count = sum(1 for entry in log_data if entry.get("success") is False)
    deception_hits = sum(1 for entry in log_data if entry.get("deception_triggered"))
    monitored_status = Counter(entry.get("monitored_status", "unknown") for entry in log_data)

    print("\n Phase Log Summary")
    print(f"- Total Phases Simulated: {phases}")
    print(f"- Successful Tools: {success_count}")
    print(f"- Failed Tools: {failure_count}")
    print(f"- Deception Triggers: {deception_hits}")
    print(f"- Unique Tools Used: {len(set(tools))}")
    print(f"- Biases Activated: {Counter(biases)}")
    print(f"- Tool Frequency: {Counter(tools)}")
    print(f"- Exit Code Distribution: {Counter(exit_codes)}")
    print(f"- Monitor Status: {dict(monitored_status)}")

def save_csv(log_data, out_path):
    keys = [
        "attacker", "phase", "tool", "args", "pid", "elapsed", "success",
        "exit_code", "bias", "deception_triggered", "monitored_status"
    ]
    with open(out_path, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in log_data:
            writer.writerow({k: row.get(k, "") for k in keys})
    print(f"\n Phase summary exported to: {out_path}")

def analyze_bias_tool_outcomes(log_data, export_path=None):
    matrix = {}

    for entry in log_data:
        bias = entry.get("bias")
        tool = entry.get("tool")
        success = entry.get("success")
        if not (bias and tool):
            continue
        key = (bias, tool)
        matrix.setdefault(key, {"success": 0, "failure": 0})
        if success:
            matrix[key]["success"] += 1
        else:
            matrix[key]["failure"] += 1

    def colorize(rate):
        if rate >= 80:
            return f"\033[92m{rate:.1f}%\033[0m"
        elif rate >= 50:
            return f"\033[93m{rate:.1f}%\033[0m"
        else:
            return f"\033[91m{rate:.1f}%\033[0m"

    print("\n📈 Bias–Tool Outcome Matrix")
    print(f"{'Bias':<16} {'Tool':<14} {'Success':<8} {'Fail':<6} {'Total':<6} {'Success Rate':<14}")
    print("-" * 66)

    rows = []
    for (bias, tool), outcomes in sorted(matrix.items()):
        s = outcomes["success"]
        f = outcomes["failure"]
        total = s + f
        rate = 100 * s / total if total else 0
        rate_colored = colorize(rate)
        print(f"{bias:<16} {tool:<14} {s:<8} {f:<6} {total:<6} {rate_colored:<14}")
        rows.append({
            "bias": bias,
            "tool": tool,
            "success": s,
            "failure": f,
            "total": total,
            "success_rate": round(rate, 1)
        })

    if export_path:
        with open(export_path, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["bias", "tool", "success", "failure", "total", "success_rate"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n Bias–Tool matrix exported to: {export_path}")

def process_log_file(jsonl_path, export_csv=None, export_matrix=None):
    log_data = load_jsonl(jsonl_path)
    if not log_data:
        print(f"[!] {jsonl_path.name} is empty.")
        return

    print(f"\n Processing: {jsonl_path.name}")
    summarize(log_data)

    if export_csv:
        csv_out = export_csv.replace("{name}", jsonl_path.stem)
        save_csv(log_data, csv_out)

    matrix_out = export_matrix.replace("{name}", jsonl_path.stem) if export_matrix else None
    analyze_bias_tool_outcomes(log_data, export_path=matrix_out)

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--log", help="Path to a single attacker .jsonl log file.")
    parser.add_argument("--log_dir", help="Directory of .jsonl files to batch process.")
    parser.add_argument("--export_csv", help="Export CSV path, use {name} in filename.")
    parser.add_argument("--export_matrix", help="Export bias-tool matrix path, use {name} in filename.")

    args = parser.parse_args()

    if args.log:
        path = Path(args.log)
        if not path.exists():
            print(f"[!] Log file not found: {path}")
            return
        process_log_file(path, args.export_csv, args.export_matrix)

    elif args.log_dir:
        folder = Path(args.log_dir)
        if not folder.exists() or not folder.is_dir():
            print(f"[!] Log directory not found: {folder}")
            return
        for file in sorted(folder.glob("*.jsonl")):
            process_log_file(file, args.export_csv, args.export_matrix)

    else:
        print("[!] Please specify either --log or --log_dir")

if __name__ == "__main__":
    main()

