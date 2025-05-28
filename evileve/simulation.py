"""
EvilEVE: Human-like AI Attacker Simulation Framework
Main CLI Entry Point (modular version)
"""

import argparse
import time
import re
from core import profile_manager, mitre_engine, logger, psychology
from core.tool_executor import execute_tool
from core.monitor_tools import monitor_active_tools
from core.logger import log_phase_result_jsonl, log_tool_event_jsonl

MITRE_PHASES = [
    "Reconnaissance", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Lateral Movement",
    "Collection", "Exfiltration", "Impact"
]

def print_psych_state(traits, attacker):
    """Prints the current psychological state of the attacker."""
    print(f"Psych - Confidence: {traits.get('confidence')} "
          f"| Frustration: {traits.get('frustration')} "
          f"| Self-doubt: {traits.get('self_doubt')} "
          f"| Surprise: {traits.get('surprise')}")
    print(f"Suspicion: {attacker.get('suspicion')} | Utility: {attacker.get('utility')}")

def main():
    """Main entry point for running the EvilEVE attacker simulation."""
    parser = argparse.ArgumentParser(
        description="""
EvilEVE: Human-like AI Attacker Simulation Framework

This tool simulates a bias-influenced attacker executing tools across MITRE ATT&CK phases.
Tool choice, success, deception response, and psychological drift are all logged in real-time.

You can run interactively or pass arguments directly.

Examples:
  python3 simulation.py
  python3 simulation.py --name Eve --ip 10.0.0.81
  python3 simulation.py --name TestUser --ip 192.168.1.100 --phases 3 --seed 42 --dry-run
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--name", help="Attacker name (prompted if omitted)")
    parser.add_argument("--ip", help="Target IP address (prompted if omitted)")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--phases", type=int, default=5, help="Number of MITRE phases to simulate")
    parser.add_argument("--dry-run", action="store_true", help="Simulate phase logic without running tools")
    args = parser.parse_args()

    if not args.name:
        args.name = input("Enter attacker name: ").strip()
    if not args.ip:
        args.ip = input("Enter target IP address: ").strip()

    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', args.ip):
        raise ValueError(f"Invalid IP format: {args.ip}")

    if args.phases < 1 or args.phases > 9:
        raise ValueError("Phases must be between 1 and 9")

    if not args.name.isalnum():
        raise ValueError("Attacker name must be alphanumeric.")

    attacker = profile_manager.load_or_create_profile(
        args.name,
        args.seed,
        preserve_psych_baseline=True,
        initialize_skill=True
    )
    attacker["dry_run"] = args.dry_run

    active_tools = []

    for phase in MITRE_PHASES[:args.phases]:
        print(f"\nStarting Phase: {phase}")

        hesitation = attacker.get("current_psychology", {}).get("self_doubt", 0) * 0.2
        if hesitation:
            print(f"Hesitating... (delay: {hesitation:.1f}s due to self-doubt)")
            time.sleep(hesitation)

        try:
            mitre_result = mitre_engine.simulate_phase(attacker, phase, args.ip)
        except Exception as e:
            print(f"[!] Error during phase '{phase}': {e}")
            continue

        if not mitre_result or not isinstance(mitre_result, dict):
            print(f"[!] Invalid result returned for phase '{phase}', skipping...")
            continue

        monitored = monitor_active_tools(active_tools, timeout=60)
        for m in monitored:
            if m["pid"] == mitre_result.get("pid"):
                mitre_result["monitored_status"] = m["status"]
                mitre_result["exit_code"] = m["exit_code"]

                if not args.dry_run:
                    try:
                        log_tool_event_jsonl({
                            "attacker": attacker["name"],
                            "phase": phase,
                            "tool": m["tool"],
                            "args": m.get("args", []),
                            "pid": m["pid"],
                            "status": m["status"],
                            "exit_code": m["exit_code"],
                            "runtime": round(time.time() - m["start_time"], 2),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        })
                    except Exception as e:
                        print(f"[logger] Failed to write tool event: {e}")

        psychology.apply_correlations(attacker)
        psychology.update_suspicion_and_utility(attacker)
        psychology.export_cognitive_state(attacker, attacker_name=args.name)
        psychology.append_ctq_csv(attacker, attacker_name=args.name, phase=phase)

        traits = attacker.get("current_psychology", {})
        psych_snapshot = {
            "confidence": traits.get("confidence"),
            "self_doubt": traits.get("self_doubt"),
            "confusion": traits.get("confusion"),
            "frustration": traits.get("frustration"),
            "surprise": traits.get("surprise"),
            "suspicion": attacker.get("suspicion"),
            "utility": attacker.get("utility"),
        }

        phase_result = {
            "attacker": attacker["name"],
            "phase": phase,
            "tool": mitre_result.get("tool"),
            "args": mitre_result.get("args"),
            "pid": mitre_result.get("pid"),
            "elapsed": mitre_result.get("elapsed"),
            "exploit_used": mitre_result.get("exploit_used", None),
            "success": mitre_result.get("success"),
            "exit_code": mitre_result.get("exit_code"),
            "bias": mitre_result.get("bias"),
            "tool_reason": mitre_result.get("tool_reason"),
            "stdout_snippet": mitre_result.get("stdout_snippet"),
            "stderr_snippet": mitre_result.get("stderr_snippet"),
            "log_warning": mitre_result.get("log_warning", None),
            "deception_triggered": mitre_result.get("deception_triggered"),
            "monitored_status": mitre_result.get("monitored_status"),
            "plugin_errors": mitre_result.get("plugin_errors", []),
            "plugin_warnings": mitre_result.get("plugin_warnings", []),
            "dry_run": mitre_result.get("dry_run", False),
            "psych_state": psych_snapshot
    }


        try:
            log_phase_result_jsonl(attacker["name"], phase_result)
        except Exception as e:
            print(f"[logger] Failed to log phase result: {e}")

        if not args.dry_run:
            print_psych_state(traits, attacker)
        else:
            print("Phase simulated in [dry-run] mode.")

    profile_manager.save_profile(attacker, preserve_baseline=True, adjust_skill=True)

    if not args.dry_run:
        logger.finalize_summary(attacker, args.phases)
        logger.export_summary_report(attacker, args.phases)
        summarize_plugin_errors()
    else:
        print("\n[dry-run] Skipped final CSV/Markdown reports.")

    print("\nSimulation complete. Logs and profile updated.")

if __name__ == "__main__":
    main()

