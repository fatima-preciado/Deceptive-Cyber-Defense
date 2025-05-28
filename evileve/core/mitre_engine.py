# core/mitre_engine.py

import os
import time
import random
import json
from core.tool_executor import execute_tool
from core.reward_system import update_profile_feedback
from core.logger import log_attack
from core.memory_graph import update_memory_graph
from core.monitor_tools import monitor_active_tools
from core.plugin_errors import summarize_plugin_errors
from plugins.metasploit_plugin import run_msf_attack, parse_msf_log
from plugins.ghidra_plugin import GhidraHeadlessPlugin
from plugins.hydra_plugin import run_hydra_attack
from plugins.nmap_plugin import run_nmap_scan
from plugins.nmap_interpreter import interpret_nmap_json
from plugins.sqlmap_plugin import run_sqlmap_attack, parse_sqlmap_log
from plugins.curl_plugin import run_curl_header_probe as run_curl_check
from plugins.wget_plugin import run_wget_probe
from plugins.httpie_plugin import run_httpie_probe
from plugins import next_tool_queue
from core.config_loader import get_path, get_default

TOOLS_BY_SKILL = {
    0: [],
    1: ["curl", "wget"],
    2: ["httpie"],
    3: ["nmap", "sqlmap"],
    4: ["hydra"],
    5: ["metasploit", "ghidra"]
}

BIAS_TOOL_WEIGHTS = {
    "anchoring": {"nmap": 2.0, "sqlmap": 2.0, "hydra": 0.5, "ghidra": 1.0},
    "confirmation": {"hydra": 2.0, "sqlmap": 2.0, "nmap": 0.5},
    "overconfidence": {"metasploit": 3.0, "ghidra": 2.0, "httpie": 0.5}
}

BIAS_EXPLOITS = {
    "anchoring": ["ftp_vsftpd"],
    "confirmation": ["apache_struts"],
    "overconfidence": ["samba_usermap", "apache_struts"]
}

FOLLOWUP_LOG_PATH = os.path.expanduser("~/.evilEVE/logs/followups.jsonl")

def log_followup_suggestions(attacker_name, suggestions):
    if not suggestions:
        return
    os.makedirs(os.path.dirname(FOLLOWUP_LOG_PATH), exist_ok=True)
    entry = {
        "attacker": attacker_name,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "suggestions": suggestions
    }
    with open(FOLLOWUP_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

def get_bias_activation_probs(deception_present: bool, informed: bool) -> dict:
    return {
        "anchoring": 0.85 if deception_present and not informed else 0.5,
        "confirmation": 0.75 if informed else 0.4,
        "overconfidence": 0.65 if informed and not deception_present else 0.3
    }

def weighted_random_choice(weight_dict):
    total = sum(weight_dict.values())
    r = random.uniform(0, total)
    upto = 0
    for k, w in weight_dict.items():
        if upto + w >= r:
            return k
        upto += w
    return random.choice(list(weight_dict.keys()))

def weighted_tool_choice(tools, bias):
    weights = []
    bias_weights = BIAS_TOOL_WEIGHTS.get(bias, {})
    for tool in tools:
        weights.append(bias_weights.get(tool, 1.0))
    total = sum(weights)
    r = random.uniform(0, total)
    upto = 0
    for tool, weight in zip(tools, weights):
        if upto + weight >= r:
            return tool
        upto += weight
    return random.choice(tools)


def simulate_phase(attacker, phase, target_ip, queued_tool=None, dry_run=False):
    print(f"\n Phase: {phase}")

    tools = [t for lvl in range(attacker["skill"] + 1) for t in TOOLS_BY_SKILL[lvl]]
    if not tools:
        print("[!] No tools available due to low skill level.")
        return

    deception_present = attacker.get("deception_present", False)
    informed = attacker.get("informed_of_deception", False)
    bias_probs = get_bias_activation_probs(deception_present, informed)
    selected_bias = weighted_random_choice(bias_probs)
    attacker["last_selected_bias"] = selected_bias
    print(f" Cognitive Bias Activated: {selected_bias}")

    queued = attacker.get("next_tools", [])
    if queued:
        print(f"[next_tool_queue] Prioritized tool from queue: {queued[0]}")
    tool = queued.pop(0) if queued else queued_tool or weighted_tool_choice(tools, selected_bias)
    attacker["next_tools"] = queued

    args = [target_ip] if tool in ["nmap", "curl", "wget", "httpie"] else []
    bias_tool_reason = f"Tool selected using bias '{selected_bias}' weighted preference"
    print(f" Using tool: {tool} on {target_ip} → Reason: {bias_tool_reason}")

    active_tools = []
    start = time.time()
    result = {}

    if dry_run:
        print(f"[dry-run] Would execute: {tool} {args}")
        result.update({
            "tool": tool, "args": args, "elapsed": 0.0, "dry_run": True,
            "bias": selected_bias, "tool_reason": bias_tool_reason,
            "success": False,  # mark explicitly
            "exit_code": None,
            "stdout_snippet": "", "stderr_snippet": "",
            "deception_triggered": False, "monitored_status": "dry-run"
        })
        return result

    try:
        if tool == "curl":
            plugin_result = run_curl_check(target_ip)
            result.update(plugin_result)
            if "apache" in plugin_result.get("stdout", "").lower():
                attacker.setdefault("next_tools", []).append("sqlmap")
                result["log_warning"] = "Found HTTP server, enqueued sqlmap"

        elif tool == "wget":
            plugin_result = run_wget_probe(target_ip)
            result.update(plugin_result)
            if "apache" in plugin_result.get("stdout", "").lower():
                attacker.setdefault("next_tools", []).append("sqlmap")
                result["log_warning"] = "Found HTTP server, enqueued sqlmap"

        elif tool == "httpie":
            plugin_result = run_httpie_probe(target_ip)
            result.update(plugin_result)
            if "apache" in plugin_result.get("stdout", "").lower():
                attacker.setdefault("next_tools", []).append("sqlmap")
                result["log_warning"] = "Found HTTP server, enqueued sqlmap"

        elif tool == "sqlmap":
            sqlmap_url = get_default("sqlmap_url").format(ip=target_ip)
            plugin_result = run_sqlmap_attack(sqlmap_url)
            time.sleep(5)
            parsed = parse_sqlmap_log(plugin_result["log"])
            result.update({
                "tool": tool, "args": [target_ip], "pid": None, "launched": plugin_result["launched"],
                "elapsed": 0.0, "stdout_snippet": "", "stderr_snippet": "",
                "deception_triggered": False, "monitored_status": "plugin", "exit_code": None,
                "bias": selected_bias, "tool_reason": bias_tool_reason,
                "log_warning": plugin_result.get("error"),
                "sqlmap_vulnerable": parsed.get("vulnerable", False),
                "plugin_errors": parsed.get("errors", []),
                "plugin_warnings": parsed.get("warnings", [])
            })



        elif tool == "metasploit":
            from plugins.metasploit_plugin import EXPLOIT_LIBRARY

    # Full list of known exploits by bias
    bias_exploits = {
        "anchoring": ["ftp_vsftpd", "ms08_067", "cve_2017_0144_eternalblue"],
        "confirmation": ["apache_struts", "samba_usermap", "cve_2017_5638"],
        "overconfidence": ["cve_2021_41773", "cve_2018_10933", "cve_2019_0708_rdp_bluekeep"]
    }

    available_exploits = bias_exploits.get(selected_bias, ["ftp_vsftpd"])
    exploit_name = random.choice(available_exploits)

    plugin_result = run_msf_attack(target_ip=target_ip, exploit_name=exploit_name)
    time.sleep(3)
    outcome = parse_msf_log(plugin_result["log"])

    result.update({
        "tool": tool,
        "args": [target_ip],
        "pid": None,
        "launched": plugin_result.get("launched", False),
        "elapsed": 0.0,
        "stdout_snippet": "",
        "stderr_snippet": "",
        "deception_triggered": False,
        "monitored_status": "plugin",
        "exit_code": None,
        "bias": selected_bias,
        "tool_reason": bias_tool_reason,
        "exploit_used": exploit_name,
        "log_warning": f"Metasploit launched (rc: {plugin_result['script']})",
        "exploit_success": outcome["session_opened"],
        "plugin_errors": outcome["errors"]
    })


        

        elif tool == "ghidra":
            ghidra_path = get_path("ghidra_home")
            binary_path = os.path.join(get_path("binaries"), "malware.exe")
            project_path = f"/home/student/ghidra-projects/{attacker['name']}"
            log_path = f"/home/student/logs/ghidra_{attacker['name']}.log"
            plugin = GhidraHeadlessPlugin(
                ghidra_path=ghidra_path,
                binary_path=binary_path,
                project_path=project_path,
                log_path=log_path
            )
            plugin.run()
            result.update({
                "tool": tool, "args": [binary_path], "pid": None, "launched": False,
                "elapsed": 0.0, "stdout_snippet": "", "stderr_snippet": "",
                "deception_triggered": False, "monitored_status": "plugin", "exit_code": None,
                "bias": selected_bias, "tool_reason": bias_tool_reason,
                "log_warning": f"Ghidra launched in background (project: {project_path})"
            })

        elif tool == "hydra":
            plugin_result = run_hydra_attack(target_ip, service="ssh")
            result.update({
                "tool": tool, "args": [target_ip], "pid": None, "launched": False,
                "elapsed": 0.0, "stdout_snippet": "", "stderr_snippet": "",
                "deception_triggered": False, "monitored_status": "plugin", "exit_code": None,
                "bias": selected_bias, "tool_reason": bias_tool_reason,
                "log_warning": f"Hydra launched against {target_ip} (log: {plugin_result['log']})"
            })

        elif tool == "nmap":
            plugin_result = run_nmap_scan(target_ip, log_dir=f"logs/nmap/{attacker['name']}")
            parsed = interpret_nmap_json(plugin_result["output"])
            result.update({
                "tool": tool, "args": [target_ip], "pid": None, "launched": False,
                "elapsed": 0.0, "stdout_snippet": "", "stderr_snippet": "",
                "deception_triggered": parsed.get("deception_flags") is not None,
                "monitored_status": "plugin", "exit_code": None,
                "bias": selected_bias, "tool_reason": bias_tool_reason,
                "log_warning": f"Nmap scan completed. Output parsed.",
                "open_ports": parsed.get("open_ports", []),
                "nmap_followups": parsed.get("suggestions", []),
                "nmap_deception_signals": parsed.get("deception_flags", [])
            })
            if result["nmap_followups"]:
                attacker.setdefault("next_tools", []).extend([
                    t for t in result["nmap_followups"] if any(k in t.lower() for k in ["hydra", "sqlmap", "eternalblue"])
                ])
                log_followup_suggestions(attacker["name"], result["nmap_followups"])
            if result["nmap_deception_signals"]:
                attacker["deception_present"] = True

        else:
            result = execute_tool(tool, args)
            result.update({
                "phase": phase, "tool": tool, "args": args,
                "bias": selected_bias, "tool_reason": bias_tool_reason
            })

            if result.get("launched"):
                result["start_time"] = start
                active_tools.append(result)

            try:
                stdout = result.get("stdout", "").lower()
                stderr = result.get("stderr", "").lower()
                result["stdout_snippet"] = stdout[:1000]
                result["stderr_snippet"] = stderr[:1000]
                result["deception_triggered"] = any(
                    kw in stdout or kw in stderr for kw in ["decoy", "honeypot", "fake", "bait", "trap"]
                )
            except Exception as e:
                result["deception_triggered"] = False
                result["stdout_snippet"] = ""
                result["stderr_snippet"] = ""
                result["log_warning"] = f"Error parsing output: {str(e)}"

            if result.get("deception_triggered"):
                print(" [!] Deception suspected from output.")

            monitored = monitor_active_tools(active_tools, timeout=60)
            for m in monitored:
                if m["pid"] == result.get("pid"):
                    result["monitored_status"] = m["status"]
                    result["exit_code"] = m["exit_code"]

    except Exception as e:
        result.update({
            "tool": tool, "args": args, "pid": None, "launched": False,
            "elapsed": 0.0, "stdout_snippet": "", "stderr_snippet": "",
            "deception_triggered": False, "monitored_status": "failed", "exit_code": None,
            "bias": selected_bias, "tool_reason": bias_tool_reason,
            "log_warning": f"[mitre_engine] Tool {tool} failed: {e}",
            "plugin_errors": [str(e)]
        })

    # Safety: ensure required keys always exist before logging
    result.setdefault("success", False)
    result.setdefault("exit_code", None)
    result.setdefault("stdout_snippet", "")
    result.setdefault("stderr_snippet", "")
    result.setdefault("deception_triggered", False)
    result.setdefault("monitored_status", "unknown")

    # Log tool used (real or dry-run) for profile history
    if "tool" in result:
        attacker.setdefault("tools_used", []).append(result["tool"])

    # Update attacker state and logs
    update_profile_feedback(attacker, result, tool)
    update_memory_graph(attacker, phase, tool, result["success"])
    log_attack(attacker, tool, target_ip, phase, result)

    result["elapsed"] = round(time.time() - start, 2)
    return result





