# plugins/nmap_plugin.py

import subprocess
import time
import os
import json
from pathlib import Path


def run_nmap_scan(target_ip, out_dir="logs/nmap", scan_level="normal"):
    """
    Executes an Nmap scan and parses structured output.
    :param target_ip: IP address of the target
    :param out_dir: Output directory for logs
    :param scan_level: 'normal' or 'aggressive'
    :return: Dictionary with summary and parsed data
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    xml_out = f"{out_dir}/nmap_{target_ip}_{timestamp}.xml"
    txt_out = f"{out_dir}/nmap_{target_ip}_{timestamp}.txt"

    flags = ["nmap", "-sV", "-T4", "-Pn", "-oX", xml_out, target_ip]
    if scan_level == "aggressive":
        flags.insert(1, "-A")

    with open(txt_out, "w") as f:
        subprocess.run(flags, stdout=f, stderr=subprocess.STDOUT)

    parsed = parse_nmap_xml(xml_out)

    deception_detected = any(
        "honeypot" in s.get("product", "").lower() or
        "fake" in s.get("product", "").lower()
        for s in parsed.get("services", [])
    )

    low_port_count = sum(1 for s in parsed.get("services", []) if s.get("port", 0) < 1024)
    overconfident = low_port_count < 2

    return {
        "log": txt_out,
        "xml": xml_out,
        "services": parsed.get("services", []),
        "deception_detected": deception_detected,
        "overconfident": overconfident,
        "timestamp": timestamp
    }


def parse_nmap_xml(xml_path):
    """Parses Nmap XML output to extract port/service info."""
    import xml.etree.ElementTree as ET

    services = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall("host"):
            for port in host.findall("ports/port"):
                port_id = int(port.get("portid", 0))
                proto = port.get("protocol", "?")
                state = port.findtext("state/@state") or port.find("state").get("state", "unknown")
                service_el = port.find("service")
                product = service_el.get("product", "") if service_el is not None else ""

                services.append({
                    "port": port_id,
                    "protocol": proto,
                    "state": state,
                    "product": product
                })
    except Exception as e:
        services.append({"error": str(e)})

    return {"services": services}
