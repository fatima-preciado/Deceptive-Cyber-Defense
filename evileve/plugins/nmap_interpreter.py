# plugins/nmap_interpreter.py

import json

DECOY_KEYWORDS = ["honeypot", "decoy", "bait", "trap", "fake", "cowrie", "elasticpot"]

SUGGESTION_MAP = {
    "ftp": ["ftp_vsftpd", "hydra"],
    "ssh": ["hydra"],
    "mysql": ["hydra", "sqlmap"],
    "http": ["sqlmap", "apache_struts"],
    "https": ["sqlmap", "nuclei"],
    "smb": ["samba_usermap", "EternalBlue", "metasploit"],
    "rdp": ["hydra"],
    "telnet": ["hydra"]
}

def interpret_nmap_json(json_data):
    """
    Parses Nmap JSON output and returns extracted metadata and next-step suggestions.

    Args:
        json_data (str or dict): Raw Nmap JSON output as string or parsed dict

    Returns:
        dict: {
            "open_ports": [(port, service_name)],
            "suggestions": [tools],
            "deception_flags": [detected_strings]
        }
    """
    try:
        if isinstance(json_data, str):
            try:
                data = json.loads(json_data)
            except json.JSONDecodeError as e:
                return {"error": f"Invalid JSON: {e}", "open_ports": [], "suggestions": [], "deception_flags": []}
        elif isinstance(json_data, dict):
            data = json_data
        else:
            return {"error": "Unsupported input type", "open_ports": [], "suggestions": [], "deception_flags": []}

        open_ports = []
        suggestions = set()
        deception_flags = set()

        for host in data.get("host", []):
            for port_info in host.get("ports", []):
                port = port_info.get("portid")
                service = port_info.get("service", {}).get("name", "").lower()

                if port and service:
                    try:
                        port = int(port)
                        open_ports.append((port, service))
                    except ValueError:
                        continue

                    for keyword, tools in SUGGESTION_MAP.items():
                        if keyword in service:
                            suggestions.update(tools)

                    banner = port_info.get("service", {}).get("banner", "").lower()
                    if any(decoy in banner for decoy in DECOY_KEYWORDS):
                        deception_flags.update([kw for kw in DECOY_KEYWORDS if kw in banner])

        return {
            "open_ports": open_ports,
            "suggestions": list(suggestions),
            "deception_flags": list(deception_flags)
        }

    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}",
            "open_ports": [],
            "suggestions": [],
            "deception_flags": []
        }

