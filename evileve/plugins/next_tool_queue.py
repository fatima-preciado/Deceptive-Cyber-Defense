# plugins/next_tool_queue.py

from collections import Counter

# Maps service keywords or tool hints to recommended follow-up tools or exploit modules
# Expanded to include banner strings and service IDs observed in real attack paths
KEYWORD_TOOLS = {
    "ftp": ["hydra", "ftp_vsftpd"],
    "ssh": ["hydra"],
    "mysql": ["hydra", "sqlmap"],
    "http": ["httpie", "curl", "wget", "sqlmap", "apache_struts"],  # Added httpie/curl/wget for passive probing
    "https": ["httpie", "sqlmap", "nuclei"],  # Nuclei for SSL-enabled targets
    "smb": ["metasploit", "samba_usermap", "EternalBlue"],
    "telnet": ["hydra"],
    "rdp": ["hydra"],
    "apache": ["sqlmap", "httpie"],
    "nginx": ["sqlmap", "httpie"],
    "iis": ["sqlmap"],
    "wordpress": ["wpscan", "sqlmap"],
    "joomla": ["joomscan"],
    "php": ["sqlmap"],
    "dns": ["dig", "dnsrecon"],
    "smtp": ["hydra", "swaks"],
    "imap": ["hydra"],
    "pop3": ["hydra"],
    "ldap": ["ldapsearch", "metasploit"],
    "node.js": ["nuclei"],
    "jira": ["nuclei"],
    "cisco": ["nmap", "nuclei"],
    "honeypot": ["none"]  # can be used to suppress or simulate retreat
}

def extract_tools_from_services(open_ports: list) -> list:
    """
    Given a list of (port, service) tuples, return tools associated with those services.
    Now also handles inferred protocol/tool hints like curl/wget in headers.

    Args:
        open_ports (list): List of tuples like (port, service_name)

    Returns:
        list: Suggested tools based on service keywords
    """
    suggestions = []
    if not isinstance(open_ports, list):
        return suggestions

    try:
        for _, service in open_ports:
            if not isinstance(service, str):
                continue
            service = service.lower()
            for keyword, tools in KEYWORD_TOOLS.items():
                if keyword in service:
                    suggestions.extend(tools)
    except Exception as e:
        print(f"[next_tool_queue] Error extracting tools: {e}")

    return suggestions

def rank_tool_suggestions(tools: list) -> list:
    """
    Rank tool suggestions by frequency of appearance.

    Args:
        tools (list): List of tool names (possibly repeated)

    Returns:
        list: Ranked list of tool names (most common first)
    """
    if not isinstance(tools, list):
        return []

    try:
        counts = Counter(tools)
        ranked = sorted(counts.items(), key=lambda x: -x[1])
        return [t[0] for t in ranked]
    except Exception as e:
        print(f"[next_tool_queue] Error ranking tools: {e}")
        return []

def queue_next_tools(attacker: dict, open_ports: list) -> list:
    """
    Analyze open ports to infer next tools the attacker should try.
    Updates the attacker["next_tools"] list in-place.

    Args:
        attacker (dict): Current attacker profile dictionary
        open_ports (list): List of (port, service) tuples from Nmap plugin or string hints

    Returns:
        list: Ranked list of tools added to the attacker's next_tool queue
    """
    if not isinstance(attacker, dict):
        return []

    try:
        raw_suggestions = extract_tools_from_services(open_ports)
        ranked = rank_tool_suggestions(raw_suggestions)
        attacker.setdefault("next_tools", []).extend(ranked)
        attacker["next_tools"] = list(dict.fromkeys(attacker["next_tools"]))  # dedup, preserve order
        return ranked
    except Exception as e:
        print(f"[next_tool_queue] Error queuing next tools: {e}")
        return []

