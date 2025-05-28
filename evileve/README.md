# EvilEVE: Cognitively-Modeled Adversary Simulation Framework

_EvilEVE_ (Evolving Intrusion Logic via Empirical Vulnerability Exploitation) is a research-grade attacker simulation framework designed to evaluate the effectiveness of deception-based cybersecurity defenses—specifically, honeypots exploiting **cognitive biases**.

This simulator mimics human-like attacker behavior based on psychological profiles, decision modeling, and the MITRE ATT&CK framework. It enables reproducible, high-fidelity experiments comparing static and adaptive deception environments.

---

## Purpose

To evaluate the hypothesis:

> “Do adaptive honeypots leveraging cognitive bias exploitation result in greater attacker engagement, confusion, and behavioral observability than traditional static honeypots?”

---

## Key Concepts & Decision Variables

| Variable               | Source                             | Impact                                                                 |
|------------------------|-------------------------------------|------------------------------------------------------------------------|
| **Deception Present**  | Experimental condition              | Increases attacker confusion and time waste                           |
| **Informed or Not**    | Experimental manipulation           | Affects attacker suspicion and confidence                             |
| **Confidence**         | CTQ (Cyber Task Questionnaire)      | Predicts decisiveness or hesitancy                                    |
| **Confusion/Frustration** | CTQ + logs + physiology         | Signals cognitive overload, changes strategy                          |
| **Belief in Deception**| Self-report / prompt-driven         | Drives strategic deviation                                             |
| **Touch/Probe/Scan**   | Decoy interaction logs              | Inferred attacker intent & engagement with deception                  |

---

## Experimental Architecture

### Honeypot Environments

1. **Baseline (Static)**
   - Fixed honeypots: Cowrie, Dionaea, Elasticpot
   - No deception adaptation

2. **Adaptive (Bias-Aware)**
   - Dynamic honeypot triggers based on attacker state
   - Responds to anchoring, overconfidence, and confirmation biases

### Attacker Simulator

- Isolated VM (no outbound access)
- Profiles attacker psychology and skill
- Operates across MITRE ATT&CK phases
- Decisions adapt in real time based on output and deception

---

## Tularosa Study Reference

EvilEVE's psychological modeling is inspired by the Tularosa Study:

- **Red teamers in a controlled environment** were observed interacting with deceptive infrastructure
- Key metrics (confidence, self-doubt, confusion, frustration, surprise, suspicion) were extracted
- **Correlational effects** were derived (e.g., frustration ↔ confusion; self-doubt ↓ confidence)

> [Reference: Boggs, J., et al. “The Tularosa Study: An Experimental Design and Implementation for Cyber Deception Effectiveness.” Sandia National Labs, 2018.](https://www.osti.gov/biblio/1483484)

Mathematical relationships encoded into EvilEVE include:

- Confusion = baseline + 0.3 * (frustration - 2.5)
- Surprise = baseline + 0.3 * (frustration - 2.5)
- Confidence = baseline - 0.3 * (self_doubt - 2.5)
- Suspicion = weighted sum of frustration, confusion, self-doubt, and inverted confidence

These formulas are defined in `psychology.py` and recalculated after each attack phase.

---

## Getting Started

### Requirements

- Python 3.8+
- Ubuntu 20.04+ (recommended)
- Access to an internal honeypot or cyber range
- Tools: `nmap`, `hydra`, `metasploit`, `ghidra`, `sqlmap`

### Installation

```bash
# Create and activate a virtual environment
python3 -m venv env
source env/bin/activate

# (Optional) Install dependencies if listed
pip install -r requirements.txt
```

---

## Simulation Overview

### Attacker Initialization

Each attacker receives a randomized but reproducible profile:

- **Traits**: Confidence, Frustration, Self-Doubt, Suspicion
- **Skill Level**: Determines tool access

| Skill | Available Tools                          |
|-------|------------------------------------------|
| 0     | None                                     |
| 1     | `curl`, `wget`                           |
| 2     | Adds `httpie`                            |
| 3     | Adds `nmap`, `sqlmap`                    |
| 4     | Adds `hydra`                             |
| 5     | Adds `metasploit`, `ghidra`, etc.        |

### MITRE ATT&CK Phases Simulated

1. Reconnaissance  
2. Initial Access  
3. Execution  
4. Persistence  
5. Privilege Escalation  
6. Lateral Movement  
7. Collection  
8. Exfiltration  
9. Impact

### Execution Modes

- `--dry-run`: Logic only (no actual tool execution)
- `--real`: Executes CLI tools for realism
- `--bias`: Future support for forcing a specific cognitive bias

---

## Running EvilEVE

```bash
python3 simulation.py --name Eve --ip 192.168.X.X --phases 5 --seed 42
```

---

## Plugin Architecture

Tool behavior is modular and lives in the `plugins/` directory:

| Plugin                  | Purpose                                       |
|------------------------|-----------------------------------------------|
| `metasploit_plugin.py` | Executes exploits via `.rc` scripting         |
| `ghidra_plugin.py`     | Headless binary analysis                      |
| `hydra_plugin.py`      | Brute-force SSH/FTP credentials               |
| `nmap_plugin.py`       | Runs and logs structured deception-aware scans|
| `nmap_interpreter.py`  | Parses Nmap output for deception signals      |

---

## Metrics Collected

| Category             | Examples                                                              |
|----------------------|-----------------------------------------------------------------------|
| Deception Impact     | Time in honeypots, tool failures, triggered decoys                   |
| Cognitive Influence  | Trait drift, hesitation, behavioral deviation                        |
| Behavioral Drift     | Tool switching, fallbacks, failed exploit escalation                 |
| Engagement Result    | Exploit, Confusion, or Withdrawal classification                     |

---

## Output Artifacts

| Path                                | Description                                      |
|-------------------------------------|--------------------------------------------------|
| `logs/phase_runs/*.jsonl`           | Phase-by-phase attacker logs                     |
| `logs/cognitive_states/*.json`      | Final psychological profile snapshot             |
| `logs/tool_runs/*.jsonl`            | Raw execution logs with runtime, PID, etc.       |
| `~/.evilEVE/logs/attack_log.csv`    | Flattened CSV summary across all sessions        |
| `logs/followups.jsonl`              | Tool follow-up recommendations from Nmap output  |

---

## Contributing

Contributions welcome!

1. Fork this repo
2. Create a feature branch
3. Make your changes
4. Submit a pull request

Open an issue first for any new plugin/tool proposal to coordinate development.

---

## Ethics Notice

EvilEVE is for academic use only. Do **not** deploy against real-world targets. All experiments must be confined to private, ethical cyber range environments.

---

## License

MIT License © [CheshireMinded](https://github.com/CheshireMinded)

