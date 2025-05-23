* **Dockerized honeypots** (Cowrie, Dionaea)
* **Cognitive bias exploitation** (anchoring, confirmation, overconfidence)
* **ELK Stack integration** (Elasticsearch, Logstash, Kibana)
* **Dynamic response scripting** (`dynamic_response.py`, `cognitive_deployer.py`)
* **Prometheus metrics**
* **Proxmox VM snapshots and Swarm node management**
* **Security deception and attacker engagement (EvilEVE)**

# General Project Information

## Group Members

* Alex Bockheim - [bockhea@wwu.edu](mailto:bockhea@wwu.edu)
* Fatima Preciado - [preciaf@wwu.edu](mailto:preciaf@wwu.edu)
* Lauren Hall - [halll24@wwu.edu](mailto:halll24@wwu.edu)
* Tristan Davis - [davist32@wwu.edu](mailto:davist32@wwu.edu)

## Resources In Use

* T-Pot Honeypot Framework
* Cowrie & Dionaea honeypots
* Docker Swarm for orchestration
* ELK Stack (Elasticsearch, Logstash, Kibana)
* Prometheus for monitoring
* EvilEVE Attacker Simulation Toolkit
* GitLab CI/CD
* Proxmox virtualization environment

## Project Outcome

We developed a dynamic deceptive cybersecurity system that adapts honeypot deployments based on attacker behavior, logging their interactions and inferring cognitive biases to optimize future deception strategies.

# Project Background & Motivations

## Previous Projects

This project expands on standard honeypot systems by adding adaptive behavior, attacker profiling, and deception-aware logging, building on concepts from prior security operations and threat analysis labs.

## Project Focus

* **Motivating factors**: Traditional honeypots are often too easily detected and dismissed by attackers. We sought to make deception more convincing and adaptive.
* **Goals of the project**: Detect attacker behavior patterns, exploit cognitive biases to retain attacker engagement, and automate honeypot response mechanisms.

## Vision Statement

To create an intelligent deception platform that not only logs attacker behavior but subtly manipulates it—gathering intelligence while wasting attacker time and resources.

# Deliverables & Outcome

## Technology Utilized

* **Cowrie** for SSH/Telnet interaction traps
* **Dionaea** for emulating vulnerable services (FTP, HTTP, etc.)
* **Docker & Swarm** for scalable deployment
* **ELK Stack** for log aggregation and visualization
* **Prometheus** for performance metrics
* **Python** for dynamic response scripting
* **FastAPI** for management endpoints

## Major Features

* Real-time log analysis and attacker categorization
* Automated honeypot orchestration based on cognitive bias inference
* Elasticsearch integration for searchable attacker logs
* Kibana dashboards for behavior analysis
* Support for attacker simulation via EvilEVE

## Project Architecture

* **Frontend**: Kibana dashboards
* **Backend**: Filebeat → Logstash → Elasticsearch → Kibana
* **Orchestration**: Docker Swarm managing honeypots across nodes
* **Logic**: Python scripts (`dynamic_response.py`, `cognitive_deployer.py`) parsing honeypot logs and scaling containers based on attacker profiles

## Project Achievements

* Successfully deployed a deception system that detects anchoring, confirmation, and overconfidence biases
* Demonstrated attacker misdirection through cognitive manipulation
* Built a resilient, multi-node infrastructure supporting adaptive honeypot behavior
* Validated logging and alerting through ELK

## Areas for Future Work

* Deeper integration with machine learning for attacker profiling
* Activly monitor attackers and change the honeypot based on their decsions
* Expand deception types (e.g., honeytokens, fake credentials)
* Deploy on cloud infrastructure for scalability testing
* Enhance UI with real-time visual overlays of attacker paths
* Develop custom simulations beyond EvilEVE for varied attacker personas
