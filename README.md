# Deceptive Cyber Defense (Senior Project)

A dynamic deception-based cybersecurity platform that deploys Dockerized honeypots across a multi-node architecture. This system infers attacker behavior and cognitive bias, then adapts honeypot deployment accordingly using automated orchestration and threat monitoring tools.

---

## Key Features

* **Dockerized honeypots** (Cowrie, Dionaea)
* **Cognitive bias exploitation** (anchoring, confirmation, overconfidence)
* **ELK Stack integration** (Elasticsearch, Logstash, Kibana)
* **Dynamic response scripting** (`dynamic_response.py`, `cognitive_deployer.py`)
* **Prometheus metrics**
* **Proxmox VM snapshots and Docker Swarm management**
* **Security deception and attacker simulation via EvilEVE**

---

## Group Members

* Alex Bockheim – [bockhea@wwu.edu](mailto:bockhea@wwu.edu)
* Fatima Preciado – [preciaf@wwu.edu](mailto:preciaf@wwu.edu)
* Lauren Hall – [halll24@wwu.edu](mailto:halll24@wwu.edu)
* Tristan Davis – [davist32@wwu.edu](mailto:davist32@wwu.edu)

---

## Resources In Use

* T-Pot Honeypot Framework
* Cowrie & Dionaea honeypots
* Docker Swarm
* ELK Stack (Elasticsearch, Logstash, Kibana)
* Prometheus
* EvilEVE Attacker Simulation Toolkit
* GitLab CI/CD
* Proxmox Virtualization Environment

---

## Project Outcome

We developed a modular deception environment that:

* Deploys containerized honeypots across nodes
* Analyzes attacker behavior in real time
* Uses dynamic logic to infer and exploit cognitive biases
* Logs, visualizes, and simulates attacker interaction across nodes

---

## Project Structure

```
project-root/
├── controller/          # Swarm manager setup, ELK, Prometheus configs
├── cowrie-node/         # Cowrie honeypot service config
├── dionaea-node/        # Dionaea honeypot service config
├── evileve/             # Simulate attacks
├── README.md            # Project overview and deployment instructions
```

---

## Deployment Instructions

### 1. Create Docker Network (run once)

```bash
docker network create --driver overlay --attachable honeynet
```

---

### 2. Deploy ELK Stack

```bash
cd controller/
docker stack deploy -c elk-stack.yml elk
docker service ls
```

---

### 3. Deploy Honeypots

```bash
cd /sensor/

docker stack deploy -c cowrie-stack.yml cowrie
docker stack deploy -c dionaea-stack.yml dionea

docker service ls
```

---

### 4. Deploy Monitoring Stack

```bash
cd controller/
docker stack rm monitor
docker stack deploy -c docker-compose.monitor.yml monitor
docker service ls
```

---

### 5. Restart Dynamic Services

```bash
sudo systemctl restart cognitive-deployer.service
sudo systemctl restart dynamic-response.service
```

---

### 6. Check Service Health

```bash
systemctl status cognitive-deployer
systemctl status dynamic-response
```

---

## Simulate Attacks (EvilEVE)

Run from the simulation VM:

```bash
cd ~/evileve
python3 simulation.py --name testreal --ip 10.0.0.82 --phases 5
python3 analyze_phase_log.py
```

---

## Extra Items

* **Infrastructure Inventory List** is provided in `controller/infrastructure-inventory.md`, which includes:

  * Usernames and passwords
  * SSH keys
  * Access methods (SSH, RDP, HTTP)
  * IP addresses and service names

* **Deployment Diagram** is included as `controller/deployment-diagram.png`

* **This README** includes full documentation for running the project

---

## Project Architecture

* **Frontend**: Kibana Dashboards
* **Backend**: Filebeat → Logstash → Elasticsearch → Kibana
* **Orchestration**: Docker Swarm across multiple VMs
* **Dynamic Logic**: Python scripts infer attacker bias and scale honeypot services accordingly

---

## Project Focus

### Motivation

Traditional honeypots are often too simplistic and are quickly identified by attackers. This project aims to create more believable and adaptive honeypot environments by integrating psychological profiling and real-time orchestration.

### Goals

* Detect and interpret attacker behavior patterns
* Exploit cognitive biases such as anchoring and overconfidence
* Retain attacker engagement and waste adversary resources
* Provide searchable, centralized logs and real-time dashboards

---

## Project Achievements

* Successfully deployed and scaled honeypots across multiple VMs
* Detected attacker behavior patterns and inferred cognitive biases
* Demonstrated real-time deception and misdirection strategies
* Validated end-to-end log aggregation and monitoring via ELK

---

## Future Work

* Integrate machine learning models for attacker classification
* Add honeytokens and more complex fake services
* Deploy in cloud infrastructure for broader testing
* Build an attacker movement UI overlay in real time
* Expand EvilEVE simulation personas for greater realism

---

## License

This project was developed as a senior capstone project for the Computer Science Department at Western Washington University and is intended for academic and educational use.
