#!/usr/bin/env python3
"""
Dynamic honeypot orchestrator
- Tails JSON logs under /data/<honeypot>/logs/*.json
- Detects attacker activity & cognitive‑bias category
- Scales Swarm services up/down accordingly
- Emits Prometheus metrics and logs to Elasticsearch (with disk queue)
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List
import socket
import docker
import requests
from prometheus_client import Counter, Gauge, Histogram, start_http_server
import logging

# ── Config paths & constants ────────────────────────────────────────────
BASE_DIR = Path("/home/student/dcd-unified")
STATE_FILE = BASE_DIR / "state/attacker_state.json"
ELK_QUEUE_FILE = BASE_DIR / "state/elk_retry_queue.json"
FETCH_WINDOW_SEC = 60   # how far back we read new log lines
COOLDOWN_SEC = 350      # seconds before we shrink replicas

# ── Prometheus metrics ─────────────────────────────────────────────────-

logger = logging.getLogger("dynamic_response")

def find_free_port(start_port=8001, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("0.0.0.0", port))
                return port  # port is available
            except OSError:
                logging.warning(f"Port {port} in use, trying {port + 1}")
    raise RuntimeError("No available port found for Prometheus server")

port = find_free_port(8001)

start_http_server(port)  # expose :8001/metrics when run as main
logger.info(f"Prometheus server started on port {port}")

RESPONSES_EXECUTED = Counter("responses_executed_total", "Dynamic responses executed")
RESPONSES_SUCCESSFUL = Counter("responses_successful_total", "Successful responses")
RESPONSE_LATENCY = Histogram("response_latency_seconds", "Response latency")
ACTIVE_HONEYPOTS = Gauge("active_honeypots", "Number of honeypots currently scaled up")
LAST_SCALE_TIME = Gauge("last_scale_timestamp", "Unix ts of last scale‑event", ["service"])

# ── Logging ─────────────────────────────────────────────────────────────
logger = logging.getLogger("dynamic_response")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── Honeypot metadata ─────────────────────────────────────────────────--
@dataclass(frozen=True)
class Honeypot:
    name: str       # directory under /data
    service: str    # Swarm service name
    bias: str       # cognitive bias bucket

HONEYPOTS: List[Honeypot] = [
    Honeypot("cowrie",     "cowrie_cowrie",    "anchoring"),
    Honeypot("dionaea",    "dionaea_dionaea",  "confirmation"),
    Honeypot("elasticpot", "elasticpot_honeypot_elasticpot_triggered", "overconfidence"),
    Honeypot("heralding",  "heralding_honeypot_heralding_triggered",   "overconfidence"),
    # Honeypot("tanner",     "tanner_honeypot_tanner_triggered",         "anchoring"),
]

# ── Main orchestrator class ─────────────────────────────────────────────
class DynamicResponseManager:
    def __init__(self, es_host: str = "localhost", es_port: int = 9200):
        self.docker = docker.from_env()
        self.es_url = f"http://{es_host}:{es_port}/dynamic-responses/_doc"
        self.state = self._load_state()
        self.last_scaled: Dict[str, datetime] = {}
        logger.info("DynamicResponseManager initialised")

    # ── State persistence ────────────────────────────────────────────
    def _load_state(self) -> Dict[str, Any]:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
        return {}

    def _save_state(self) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(self.state, indent=2))

    # ── Event ingestion ─────────────────────────────────────────────--
    def _honeypot_log_paths(self, hp: Honeypot) -> List[Path]:
        """Return all *.json log files for a honeypot."""
        log_dir = BASE_DIR / "data" / hp.name / "logs"
        return list(log_dir.glob("*.json"))

    def _iter_recent_lines(self, path: Path, cutoff: datetime):
        """Yield JSON record dictionaries newer than cutoff."""
        try:
            with path.open() as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                        ts_raw = rec.get("timestamp") or rec.get("time")
                        ts = isoparse(ts_raw)
                        if ts >= cutoff:
                            yield rec, ts
                    except Exception:
                        continue
        except FileNotFoundError:
            pass

    def fetch_recent_events(self) -> List[Dict[str, Any]]:
        cutoff = datetime.utcnow() - timedelta(seconds=FETCH_WINDOW_SEC)
        events: List[Dict[str, Any]] = []
        for hp in HONEYPOTS:
            for path in self._honeypot_log_paths(hp):
                for rec, ts in self._iter_recent_lines(path, cutoff):
                    txt = json.dumps(rec)
                    if any(k in txt for k in ("login attempt", "ftp", "exploit")):
                        ip = rec.get("src_ip") or rec.get("remote_host") or "0.0.0.0"
                        events.append({"ip": ip, "bias": hp.bias, "when": ts})
        return events

    def active_attackers(self) -> Dict[str, List[datetime]]:
        mapping: Dict[str, List[datetime]] = {}
        for evt in self.fetch_recent_events():
            mapping.setdefault(evt["ip"], []).append(evt["when"])
        return mapping

    # ── Scaling logic ─────────────────────────────────────────────---
    def trigger_honeypot(self, bias: str, attacker_ip: str) -> None:
        MAX_REPLICA = 2

        cands = [h for h in HONEYPOTS if h.bias == bias]
        if not cands:
            return
        hp = random.choice(cands)
        try:
            svc = self.docker.services.get(hp.service)
            svc.reload()
        except docker.errors.NotFound:
            logger.error("Service %s not found", hp.service)
            return
        logger.info("🔥 TRIGGER CALLED FOR: %s", hp.service)
        curr = svc.attrs["Spec"]["Mode"]["Replicated"]["Replicas"]
        if curr >= MAX_REPLICA:
            logger.info("Skipping, at max replica")
            return
        svc.scale(curr + 1)
        now = datetime.utcnow()
        self.last_scaled[hp.service] = now
        LAST_SCALE_TIME.labels(service=hp.service).set(now.timestamp())
        ACTIVE_HONEYPOTS.set(len(self.last_scaled))
        logger.info("Scaled UP %s %d → %d", hp.service, curr, curr + 1)

    def _should_scale_down(self, svc_name: str) -> bool:
        last = self.last_scaled.get(svc_name)
        if not last:
            return False
        if (datetime.utcnow() - last).total_seconds() < COOLDOWN_SEC:
            return False
        return len(self.active_attackers()) == 0

   # def scale_down_honeypots(self):
   #     for svc in list(self.last_scaled.keys()):
   #         if self._should_scale_down(svc):
   #             service = self.docker.services.get(svc)
   #             curr = service.attrs["Spec"]["Mode"]["Replicated"]["Replicas"]
   #             if curr > 1:
   #                 service.scale(curr - 1)
   #                 logger.info("Scaled DOWN %s %d → %d", svc, curr, curr - 1)
   #             del self.last_scaled[svc]
   #     ACTIVE_HONEYPOTS.set(len(self.last_scaled))


    def scale_down_honeypots(self):
        for svc in list(self.last_scaled.keys()):
            if not self._should_scale_down(svc):
                continue

            try:
                service = self.docker.services.get(svc)
                curr = service.attrs["Spec"]["Mode"]["Replicated"]["Replicas"]

                if curr <= 1:
                    logger.info("⚠️ Skipping scale-down for %s — already at minimum replicas (%d)", svc, curr)
                    continue

                logger.info("Scaling down %s from %d → %d", svc, curr, curr - 1)
                service.scale(curr - 1)
                del self.last_scaled[svc]

            except Exception as e:
                logger.exception("🔥 Failed to scale down service %s: %s", svc, e)

        ACTIVE_HONEYPOTS.set(len(self.last_scaled))



    # ── Elasticsearch logging ─────────────────────────────────------
    def log_to_elasticsearch(self, ip: str, bias: str, rtype: str):
        doc = {
            "@timestamp": datetime.utcnow().isoformat(),
            "attacker_ip": ip,
            "response.bias": bias,
            "response.type": rtype,
        }
        try:
            requests.post(self.es_url, json=doc, timeout=3).raise_for_status()
        except Exception:
            ELK_QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
            ELK_QUEUE_FILE.open("a").write(json.dumps(doc) + "\n")
            logger.warning("Buffered ES doc (queue length now %d)", sum(1 for _ in ELK_QUEUE_FILE.open()))

    def replay_elk_queue(self):
        if not ELK_QUEUE_FILE.exists():
            return
        lines = ELK_QUEUE_FILE.read_text().splitlines()
        kept = []
        for ln in lines:
            doc = json.loads(ln)
            try:
                requests.post(self.es_url, json=doc, timeout=3).raise_for_status()
            except Exception:
                kept.append(ln)
        ELK_QUEUE_FILE.write_text("\n".join(kept))

    def _codename(self, ip, bias):
        h = sum(ord(c) for c in ip) % 10000
        fam = {"anchoring": "Storm",
               "confirmation": "Tempest",
               "overconfidence": "Typhoon"
               }.get(bias, "Storm")

        return f"{fam}-{h:04d}"
    
    def _update_profile(self, ip, bias, rtype):
        MAX_HISTORY = 100  # Limit history length
        
        p = self.state.get(ip, {
            "session_count": 0,
            "bias_history": [],
            "response_history": [],
            "frustration": 0.0,
            "confidence": 0.0 })

        p.setdefault("profile_name", self._codename(ip, bias))
        p["session_count"] += 1
        p["bias_history"].append(bias)
        p["response_history"].append(rtype)

        p["bias_history"] = p["bias_history"][-MAX_HISTORY:]
        p["response_history"] = p["response_history"][-MAX_HISTORY:]

        if rtype in ("fake_error", "challenge"):
            p["frustration"] += 0.1
        
        if rtype == "fake_success":
            p["confidence"] += 0.2

        p["last_seen"] = datetime.utcnow().isoformat()
        self.state[ip] = p
        self._save_state()

    # ── Deception responses ─────────────────────────────────────────
    _templates: Dict[str, List[Dict[str, Any]]] = {
        "anchoring": [
            {"type": "misleading_info", "message": "System vulnerable to CVE‑2021‑41773"},
            {"type": "fake_error", "error": "Access Denied", "hint": "Try admin:admin"},
        ],
        "confirmation": [
            {"type": "decoy_file", "filename": "credentials.txt", "content": "admin:password123"},
            {"type": "delayed_response", "delay": 5},
        ],
        "overconfidence": [
            {"type": "fake_success", "message": "Access granted to /root", "content": "Sensitive data found."},
            {"type": "challenge", "hint": "Bypass required for internal auth"},
        ],
    }

    def apply_response(self, bias: str, attacker_ip: str) -> bool:
        resp = random.choice(self._templates.get(bias, []))
        rtype = resp["type"]
        logger.info("Applying %s for %s", rtype, bias)
        
        try:
            if rtype == "decoy_file":
                bait_dir = BASE_DIR / "data" / bias / "bait"
                bait_dir.mkdir(parents=True, exist_ok=True)
                (bait_dir / resp["filename"]).write_text(resp["content"])
            elif rtype == "delayed_response":
                time.sleep(resp["delay"])
            elif rtype == "misleading_info":
                logger.info("[Deception] %s", resp["message"])
            elif rtype == "fake_error":
                logger.info("[Fake Error] %s — %s", resp["error"], resp["hint"])
            elif rtype == "fake_success":
                logger.info("[Fake Success] %s → %s", resp["message"], resp["content"])
            elif rtype == "challenge":
                logger.info("[Challenge] %s", resp["hint"])
            
            self._update_profile(attacker_ip, bias, rtype)
            self.log_to_elasticsearch(attacker_ip, bias, rtype)
            RESPONSES_EXECUTED.inc()
            RESPONSES_SUCCESSFUL.inc()
            return True
        except Exception as exc:
            logger.exception("Error applying response: %s", exc)
            return False

# ── Run loop (stand‑alone mode) ─────────────────────────────────────
if __name__ == "__main__":
    mgr = DynamicResponseManager()
    while True:
        for evt in mgr.fetch_recent_events():
            mgr.trigger_honeypot(evt["bias"], evt["ip"])
        mgr.scale_down_honeypots()
        mgr.replay_elk_queue()
        time.sleep(FETCH_WINDOW_SEC)
