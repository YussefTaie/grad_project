"""
action_manager.py — Centralized IPS Action Manager
====================================================
Handles threat-specific responses:
  - MALWARE  → Block IP + Mark COMPROMISED
  - RANSOMWARE → Full isolation + CRITICAL INCIDENT
  - DDOS     → Block IP + rate-limit
  - BRUTEFORCE→ Block IP
  - GENERIC  → Progressive monitor/block

All actions respect:
  - Whitelist (localhost + gateway only)
  - Confidence threshold (> 0.8)
  - Progressive detection (≥ 3 hits to block)
"""

import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Literal

# Import core action primitives
from action import (
    execute_decision, block_ip, monitor_ip, unblock_ip,
    ip_in_whitelist, _states, IPState
)

log = logging.getLogger("ActionManager")

# ──────────────────────────────────────────────────────────────
# 🗂️ Host Status Registry
# ──────────────────────────────────────────────────────────────
@dataclass
class HostRecord:
    ip: str
    status: str = "CLEAN"          # CLEAN, MONITORED, COMPROMISED, ISOLATED, CRITICAL
    threat_type: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    incident_count: int = 0
    notes: list = field(default_factory=list)

_host_registry: dict[str, HostRecord] = {}
_registry_lock = threading.Lock()

def _get_or_create(ip: str) -> HostRecord:
    with _registry_lock:
        if ip not in _host_registry:
            _host_registry[ip] = HostRecord(ip=ip)
        _host_registry[ip].last_seen = time.time()
        return _host_registry[ip]

def get_all_incidents() -> list[dict]:
    """Returns all non-CLEAN host records for dashboard consumption."""
    with _registry_lock:
        return [
            {
                "ip": h.ip, "status": h.status, "threat": h.threat_type,
                "incidents": h.incident_count,
                "first_seen": h.first_seen, "last_seen": h.last_seen,
                "notes": h.notes[-5:],  # Last 5 notes
            }
            for h in _host_registry.values()
            if h.status != "CLEAN"
        ]

# ──────────────────────────────────────────────────────────────
# 🔴 Threat-Specific Response Handlers
# ──────────────────────────────────────────────────────────────

def _handle_malware(ip: str, reason: str, conf: float):
    """
    Malware Response:
    - Block source IP (firewall)
    - Mark host as COMPROMISED
    - Log detailed structured incident
    """
    host = _get_or_create(ip)
    host.threat_type = "MALWARE"
    host.incident_count += 1
    host.notes.append(f"[{_ts()}] Malware detected | conf={conf:.2f} | {reason}")

    log.critical(
        f"[MALWARE INCIDENT] ip={ip} | conf={conf:.2f} | "
        f"reason={reason} | incident_count={host.incident_count}"
    )

    # Execute block through progressive engine
    execute_decision(ip, "BLOCK", reason=f"MALWARE:{reason}", conf=conf)

    # Mark status after action engine processes it
    host.status = "COMPROMISED"
    log.warning(f"[HOST STATUS] {ip} marked as COMPROMISED")


def _handle_ransomware(ip: str, reason: str, conf: float, simulation: bool = False):
    """
    Ransomware Response (Critical):
    - Full isolation (block inbound + outbound simulation)
    - Mark as CRITICAL INCIDENT
    - Trigger lockdown log event
    """
    host = _get_or_create(ip)
    host.threat_type = "RANSOMWARE"
    host.incident_count += 1
    host.notes.append(f"[{_ts()}] RANSOMWARE detected | conf={conf:.2f} | {reason}")
    host.status = "CRITICAL"

    log.critical(
        f"[!!! CRITICAL INCIDENT !!!] RANSOMWARE from ip={ip} | "
        f"conf={conf:.2f} | reason={reason}"
    )
    print(f"\n{'!'*60}")
    print(f"  [CRITICAL] RANSOMWARE DETECTED — IP: {ip}")
    print(f"  Reason: {reason}")
    print(f"  Confidence: {conf:.2f}")
    print(f"  Action: FULL ISOLATION")
    print(f"{'!'*60}\n")

    # Force-block regardless of progressive counter
    # (Ransomware warrants immediate hard block — no 3-hit requirement)
    if ip not in _states:
        _states[ip] = IPState()
    _states[ip].hit_count = 99  # Bypass progressive counter
    _states[ip].first_hit_time = time.time()

    block_ip(ip, reason=f"RANSOMWARE ISOLATION:{reason}")
    host.status = "ISOLATED"

    if simulation:
        log.warning(f"[SIMULATION] System lockdown event triggered for {ip} (no real OS changes)")
        print(f"  >> [SIMULATION] Lockdown event logged for {ip}")


def _handle_ddos(ip: str, reason: str, conf: float):
    host = _get_or_create(ip)
    host.threat_type = "DDOS"
    host.incident_count += 1
    host.notes.append(f"[{_ts()}] DDoS detected | conf={conf:.2f}")

    log.warning(f"[DDOS ACTION] ip={ip} | conf={conf:.2f} | {reason}")
    execute_decision(ip, "BLOCK", reason=f"DDoS:{reason}", conf=conf)
    host.status = "COMPROMISED"


def _handle_bruteforce(ip: str, reason: str, conf: float):
    host = _get_or_create(ip)
    host.threat_type = "BRUTEFORCE"
    host.incident_count += 1
    host.notes.append(f"[{_ts()}] BruteForce detected | conf={conf:.2f}")

    log.warning(f"[BRUTEFORCE ACTION] ip={ip} | conf={conf:.2f} | {reason}")
    execute_decision(ip, "BLOCK", reason=f"BruteForce:{reason}", conf=conf)
    host.status = "COMPROMISED"


# ──────────────────────────────────────────────────────────────
# 🧠 Central Dispatch: execute_action()
# ──────────────────────────────────────────────────────────────

ThreatType = Literal["MALWARE", "RANSOMWARE", "DDOS", "BRUTEFORCE", "SUSPICIOUS", "GENERIC"]
Decision   = Literal["BLOCK", "MONITOR", "ISOLATE", "UNBLOCK"]

def execute_action(
    ip: str,
    threat_type: ThreatType,
    decision: Decision,
    reason: str = "",
    conf: float = 1.0,
    simulation: bool = False,
):
    """
    Central action dispatcher.
    Routes to the correct threat-specific handler.

    Args:
        ip:          Source IP address
        threat_type: Type of detected threat
        decision:    Desired action (BLOCK / MONITOR / ISOLATE / UNBLOCK)
        reason:      Human-readable reason string
        conf:        ML/rule confidence score (0.0 – 1.0)
        simulation:  If True, enables simulation-only events (no real OS changes)
    """
    if ip_in_whitelist(ip):
        log.debug(f"[ActionManager] Skipping whitelisted IP: {ip}")
        return

    if decision == "UNBLOCK":
        unblock_ip(ip)
        host = _get_or_create(ip)
        host.status = "CLEAN"
        host.notes.append(f"[{_ts()}] Unblocked")
        return

    if decision == "MONITOR":
        monitor_ip(ip, reason=reason)
        _get_or_create(ip).status = "MONITORED"
        return

    # For BLOCK / ISOLATE — route by threat type
    threat = threat_type.upper()

    if threat == "RANSOMWARE" or decision == "ISOLATE":
        _handle_ransomware(ip, reason, conf, simulation=simulation)

    elif threat == "MALWARE":
        _handle_malware(ip, reason, conf)

    elif threat == "DDOS":
        _handle_ddos(ip, reason, conf)

    elif threat == "BRUTEFORCE":
        _handle_bruteforce(ip, reason, conf)

    else:
        # Generic block through progressive engine
        execute_decision(ip, "BLOCK", reason=reason, conf=conf)


# ──────────────────────────────────────────────────────────────
# 🔧 Helpers
# ──────────────────────────────────────────────────────────────
def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")
