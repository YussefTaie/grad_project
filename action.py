"""
action.py — IPS Action Engine (Detect → Confirm → Act)
======================================================
1. Progressive Detection (>=3 hits in 10s -> Block)
2. IP State Tracking (Hit count, Timestamps, Status)
3. BLOCK Implementation (OS-specific firewall rules)
4. Cooldown System (Prevent repeated blocks in 60s)
5. Auto Unblock with Exponential Backoff
6. Whitelist Protection (localhost + gateway ONLY, no blanket LAN)
"""

import os
import time
import socket
import logging
import platform
import subprocess
import ipaddress
import threading
from dataclasses import dataclass

log = logging.getLogger("ActionEngine")

# Cooldown & Unblock Durations
COOLDOWN_SEC = 60.0
AUTO_UNBLOCK_BASE = 120.0   # Exponential backoff base (seconds)

@dataclass
class IPState:
    hit_count: int = 0
    first_hit_time: float = 0.0
    last_hit_time: float = 0.0
    status: str = "NORMAL"       # NORMAL, MONITOR, BLOCKED
    unblock_timer: threading.Timer | None = None
    last_block_time: float = 0.0
    block_attempts: int = 0      # For exponential backoff

_states: dict[str, IPState] = {}

# ──────────────────────────────────────────────────────────────
# 🛡️ Whitelist Protection
# ──────────────────────────────────────────────────────────────
def _build_base_whitelist() -> set:
    wl = {
        "127.0.0.1", "::1", "0.0.0.0",
        "8.8.8.8", "8.8.4.4", "1.1.1.1",
    }
    try:
        wl.add(socket.gethostbyname(socket.gethostname()))
    except: pass
    
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=3
            )
            if result.stdout.strip(): wl.add(result.stdout.strip())
        else:
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
            if result.stdout and "via" in result.stdout.split():
                idx = result.stdout.split().index("via")
                wl.add(result.stdout.split()[idx+1])
    except: pass
    return wl

# ──────────────────────────────────────────────────────────────
# 🛡️ Whitelist Protection
# CRITICAL: Whitelist ONLY specific trusted IPs (not entire LAN)
# ──────────────────────────────────────────────────────────────

# Trusted IPs explicitly configured — add your own safe IPs here
_TRUSTED_EXPLICIT: set = {
    "127.0.0.1", "::1", "0.0.0.0",
    "8.8.8.8", "8.8.4.4",   # Google DNS
    "1.1.1.1",               # Cloudflare DNS
}

def _build_base_whitelist() -> set:
    wl = set(_TRUSTED_EXPLICIT)
    # Auto-detect local machine IP
    try:
        wl.add(socket.gethostbyname(socket.gethostname()))
    except: pass
    # Auto-detect default gateway (only it, not the whole subnet)
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=3
            )
            gw = result.stdout.strip()
            if gw:
                wl.add(gw)
                log.info(f"[Whitelist] Gateway detected: {gw}")
        else:
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
            if result.stdout and "via" in result.stdout.split():
                idx = result.stdout.split().index("via")
                wl.add(result.stdout.split()[idx+1])
    except: pass
    return wl

_WL_EXACT = _build_base_whitelist()

def ip_in_whitelist(ip: str) -> bool:
    """Check if an IP is explicitly trusted. Does NOT blanket-allow all private IPs."""
    if ip in _WL_EXACT:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Only block loopback unconditionally — NOT all private ranges
        if ip_obj.is_loopback:
            return True
    except ValueError:
        return False
    return False

# ──────────────────────────────────────────────────────────────
# 🔓 Auto Unblock (Exponential Backoff)
# ──────────────────────────────────────────────────────────────
def _get_unblock_delay(attempts: int) -> float:
    """Exponential backoff: 120s -> 240s -> 480s ... capped at 1 hour."""
    delay = AUTO_UNBLOCK_BASE * (2 ** max(0, attempts - 1))
    return min(delay, 3600.0)  # Never exceed 1 hour

def _auto_unblock(ip: str):
    delay = _get_unblock_delay(_states[ip].block_attempts if ip in _states else 1)
    log.info(f"[AUTO-UNBLOCK] Timeout reached for {ip} (backoff delay was {delay:.0f}s)")
    unblock_ip(ip)

# ──────────────────────────────────────────────────────────────
# 🔴 OS-Level Block
# ──────────────────────────────────────────────────────────────
def block_ip(ip: str, reason: str = "ATTACK"):
    state = _ensure_state(ip)   # FIX: never crash on uninitialized IP
    now = time.time()
    
    # Cooldown check (60 seconds)
    if state.status == "BLOCKED" and (now - state.last_block_time) < COOLDOWN_SEC:
        return

    state.status = "BLOCKED"
    state.last_block_time = now
    state.block_attempts += 1

    # Compute exponential backoff delay for auto-unblock
    unblock_delay = _get_unblock_delay(state.block_attempts)
    
    log.warning(
        f"[BLOCK] IP: {ip} | Reason: {reason} | "
        f"Attempt #{state.block_attempts} | Auto-Unblock in {unblock_delay:.0f}s"
    )
    print(f"  >> [BLOCK] {ip} | {reason} | Unblock in {unblock_delay:.0f}s")

    # OS Firewall Action
    if platform.system().lower() == "windows":
        rule_name = f"IDS_Block_{ip.replace('.', '_')}"
        os.system(f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip} > nul 2>&1')
    else:
        os.system(f'iptables -A INPUT -s {ip} -j DROP > /dev/null 2>&1')

    # Schedule Auto-Unblock with exponential backoff
    if state.unblock_timer:
        state.unblock_timer.cancel()
    state.unblock_timer = threading.Timer(unblock_delay, _auto_unblock, args=[ip])
    state.unblock_timer.daemon = True
    state.unblock_timer.start()

# ──────────────────────────────────────────────────────────────
# Ensure IP state is always initialized before access
# ──────────────────────────────────────────────────────────────
def _ensure_state(ip: str) -> IPState:
    """Get or create IPState for ip. Fixes crash when block_ip/monitor_ip called directly."""
    if ip not in _states:
        _states[ip] = IPState()
    return _states[ip]

# ──────────────────────────────────────────────────────────────
# Monitor Mode
# ──────────────────────────────────────────────────────────────
def monitor_ip(ip: str, reason: str = "SUSPICIOUS"):
    state = _ensure_state(ip)   # FIX: never crash on uninitialized IP
    if state.status == "BLOCKED":
        return  # Never downgrade if already blocked
    state.status = "MONITOR"
    log.info(f"[MONITOR] IP: {ip} | Reason: {reason}")
    print(f"  >> [MONITOR] {ip} | {reason}")

# ──────────────────────────────────────────────────────────────
# 🧠 Main Action Engine (Progressive State Machine)
# ──────────────────────────────────────────────────────────────
def execute_decision(ip: str, decision: str, reason: str = "", conf: float = 1.0):
    decision = decision.upper()
    if decision not in ("BLOCK", "ATTACK", "SUSPICIOUS", "MONITOR"):
        return

    if conf < 0.5:
        return

    if ip_in_whitelist(ip):
        # We silently ignore internally
        return

    # Normalize decisions
    if decision == "ATTACK": decision = "BLOCK"
    if decision == "SUSPICIOUS": decision = "MONITOR"

    # Initialize State Tracker
    if ip not in _states:
        _states[ip] = IPState()
    
    state = _states[ip]
    now = time.time()

    if decision == "BLOCK":
        # Safe Decision Rules: Decline Block without confidence
        if conf <= 0.8:
            monitor_ip(ip, reason=f"Low Conf ({conf:.2f}) -> {reason}")
            return

        # Time-based decay: hits older than 60s decay by 1 (not full reset)
        # This means attackers need sustained pressure to escalate
        HIT_DECAY_WINDOW = 60.0
        if now - state.last_hit_time > HIT_DECAY_WINDOW and state.hit_count > 0:
            state.hit_count = max(0, state.hit_count - 1)  # Decay, not reset
            state.first_hit_time = now
            log.debug(f"[HITS] ip={ip} | Decay applied | count={state.hit_count}")

        state.hit_count += 1
        state.last_hit_time = now
        if state.first_hit_time == 0.0:
            state.first_hit_time = now

        log.info(f"[HITS] ip={ip} count={state.hit_count} conf={conf:.2f}")
        print(f"  [HITS] ip={ip} count={state.hit_count}")

        if state.hit_count < 3:
            monitor_ip(ip, reason=f"Hit #{state.hit_count} (awaiting 3) -> {reason}")
        else:
            block_ip(ip, reason=f"Confirmed Threat (Hit #{state.hit_count}) -> {reason}")

    elif decision == "MONITOR":
        monitor_ip(ip, reason=reason)

# Backwards compatibility mapping
def take_action(result: str, ip: str, attack_type: str = "", conf: float = 1.0):
    execute_decision(ip, result, reason=attack_type, conf=conf)

def unblock_ip(ip: str):
    """Removes firewall rule and resets IP state (preserves block_attempts for backoff)."""
    if platform.system().lower() == "windows":
        rule_name = f"IDS_Block_{ip.replace('.', '_')}"
        os.system(f'netsh advfirewall firewall delete rule name="{rule_name}" > nul 2>&1')
    else:
        os.system(f'iptables -D INPUT -s {ip} -j DROP > /dev/null 2>&1')
        
    if ip in _states:
        if _states[ip].unblock_timer:
            _states[ip].unblock_timer.cancel()
        _states[ip].status = "NORMAL"
        _states[ip].hit_count = 0
        _states[ip].last_block_time = 0.0
        # NOTE: block_attempts is intentionally NOT reset — preserved for exponential backoff
        
    log.info(f"[UNBLOCK] Removed firewall rule for {ip}")
    print(f"  >> [UNBLOCK] {ip}")