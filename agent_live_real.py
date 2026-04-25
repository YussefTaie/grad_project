"""
agent_live_real.py  —  REAL-TIME IDS/IPS Pipeline (Full Integration)
======================================================================
Architecture:

  [1] Live Traffic Sniffing    (Scapy — main thread)
        ↓
  [2] Stateful Flow Table      (bidirectional, per 5-tuple)
        ↓  (on flow completion)
  [3] Feature Extraction       (74 CICIDS-compatible features)
        ↓  ──────────────────────────────────────────────────
        │  THREAD A (per completed flow — non-blocking):
        │    [4a] ML API  POST /predict
        │          ↓  response: {result, confidence, attack_type}
        │    [4b] FALLBACK: local rule-based if API is down
        │          ↓
        │    [5]  IPS Action (via ActionManager):
        │           ATTACK     → execute_action(BLOCK)
        │           SUSPICIOUS → execute_action(MONITOR)
        │           NORMAL     → nothing
        │
        │  THREAD B (every 10s — aggregate window):
        │    [4c] DDoS Detector        ← PPS rule
        │    [4d] Brute Force Detector ← attempt count
        │    [4e] Malware Detector     ← beacon + exfil + asymmetry
        │          ↓  fusion
        │    [5]  IPS Action (via ActionManager)
        │
  [6] Rate Limiter             (max 1 API call / IP / 30s)
  [7] Duplicate Block Guard    (tracked in action.py _states)
  [8] Structured Logging       ([API] / [IPS] / [FALLBACK] / [ERROR])

Constraints:
  - Scapy sniff() is NEVER blocked by API calls (threading)
  - ActionManager is the single IPS entry point (no raw take_action)
  - Whitelist is enforced at ActionManager level (gateway, DNS, localhost)
  - API errors are caught and logged; fallback activates automatically
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import sys
import time
import logging
import threading
from collections import defaultdict, deque

# ── third-party ───────────────────────────────────────────────────────────────
import numpy as np
import requests
from scapy.all import sniff, IP, TCP, UDP

# ── local modules ─────────────────────────────────────────────────────────────
from config import (
    FLOW_TIMEOUT_SEC,
    MAX_FLOW_PACKETS,
    API_URL,
    DDOS_PPS_THRESHOLD,
    DDOS_MIN_ALERTS,
    ATTACK_CLASS_NAMES,
)
from action_manager import execute_action            # ← INTEGRATION POINT
from brute_force_detector import bruteforce_verdict_by_ip
from malware_detector      import malware_verdict_by_ip
from ddos_detector_module  import detect_ddos_from_flows
from flow_utils            import compute_pps

# ── [DB] Sync wrappers — agent runs in threads, needs sync bridge to asyncpg ─
from db import sync_insert_flow as insert_flow, sync_upsert_host as upsert_host

# ── encoding ──────────────────────────────────────────────────────────────────
sys.stdout.reconfigure(encoding="utf-8")

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 0 — LOGGING SETUP
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(name)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("IDS-IPS")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# Rolling window: last N completed flows kept in memory for aggregate analysis
ROLLING_WINDOW_SIZE = 500

# How often (seconds) to run the aggregate detectors on the rolling window
ANALYSIS_INTERVAL   = 10.0

# Rate limiter: min seconds between API calls for the same src_ip
API_RATE_LIMIT_SEC  = 30.0

# Minimum confidence to trigger IPS action from ML verdict
MIN_CONFIDENCE_TO_ACT = 0.70

# Confidence threshold above which ATTACK is immediate (no debounce)
HIGH_CONFIDENCE_THRESHOLD = 0.85


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — SHARED STATE
# ══════════════════════════════════════════════════════════════════════════════

# Stateful flow table: flow_key → {packets, timestamps, src/dst metadata}
flow_table: dict = defaultdict(lambda: {
    "packets":   [],
    "last_seen": 0.0,
    "src_ip":    None,
    "dst_ip":    None,
    "src_port":  None,
    "dst_port":  None,
})
flow_lock = threading.Lock()

# Rolling window of completed feature dicts (shared across threads)
_rolling_window: deque = deque(maxlen=ROLLING_WINDOW_SIZE)
_window_lock = threading.Lock()

# ── [6] Rate Limiter: tracks last API call time per src_ip ───────────────────
# { src_ip → last_call_unix_timestamp }
_api_rate_limiter: dict = {}
_rate_limiter_lock = threading.Lock()

# ── API liveness flag (toggled by health-check thread) ───────────────────────
_api_alive = threading.Event()
_api_alive.set()   # assume alive at start


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — HELPER UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def _map_attack_type_to_threat(attack_type: str) -> str:
    """
    Maps ML attack_type string → ActionManager ThreatType literal.
    This ensures the correct threat-specific handler fires (malware,
    ddos, bruteforce, generic).
    """
    t = attack_type.upper()

    # ── [INTEGRATION] Threat-type mapping ───────────────────────────────────
    if "DDOS" in t or "DOS" in t:
        return "DDOS"
    if "BRUTE" in t or "PATATOR" in t or "FTP" in t or "SSH" in t:
        return "BRUTEFORCE"
    if "RANSOMWARE" in t:
        return "RANSOMWARE"
    if "MALWARE" in t or "BOTNET" in t or "BOT" in t or "WEB" in t:
        return "MALWARE"
    if "PORT" in t or "SCAN" in t:
        return "GENERIC"
    return "GENERIC"


def _can_call_api(src_ip: str) -> bool:
    """
    [6] Rate Limiter — returns True if it's safe to call the API for this IP.
    Prevents flooding the API with calls for the same source IP.
    """
    now = time.time()
    with _rate_limiter_lock:
        last = _api_rate_limiter.get(src_ip, 0.0)
        if now - last >= API_RATE_LIMIT_SEC:
            _api_rate_limiter[src_ip] = now
            return True
        return False


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — FLOW KEY + PACKET PARSING
# ══════════════════════════════════════════════════════════════════════════════

def get_flow_key(pkt):
    """
    Returns a canonical (bidirectional) 4-tuple key for the flow,
    plus the source and destination IPs for this particular packet.
    """
    if IP not in pkt:
        return None, None, None
    src = pkt[IP].src
    dst = pkt[IP].dst
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        sport, dport = 0, 0
    # Canonical ordering so A→B and B→A have the same key
    if (src, sport) < (dst, dport):
        return (src, sport, dst, dport), src, dst
    return (dst, dport, src, sport), src, dst


def parse_packet(pkt, flow_src_ip: str) -> dict:
    """Extracts per-packet statistics for later flow feature computation."""
    size   = len(pkt)
    is_fwd = (pkt[IP].src == flow_src_ip)
    flags  = {}
    if TCP in pkt:
        t = pkt[TCP]
        flags = {
            "SYN": bool(t.flags & 0x02),
            "FIN": bool(t.flags & 0x01),
            "RST": bool(t.flags & 0x04),
            "PSH": bool(t.flags & 0x08),
            "ACK": bool(t.flags & 0x10),
            "URG": bool(t.flags & 0x20),
        }
    return {
        "time":      float(pkt.time),
        "size":      size,
        "direction": "fwd" if is_fwd else "bwd",
        **flags,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — FEATURE COMPUTATION  (CICIDS-compatible, 74+ features)
# ══════════════════════════════════════════════════════════════════════════════

def compute_flow_features(flow_data: dict) -> dict | None:
    """
    Converts raw per-packet data into a CICIDS-compatible feature vector
    suitable for the ML API.
    """
    pkts = flow_data["packets"]
    if not pkts:
        return None

    times  = [p["time"] for p in pkts]
    sizes  = [p["size"] for p in pkts]
    fwd    = [p for p in pkts if p["direction"] == "fwd"]
    bwd    = [p for p in pkts if p["direction"] == "bwd"]
    fwd_sz = [p["size"] for p in fwd]
    bwd_sz = [p["size"] for p in bwd]

    dur_us = (times[-1] - times[0]) * 1_000_000 if len(times) > 1 else 1.0
    if dur_us == 0:
        dur_us = 1.0

    iats = [times[i + 1] - times[i] for i in range(len(times) - 1)]

    def safe_mean(lst): return float(np.mean(lst)) if lst else 0.0
    def safe_std(lst):  return float(np.std(lst))  if lst else 0.0
    def safe_max(lst):  return float(max(lst))      if lst else 0.0
    def safe_min(lst):  return float(min(lst))      if lst else 0.0

    return {
        # ── [2] Feature Extraction — Identifiers ────────────────────────────
        "Src IP":   flow_data["src_ip"],
        "Dst IP":   flow_data["dst_ip"],
        "Src Port": flow_data["src_port"],
        "Dst Port": flow_data["dst_port"],
        # ── CICIDS features ──────────────────────────────────────────────────
        "Destination Port":              flow_data["dst_port"],
        "Flow Duration":                 dur_us,
        "Total Fwd Packets":             len(fwd),
        "Total Backward Packets":        len(bwd),
        "Total Length of Fwd Packets":   sum(fwd_sz),
        "Total Length of Bwd Packets":   sum(bwd_sz),
        "Fwd Packet Length Max":         safe_max(fwd_sz),
        "Fwd Packet Length Min":         safe_min(fwd_sz),
        "Fwd Packet Length Mean":        safe_mean(fwd_sz),
        "Fwd Packet Length Std":         safe_std(fwd_sz),
        "Bwd Packet Length Max":         safe_max(bwd_sz),
        "Bwd Packet Length Min":         safe_min(bwd_sz),
        "Bwd Packet Length Mean":        safe_mean(bwd_sz),
        "Bwd Packet Length Std":         safe_std(bwd_sz),
        "Flow IAT Mean":                 safe_mean(iats),
        "Flow IAT Std":                  safe_std(iats),
        "Flow IAT Max":                  safe_max(iats),
        "Flow IAT Min":                  safe_min(iats),
        "Fwd IAT Total":                 float(sum(iats)),
        "Fwd IAT Mean":                  safe_mean(iats),
        "Fwd IAT Std":                   safe_std(iats),
        "Fwd IAT Max":                   safe_max(iats),
        "Fwd IAT Min":                   safe_min(iats),
        "SYN Flag Count":                sum(1 for p in pkts if p.get("SYN")),
        "FIN Flag Count":                sum(1 for p in pkts if p.get("FIN")),
        "RST Flag Count":                sum(1 for p in pkts if p.get("RST")),
        "PSH Flag Count":                sum(1 for p in pkts if p.get("PSH")),
        "ACK Flag Count":                sum(1 for p in pkts if p.get("ACK")),
        "URG Flag Count":                sum(1 for p in pkts if p.get("URG")),
        "Packet Length Mean":            safe_mean(sizes),
        "Packet Length Std":             safe_std(sizes),
        "Packet Length Variance":        float(np.var(sizes)) if sizes else 0.0,
        "Max Packet Length":             safe_max(sizes),
        "Min Packet Length":             safe_min(sizes),
        "Average Packet Size":           safe_mean(sizes),
        "Avg Fwd Segment Size":          safe_mean(fwd_sz),
        "Avg Bwd Segment Size":          safe_mean(bwd_sz),
        "Subflow Fwd Packets":           len(fwd),
        "Subflow Fwd Bytes":             sum(fwd_sz),
        "Subflow Bwd Packets":           len(bwd),
        "Subflow Bwd Bytes":             sum(bwd_sz),
        "act_data_pkt_fwd":             sum(1 for p in fwd if p["size"] > 0),
        "min_seg_size_forward":          safe_min(fwd_sz),
        # ── DDoS / PPS helpers ───────────────────────────────────────────────
        "Packets per Second":            compute_pps(len(pkts), dur_us / 1_000_000),
        "Total Packets":                 len(pkts),
        "Total Bytes":                   sum(sizes),
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — FALLBACK: LOCAL RULE-BASED DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def _local_fallback(features: dict) -> dict:
    """
    [4b] FALLBACK — used when the ML API is unreachable.
    Applies simple heuristic rules directly on the feature vector
    so the IPS never goes completely blind.

    Rules:
      - SYN flood  : SYN Flag Count / Total Packets > 0.9 AND PPS > 100
      - Port scan  : many unique dst ports (heuristic via RST count)
      - High volume: Total Bytes > 5MB in one flow
    """
    result     = "NORMAL"
    attack_type = "BENIGN"
    confidence  = 0.5   # fallback rules aren't probabilistic

    total_pkts = features.get("Total Packets", 1) or 1
    syn_count  = features.get("SYN Flag Count",  0)
    pps        = features.get("Packets per Second", 0)
    total_bytes = features.get("Total Bytes", 0)

    syn_ratio = syn_count / total_pkts

    # ── [4b] Heuristic rules ─────────────────────────────────────────────────
    if syn_ratio > 0.90 and pps > DDOS_PPS_THRESHOLD:
        result, attack_type, confidence = "ATTACK", "DDoS(Fallback-SYNFlood)", 0.80

    elif total_bytes > 5_000_000:
        result, attack_type, confidence = "SUSPICIOUS", "Exfiltration(Fallback)", 0.65

    elif features.get("RST Flag Count", 0) / total_pkts > 0.5:
        result, attack_type, confidence = "SUSPICIOUS", "Scan(Fallback-RST)", 0.60

    return {
        "result":      result,
        "attack_type": attack_type,
        "confidence":  confidence,
        "source":      "FALLBACK",
    }


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — ML API CALL  (non-blocking, with timeout + fallback)
# ══════════════════════════════════════════════════════════════════════════════

def _call_api(features: dict) -> dict:
    """
    [3] Sends a POST request to the Flask ML API.

    Error handling:
      - Connection refused / timeout → fallback to local rules + marks API down
      - Non-200 response → fallback
      - Invalid JSON → fallback

    [8] Logging:
      [API]     → successful response
      [FALLBACK] → API was down, used local rules
      [ERROR]   → unexpected exception
    """
    try:
        resp = requests.post(API_URL, json=features, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            data["source"] = "ML_API"
            if not _api_alive.is_set():
                _api_alive.set()
                log.info("[API] Connection restored.")
            return data

        # ── Non-200 response ─────────────────────────────────────────────────
        log.warning(f"[API] Non-200 response: HTTP {resp.status_code} — using fallback")
        return _local_fallback(features)

    except requests.exceptions.ConnectionError:
        if _api_alive.is_set():
            _api_alive.clear()
            log.error("[API] Connection refused — API is DOWN. Switching to FALLBACK mode.")
        return _local_fallback(features)

    except requests.exceptions.Timeout:
        log.warning("[API] Request timed out after 3s — using fallback")
        return _local_fallback(features)

    except Exception as e:
        # ── [8] ERROR logging ────────────────────────────────────────────────
        log.error(f"[ERROR] Unexpected API error: {e}")
        return _local_fallback(features)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — IPS DISPATCHER  (single entry point for all actions)
# ══════════════════════════════════════════════════════════════════════════════

def _dispatch_ips(
    src_ip:      str,
    verdict:     str,
    attack_type: str,
    confidence:  float,
    source:      str = "ML_API",
):
    """
    [5] IPS Action Dispatcher — INTEGRATION POINT.

    Routes the detection verdict to the ActionManager with the correct
    threat type. This replaces the old take_action() call and ensures:
      ✓ Whitelist checked (gateway, DNS, localhost — never blocked)
      ✓ Threat-specific handler fires (malware, ddos, bruteforce, generic)
      ✓ Progressive debouncing (needs N hits before hard block)
      ✓ Deduplication (no double-blocking same IP)

    [8] Logging:
      [IPS] → action taken
    """
    if verdict == "NORMAL":
        return   # Nothing to do

    threat_type = _map_attack_type_to_threat(attack_type)
    decision    = "BLOCK" if verdict == "ATTACK" else "MONITOR"

    reason = (
        f"source={source} | type={attack_type} | "
        f"verdict={verdict} | conf={confidence:.3f}"
    )

    # ── [8] IPS log ──────────────────────────────────────────────────────────
    icon = "[!!]" if verdict == "ATTACK" else "[? ]"
    log.warning(
        f"[IPS] {icon} {decision:<7}  src={src_ip:<16}  "
        f"threat={threat_type:<12}  type={attack_type:<22}  conf={confidence:.3f}"
    )

    # ── [INTEGRATION] Call ActionManager ─────────────────────────────────────
    execute_action(
        ip          = src_ip,
        threat_type = threat_type,  # type: ignore[arg-type]
        decision    = decision,     # type: ignore[arg-type]
        reason      = reason,
        conf        = confidence,
    )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — FUSION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _fusion(
    ml_result:       dict,
    ddos_verdict:    str,
    brute_verdict:   str,
    malware_verdict: str,
) -> tuple[str, str]:
    """
    Combines all detection signals into (final_verdict, reason).
    Priority: DDoS > BruteForce > Malware > ML
    """
    if ddos_verdict == "ATTACK":
        return "ATTACK", "DDoS"
    if brute_verdict == "ATTACK":
        return "ATTACK", "BruteForce"
    if malware_verdict == "ATTACK":
        return "ATTACK", "Malware"

    ml_label = ml_result.get("result", "").upper()
    ml_type  = ml_result.get("attack_type", "")

    if "ATTACK" in ml_label:
        return "ATTACK", f"ML:{ml_type}"
    if malware_verdict == "SUSPICIOUS" or "SUSPICIOUS" in ml_label:
        return (
            "SUSPICIOUS",
            f"ML:{ml_type}" if "SUSPICIOUS" in ml_label else "Malware(Suspicious)",
        )
    return "NORMAL", "BENIGN"


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — THREAD A: PER-FLOW PROCESSING (ML API → IPS)
# ══════════════════════════════════════════════════════════════════════════════

def process_completed_flow(flow_key, flow_data: dict):
    """
    [THREAD A] Runs for every completed flow in a daemon thread.
    Non-blocking: Scapy sniff() is never stalled by this function.

    Steps:
      1. Compute 74-feature vector                  [2]
      2. Rate-limit check                           [6]
      3. POST to ML API (with fallback)             [3][4b]
      4. Log the API response                       [8]
      5. Dispatch IPS action if needed              [5]
      6. Add features to rolling window             (aggregate)
    """
    # ── [2] Feature extraction ───────────────────────────────────────────────
    features = compute_flow_features(flow_data)
    if not features:
        return

    src_ip = flow_data["src_ip"]

    # ── [DB] Persist flow + host (daemon sub-thread, fire-and-forget) ────────
    def _store_flow():
        try:
            upsert_host(src_ip)           # ensure hosts row exists
            insert_flow(
                src_ip   = src_ip,
                dst_ip   = flow_data.get("dst_ip", "unknown"),
                packets  = features.get("Total Packets", 0),
                bytes_   = features.get("Total Bytes",   0),
                pps      = features.get("Packets per Second", 0.0),
                duration = features.get("Flow Duration", 0.0),
            )
        except Exception as _e:
            log.error(f"[DB ERROR] store_flow failed for {src_ip}: {_e}")

    threading.Thread(target=_store_flow, daemon=True).start()
    # ─────────────────────────────────────────────────────────────────────

    # ── [6] Rate limiting — skip API if called too recently ──────────────────
    if not _can_call_api(src_ip):
        return

    # ── Add to rolling window ─────────────────────────────────────────────────
    with _window_lock:
        _rolling_window.append(features)

    # ── [3] Call ML API (blocking call — runs in daemon thread, safe) ─────────
    ml_result = _call_api(features)

    verdict    = ml_result.get("result",      "NORMAL")
    attack_type = ml_result.get("attack_type", "BENIGN")
    confidence  = ml_result.get("confidence",  0.0)
    source      = ml_result.get("source",      "ML_API")

    # ── [8] API response log ─────────────────────────────────────────────────
    src_tag  = source[:2]   # "ML" or "FA" (FALLBACK)
    icon     = "[!!]" if "ATTACK" in verdict.upper() \
               else "[? ]" if "SUSPICIOUS" in verdict.upper() \
               else "[OK]"
    log.info(
        f"[{src_tag}]  {icon} src={src_ip:<16}  "
        f"verdict={verdict:<10}  type={attack_type:<22}  conf={confidence:.3f}"
    )

    # ── [5] IPS action — only if confidence meets threshold ──────────────────
    if "NORMAL" not in verdict.upper() and confidence >= MIN_CONFIDENCE_TO_ACT:
        _dispatch_ips(src_ip, verdict, attack_type, confidence, source)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — THREAD B: AGGREGATE ANALYSIS (DDoS / BruteForce / Malware)
# ══════════════════════════════════════════════════════════════════════════════

def _aggregate_analysis_loop():
    """
    [THREAD B] Runs every ANALYSIS_INTERVAL seconds.
    Analyzes the rolling window of completed flows with rule-based detectors
    that require multiple flows (DDoS, BruteForce, Malware beaconing).

    Results are fused and dispatched to the IPS via ActionManager.
    """
    while True:
        time.sleep(ANALYSIS_INTERVAL)

        # Snapshot the rolling window (lock-protected copy)
        with _window_lock:
            window = list(_rolling_window)

        if not window:
            continue

        print(f"\n{'='*68}")
        print(f"  [~] Aggregate Analysis — {len(window)} flows in window")
        print(f"{'='*68}")

        # ── [4c] DDoS ────────────────────────────────────────────────────────
        ddos_verdicts    = detect_ddos_from_flows(window)

        # ── [4d] Brute Force ─────────────────────────────────────────────────
        brute_verdicts   = bruteforce_verdict_by_ip(window)

        # ── [4e] Malware ──────────────────────────────────────────────────────
        malware_verdicts = malware_verdict_by_ip(window)

        # ── Collect unique src IPs from window ────────────────────────────────
        all_ips = {
            f.get("Src IP") or f.get("Source IP", "unknown")
            for f in window
        }

        acted_ips: list[str] = []

        for ip in all_ips:
            ddos_v    = ddos_verdicts.get(ip,    "NORMAL")
            brute_v   = brute_verdicts.get(ip,   "NORMAL")
            malware_v = malware_verdicts.get(ip, "NORMAL")

            # ML signal is empty here (handled per-flow in THREAD A)
            dummy_ml  = {"result": "NORMAL", "confidence": 0.0}
            final, reason = _fusion(dummy_ml, ddos_v, brute_v, malware_v)

            if final in ("ATTACK", "SUSPICIOUS"):
                flags = []
                if ddos_v    == "ATTACK": flags.append("DDoS")
                if brute_v   == "ATTACK": flags.append("BruteForce")
                if malware_v in ("ATTACK", "SUSPICIOUS"):
                    flags.append(f"Malware({malware_v})")
                flags_str = "+".join(flags) or reason

                # ── [5] IPS dispatch ──────────────────────────────────────────
                _dispatch_ips(
                    src_ip      = ip,
                    verdict     = final,
                    attack_type = flags_str,
                    confidence  = 0.90 if final == "ATTACK" else 0.70,
                    source      = "AGGREGATE",
                )
                acted_ips.append(ip)

        if not acted_ips:
            log.info("  [OK] No aggregate threats detected this window.")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — FLOW TIMEOUT FLUSHER THREAD
# ══════════════════════════════════════════════════════════════════════════════

def _flow_timeout_flusher():
    """
    Flushes flows that have been idle for FLOW_TIMEOUT_SEC seconds.
    Runs every second in a daemon thread.
    """
    while True:
        time.sleep(1.0)
        now     = time.time()
        expired = []

        with flow_lock:
            for key, flow in list(flow_table.items()):
                if flow["last_seen"] > 0 and (now - flow["last_seen"]) >= FLOW_TIMEOUT_SEC:
                    expired.append((key, dict(flow)))

        for key, snapshot in expired:
            # Remove from table first to avoid races
            with flow_lock:
                flow_table.pop(key, None)
            # Process in a new daemon thread — keeps sniff() unblocked
            threading.Thread(
                target=process_completed_flow,
                args=(key, snapshot),
                daemon=True,
            ).start()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — API HEALTH MONITOR  (optional background check)
# ══════════════════════════════════════════════════════════════════════════════

def _api_health_monitor():
    """
    Periodically checks if the API is back online after a failure.
    Updates _api_alive event so logs reflect current state.
    """
    health_url = API_URL.replace("/predict", "/health")
    while True:
        time.sleep(15)
        if not _api_alive.is_set():
            try:
                r = requests.get(health_url, timeout=2)
                if r.status_code == 200:
                    _api_alive.set()
                    log.info("[API] Health check: API is back ONLINE.")
            except Exception:
                pass   # Still down — try again next cycle


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — PACKET HANDLER  (Scapy main thread)
# ══════════════════════════════════════════════════════════════════════════════

def on_packet(pkt):
    """
    Called by Scapy for every captured packet.
    Only populates the stateful flow table — never blocks on API.
    When a flow is full (MAX_FLOW_PACKETS), it's flushed to a daemon thread.
    """
    key, src_ip, dst_ip = get_flow_key(pkt)
    if key is None:
        return

    pkt_data   = parse_packet(pkt, src_ip)
    flush_snap = None   # set if flow is full mid-packet

    with flow_lock:
        flow = flow_table[key]
        if flow["src_ip"] is None:
            flow["src_ip"]   = src_ip
            flow["dst_ip"]   = dst_ip
            flow["src_port"] = key[1]
            flow["dst_port"] = key[3]

        flow["packets"].append(pkt_data)
        flow["last_seen"] = pkt_data["time"]

        # ── [5 OPTIMIZATION] Batch: flush when MAX_FLOW_PACKETS reached ──────
        if len(flow["packets"]) >= MAX_FLOW_PACKETS:
            flush_snap = dict(flow)
            del flow_table[key]

    if flush_snap:
        threading.Thread(
            target=process_completed_flow,
            args=(key, flush_snap),
            daemon=True,
        ).start()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 15 — ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print("=" * 68)
    print("  REAL-TIME IDS/IPS PIPELINE  —  Full Integration")
    print("=" * 68)
    print(f"  ML API             : {API_URL}")
    print(f"  Flow Timeout       : {FLOW_TIMEOUT_SEC}s")
    print(f"  Max Pkts/Flow      : {MAX_FLOW_PACKETS}")
    print(f"  Rolling Window     : {ROLLING_WINDOW_SIZE} flows")
    print(f"  Aggregate Interval : {ANALYSIS_INTERVAL}s")
    print(f"  API Rate Limit     : {API_RATE_LIMIT_SEC}s / IP")
    print(f"  Min Confidence     : {MIN_CONFIDENCE_TO_ACT}")
    print("=" * 68)
    print()
    print("  IDS Detectors:")
    print("    [1] ML  — XGBoost (6-class) + IsoForest   per flow")
    print("    [2] DDoS  — PPS rule-based                 every 10s")
    print("    [3] BruteForce  — attempt count            every 10s")
    print("    [4] Malware  — beacon + exfil + asymmetry  every 10s")
    print("    [FALLBACK] Local rules if API is down")
    print()
    print("  IPS Actions (via ActionManager):")
    print("    ATTACK      → BLOCK  (threat-specific handler)")
    print("    SUSPICIOUS  → MONITOR (log + track)")
    print("    NORMAL      → allow (no action)")
    print("=" * 68)
    print()

    # ── [6] Thread: flush idle flows ─────────────────────────────────────────
    t_flush = threading.Thread(target=_flow_timeout_flusher, daemon=True)
    t_flush.start()
    log.info("Thread [flow-flusher] started.")

    # ── [THREAD B] Aggregate analysis ────────────────────────────────────────
    t_agg = threading.Thread(target=_aggregate_analysis_loop, daemon=True)
    t_agg.start()
    log.info("Thread [aggregate-analysis] started.")

    # ── API health monitor ───────────────────────────────────────────────────
    t_health = threading.Thread(target=_api_health_monitor, daemon=True)
    t_health.start()
    log.info("Thread [api-health-monitor] started.")

    # ── [1] Main thread: packet capture ──────────────────────────────────────
    log.info("Sniffing on all interfaces... (Ctrl+C to stop)\n")
    try:
        sniff(filter="ip", prn=on_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS/IPS agent...")
        log.info("Agent stopped by user.")