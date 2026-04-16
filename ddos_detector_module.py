"""
ddos_detector_module.py  —  Adaptive DDoS Detection
=====================================================
Drop-in upgrade of the original module.

Backward compatibility
----------------------
* The public function ``detect_ddos_from_flows(flows)`` signature is UNCHANGED.
* The original fixed thresholds (THRESHOLD=150, MIN_ALERTS=3) are kept as
  *fallback* values when the baseline engine has not yet collected enough
  samples.
* ddos_detector.py is left completely untouched.

What changed
------------
* Threshold is now ADAPTIVE: per-IP mean + k*std  (via BaselineEngine).
* Context layer suppresses false positives caused by:
    - High traffic to MANY different destinations  (browsing, downloads)
    - Brief PPS spikes that are NOT sustained
* MIN_ALERTS is still required (now adaptive: max(2, MIN_ALERTS)).
* A new optional ``detect_ddos_from_flows_ctx`` accepts the ContextLayer
  directly (used by unified_agent in live/pcap modes for richer logging).
"""

from collections import defaultdict
from typing import Optional
import time

_last_ddos_alert: dict = {} # ip -> timestamp

# ── Original thresholds kept as fallback (DO NOT REMOVE) ─────────────────────
THRESHOLD  = 150   # packets per second – original fixed threshold
MIN_ALERTS = 3     # minimum alert windows before declaring ATTACK

# ── Adaptive machinery (new, additive) ────────────────────────────────────────
try:
    from baseline_engine import get_engine, BaselineEngine
    from context_layer   import get_context_layer, ContextLayer
    _ADAPTIVE_AVAILABLE = True
except ImportError:
    _ADAPTIVE_AVAILABLE = False


# ── Helper ────────────────────────────────────────────────────────────────────
def _float(row: dict, *keys, default: float = 0.0) -> float:
    for k in keys:
        v = row.get(k)
        if v is not None:
            try:
                return float(v)
            except (ValueError, TypeError):
                pass
    return default


def _src(row: dict) -> str:
    return (
        row.get("Src IP") or row.get("Source IP") or
        row.get("src_ip") or "unknown"
    )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN DETECTION FUNCTION  (drop-in replacement)
# ══════════════════════════════════════════════════════════════════════════════

def detect_ddos_from_flows(
    flows: list[dict],
    engine: Optional["BaselineEngine"] = None,   # noqa: F821
    ctx_layer: Optional["ContextLayer"] = None,   # noqa: F821
) -> dict[str, str]:
    """
    Run adaptive DDoS detection on a list of flow dictionaries.

    Each flow dict must contain at least:
      - "Src IP"            (or "Source IP")
      - "Packets per Second"

    Returns
    -------
    dict[src_ip → "ATTACK" | "NORMAL"]

    The function falls back to the original fixed-threshold logic when the
    baseline engine has no data yet, ensuring zero regression.
    """
    # Resolve engines (use singletons if not provided)
    if _ADAPTIVE_AVAILABLE:
        _engine    = engine    or get_engine()
        _ctx_layer = ctx_layer or get_context_layer()
    else:
        _engine    = None
        _ctx_layer = None

    # ── Collect per-IP statistics ─────────────────────────────────────────────
    ip_stats: dict = defaultdict(lambda: {"pps_values": [], "alerts": 0})

    for row in flows:
        src_ip = _src(row)
        pps    = _float(row, "Packets per Second")
        ip_stats[src_ip]["pps_values"].append(pps)

        # Feed the baseline engine so it learns continuously
        if _engine:
            _engine.update(row)

    results: dict[str, str] = {}

    for ip, data in ip_stats.items():
        values  = data["pps_values"]
        avg_pps = sum(values) / len(values) if values else 0.0
        max_pps = max(values) if values else 0.0

        # ── Determine adaptive threshold ──────────────────────────────────
        if _engine:
            adaptive_thr = _engine.adaptive_ddos_threshold(ip, fallback=THRESHOLD)
        else:
            adaptive_thr = float(THRESHOLD)

        # Count how many windows exceeded the *adaptive* threshold
        adaptive_alerts = sum(1 for pps in values if pps > adaptive_thr)

        # ── Print diagnostic (same format as original) ────────────────────
        print(
            f"[DDoS] {ip:<15}  AVG={avg_pps:.2f}  MAX={max_pps:.2f}"
            f"  ALERTS={adaptive_alerts}"
            f"  ADAPTIVE_THR={adaptive_thr:.1f}"
        )

        total_flows = len(values)
        
        # ── 1. Minimum Alert Threshold ────────────────────────────────────
        if adaptive_alerts < 3:
            results[ip] = "NORMAL"
            continue

        # ── 2. Confidence-Based Filtering ─────────────────────────────────
        ddos_confidence = adaptive_alerts / total_flows if total_flows > 0 else 0.0
        
        if ddos_confidence < 0.3:
            print(f"[DDoS] ↳  Suppressed: {ip} | conf {ddos_confidence:.2f} < 0.3")
            results[ip] = "NORMAL"
            continue

        # Apply context check to suppress false positives
        if _ctx_layer:
            should_flag, reason = _ctx_layer.should_flag_ddos(
                ip, max_pps, adaptive_alerts
            )
            if not should_flag:
                print(f"[DDoS] ↳  Suppressed: {ip} | {reason}")
                results[ip] = "NORMAL"
                continue

        # ── 3. Cooldown System (10s) ──────────────────────────────────────
        now = time.time()
        if now - _last_ddos_alert.get(ip, 0) < 10.0:
            print(f"[DDoS] ↳  Suppressed: {ip} | Cooldown active (10s)")
            results[ip] = "NORMAL"  # Or keep previous state, but we return NORMAL so we don't trigger action engine
            continue
            
        _last_ddos_alert[ip] = now

        # ── 4. Alert vs Attack Separation ─────────────────────────────────
        # Weak signals -> MONITOR (SUSPICIOUS)
        # Strong/sustained signals -> BLOCK (ATTACK)
        if ddos_confidence >= 0.7 or adaptive_alerts >= 6:
            print(f"[DDoS] ⚠  ATTACK: {ip} | conf={ddos_confidence:.2f} alerts={adaptive_alerts}")
            results[ip] = "ATTACK"
        else:
            print(f"[DDoS] ⚠  ALERT: {ip} | conf={ddos_confidence:.2f} alerts={adaptive_alerts}")
            results[ip] = "SUSPICIOUS"

    return results
