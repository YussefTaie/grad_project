"""
brute_force_detector.py  —  Rule-Based Brute Force Detection Agent
===================================================================
FIX 4: Time-window based detection (Option A)

OLD logic (broken):
  Count ALL flows in the rolling window (up to 500 flows) that share
  (src_ip, dst_ip, dst_port). Threshold = 10.
  → Normal browsing (e.g. 10 HTTP/HTTPS connections) → false ATTACK.

NEW logic:
  Group flows by (src_ip, dst_ip, dst_port) AND time.
  Only count flows that fall within the last TIME_WINDOW_SEC seconds
  of the most recent flow in each group.
  Threshold raised to ATTACK_THRESHOLD (50) to match real brute-force tools.
  Flows that are spread across long durations are NOT counted together.

The flows supported (same format as flow_builder.py):
  Keys: "Src IP" or "Source IP"
        "Dst IP" or "Destination IP"  or "dst_ip"
        "Dst Port" or "Destination Port"
        "Flow Duration"   (optional — used for time filtering)
        "_timestamp"      (optional — epoch seconds, injected by live agent)
"""

import time
from collections import defaultdict
from config import FLOW_TIMEOUT_SEC  # for reference only

# ──────────────────────────────────────────────────────────────
# ⚙️ Thresholds (FIX 4: realistic values)
# ──────────────────────────────────────────────────────────────
ATTACK_THRESHOLD  = 50   # flows in TIME_WINDOW_SEC → ATTACK
                          # (old value = 10 → triggered by normal browsing)
TIME_WINDOW_SEC   = 60   # look-back window in seconds for rate calculation


# ──────────────────────────────────────────────────────────────
# 🔧 Helper — نستخرج الـ keys باتساق
# ──────────────────────────────────────────────────────────────
def _get(flow: dict, *keys, default="unknown"):
    for k in keys:
        v = flow.get(k)
        if v is not None and v != "":
            return str(v)
    return default


def _get_flow_time(flow: dict) -> float:
    """
    Extract a best-guess epoch timestamp from a flow dict.
    Tries several fields that different modules may populate.
    Falls back to current time if nothing is available.
    """
    # Prefer an explicit injection timestamp (live agent may set this)
    t = flow.get("_timestamp")
    if t is not None:
        try:
            return float(t)
        except (ValueError, TypeError):
            pass
    # Fall back to current time (all flows in a batch are treated as "now")
    return time.time()


# ──────────────────────────────────────────────────────────────
# 🔍 Main Detection Function  (FIX 4: time-window aware)
# ──────────────────────────────────────────────────────────────
def detect_bruteforce(flows: list[dict]) -> list[dict]:
    """
    Detects Brute Force by grouping flows per (src_ip, dst_ip, dst_port)
    and counting only those that fall within TIME_WINDOW_SEC of each other.

    Key difference from old code:
      - Old: counted ALL flows in a 500-flow rolling window. Threshold = 10.
            Normal browsing with 10+ connections → false ATTACK.
      - New: counts only flows within a 60-second time window. Threshold = 50.
            A real brute-force tool sends many requests in rapid succession;
            normal browsing spreads its connections over minutes.

    Args:
        flows: list of flow dicts

    Returns:
        list of alert dicts:
        [
            {
                "ip":       "192.168.1.5",
                "dst_ip":   "10.0.0.1",
                "dst_port": "22",
                "result":   "ATTACK",
                "attempts": 75,
                "window_sec": 60,
                "reason":   "Brute Force: 75 attempts on 10.0.0.1:22 in 60s"
            },
            ...
        ]
    """
    # { (src_ip, dst_ip, dst_port) → sorted list of epoch timestamps }
    groups: dict = defaultdict(list)

    for flow in flows:
        src_ip   = _get(flow, "Src IP", "Source IP", "src_ip")
        dst_ip   = _get(flow, "Dst IP", "Destination IP", "dst_ip")
        dst_port = _get(flow, "Dst Port", "Destination Port", "dst_port")
        ts       = _get_flow_time(flow)
        key      = (src_ip, dst_ip, dst_port)
        groups[key].append(ts)

    results = []

    for (src_ip, dst_ip, dst_port), timestamps in groups.items():
        if len(timestamps) < 2:
            # Single flow is never brute-force
            continue

        timestamps_sorted = sorted(timestamps)

        # Sliding window: find the maximum number of attempts in any
        # TIME_WINDOW_SEC-wide window using a two-pointer approach.
        max_in_window = 0
        left = 0
        for right in range(len(timestamps_sorted)):
            # Shrink window from the left until it fits within TIME_WINDOW_SEC
            while timestamps_sorted[right] - timestamps_sorted[left] > TIME_WINDOW_SEC:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        if max_in_window > ATTACK_THRESHOLD:
            results.append({
                "ip":         src_ip,
                "dst_ip":     dst_ip,
                "dst_port":   dst_port,
                "result":     "ATTACK",
                "attempts":   max_in_window,
                "window_sec": TIME_WINDOW_SEC,
                "reason": (
                    f"Brute Force: {max_in_window} attempts "
                    f"on {dst_ip}:{dst_port} within {TIME_WINDOW_SEC}s window"
                ),
            })

    return results


# ──────────────────────────────────────────────────────────────
# 🗺️  Index سريع: src_ip → verdict  (للـ fusion في main_agent)
# ──────────────────────────────────────────────────────────────
def bruteforce_verdict_by_ip(flows: list[dict]) -> dict[str, str]:
    """
    Helper للاستخدام في main_agent.py — يرجع:
      { src_ip → "ATTACK" | "NORMAL" }

    لو نفس الـ src_ip ظهر في أكثر من target، بنأخذ أشد حكم.
    """
    verdict: dict = {}
    for r in detect_bruteforce(flows):
        ip = r["ip"]
        # لو موجود بالفعل وكان ATTACK، إبقيه
        if verdict.get(ip) != "ATTACK":
            verdict[ip] = r["result"]
    return verdict


# ──────────────────────────────────────────────────────────────
# 🧪 Quick self-test
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    # محاكاة: نفس src يضرب SSH على نفس الـ dst كتير
    test_flows = []
    for i in range(15):
        test_flows.append({
            "Src IP":          "10.0.0.99",
            "Dst IP":          "192.168.1.10",
            "Dst Port":        "22",
            "Total Packets":   3,
            "Flow Duration":   0.5,
        })
    # بعض الـ flows الطبيعية
    for i in range(3):
        test_flows.append({
            "Src IP":   "10.0.0.1",
            "Dst IP":   "192.168.1.20",
            "Dst Port": "443",
            "Total Packets": 10,
        })

    print("=== Brute Force Detector Self-Test ===\n")
    results = detect_bruteforce(test_flows)
    for r in results:
        print(json.dumps(r, indent=2))

    print("\nVerdict by IP:")
    print(json.dumps(bruteforce_verdict_by_ip(test_flows), indent=2))
