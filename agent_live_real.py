"""
agent_live_real.py  —  Unified Live IDS Agent (Full Integration)
================================================================
Pipeline الكامل على حركة المرور الحية:

  Packets (Scapy)
       ↓
  Stateful Flow Table  (تجميع الحزم في تدفقات)
       ↓
  Completed Flow  (بعد FLOW_TIMEOUT ثانية من السكون)
       ↓ ─────────────────────────────────────────
       │  ① ML API        ← XGBoost + IsoForest
       │  ② BruteForce    ← rule-based (rolling window)
       │  ③ Malware       ← beaconing + exfil + asymmetry
       │  ④ DDoS          ← PPS threshold (rolling window)
       ↓ ─────────────────────────────────────────
  Fusion Engine  (دمج كل الإشارات)
       ↓
  Action Engine  (block / monitor / allow)

Rolling Window:
  آخر ROLLING_WINDOW_SIZE تدفق مكتمل محفوظ في الذاكرة.
  كل ANALYSIS_INTERVAL ثانية بيتشغّل تحليل aggregate على النافذة.
"""

import threading
import time
import numpy as np
import requests
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP

# ── Local modules ─────────────────────────────────────────────
from action import take_action
from config import (
    FLOW_TIMEOUT_SEC,
    MAX_FLOW_PACKETS,
    API_URL,
    DDOS_PPS_THRESHOLD,
    DDOS_MIN_ALERTS,
)
from brute_force_detector import bruteforce_verdict_by_ip
from malware_detector      import malware_verdict_by_ip
from ddos_detector_module  import detect_ddos_from_flows
# FIX 1 + FIX 5 — shared, consistent PPS calculation
from flow_utils            import compute_pps

# ══════════════════════════════════════════════════════════════
# ⚙️  Configuration
# ══════════════════════════════════════════════════════════════
ROLLING_WINDOW_SIZE = 500      # أقصى عدد تدفقات محفوظة في النافذة
ANALYSIS_INTERVAL   = 10.0     # كل كام ثانية يتشغّل الـ aggregate analysis

# ══════════════════════════════════════════════════════════════
# 🗂️  Stateful Flow Table
# ══════════════════════════════════════════════════════════════
flow_table: dict = defaultdict(lambda: {
    "packets":   [],
    "last_seen": 0.0,
    "src_ip":    None,
    "dst_ip":    None,
    "src_port":  None,
    "dst_port":  None,
})
flow_lock = threading.Lock()

# Rolling window of completed flows (shared between threads)
_rolling_window: deque = deque(maxlen=ROLLING_WINDOW_SIZE)
_window_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════
# 🔑  Flow Key (bidirectional)
# ══════════════════════════════════════════════════════════════
def get_flow_key(pkt):
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
    if (src, sport) < (dst, dport):
        return (src, sport, dst, dport), src, dst
    return (dst, dport, src, sport), src, dst


# ══════════════════════════════════════════════════════════════
# 📦  Per-Packet Data Extraction
# ══════════════════════════════════════════════════════════════
def parse_packet(pkt, flow_src_ip: str) -> dict:
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
    return {"time": float(pkt.time), "size": size,
            "direction": "fwd" if is_fwd else "bwd", **flags}


# ══════════════════════════════════════════════════════════════
# 🧮  Flow Feature Computation  (CICIDS-compatible)
# ══════════════════════════════════════════════════════════════
def compute_flow_features(flow_data: dict) -> dict | None:
    pkts = flow_data["packets"]
    if not pkts:
        return None

    times = [p["time"] for p in pkts]
    sizes = [p["size"] for p in pkts]
    fwd   = [p for p in pkts if p["direction"] == "fwd"]
    bwd   = [p for p in pkts if p["direction"] == "bwd"]

    dur_us = (times[-1] - times[0]) * 1_000_000 if len(times) > 1 else 1.0
    if dur_us == 0:
        dur_us = 1.0

    iats     = [times[i+1] - times[i] for i in range(len(times)-1)]
    fwd_sz   = [p["size"] for p in fwd]
    bwd_sz   = [p["size"] for p in bwd]

    def safe_mean(lst): return float(np.mean(lst)) if lst else 0.0
    def safe_std(lst):  return float(np.std(lst))  if lst else 0.0
    def safe_max(lst):  return float(max(lst))      if lst else 0.0
    def safe_min(lst):  return float(min(lst))      if lst else 0.0

    return {
        # identifiers (for aggregate detectors)
        "Src IP":   flow_data["src_ip"],
        "Dst IP":   flow_data["dst_ip"],
        "Src Port": flow_data["src_port"],
        "Dst Port": flow_data["dst_port"],
        # CICIDS features
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
        # FIX 1 + FIX 5: use shared compute_pps() with 0.01s floor
        # (was: len(pkts) / max(dur_us / 1e6, 1e-6)  → could reach 1,000,000)
        "Packets per Second": compute_pps(len(pkts), dur_us / 1_000_000),
        "Total Packets":      len(pkts),
        "Total Bytes":        sum(sizes),
    }


# ══════════════════════════════════════════════════════════════
# 🧠  Fusion Engine  (دمج كل الإشارات)
# ══════════════════════════════════════════════════════════════
def fusion(
    ml_result:      dict,
    ddos_verdict:   str,
    brute_verdict:  str,
    malware_verdict: str,
) -> tuple[str, str]:
    """
    يدمج كل الإشارات ويرجع (final_verdict, reason).
    الأولوية: DDoS > BruteForce > Malware > ML
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
        return "SUSPICIOUS", f"ML:{ml_type}" if "SUSPICIOUS" in ml_label else "Malware(Suspicious)"

    return "NORMAL", "BENIGN"


# ══════════════════════════════════════════════════════════════
# 📡  Single-Flow Processing  (ML API + per-flow action)
# ══════════════════════════════════════════════════════════════
def process_completed_flow(flow_key, flow_data: dict):
    """
    يُشغَّل لكل تدفق مكتمل:
      1. يحسب الـ feature vector
      2. يبعته للـ ML API
      3. يضيفه للـ rolling window
      4. يحفظ الـ ML verdict للـ fusion في الـ aggregate thread
    """
    features = compute_flow_features(flow_data)
    if not features:
        return

    src_ip = flow_data["src_ip"]

    # ── إضافة للـ rolling window ──────────────────────────────
    with _window_lock:
        _rolling_window.append(features)

    # ── ML API ────────────────────────────────────────────────
    try:
        resp = requests.post(API_URL, json=features, timeout=3)
        if resp.status_code != 200:
            return
        ml_result = resp.json()
    except Exception:
        return

    # ── Verdict من الـ ML فقط (aggregate يكمّل الباقي) ────────
    ml_label    = ml_result.get("result", "NORMAL")
    attack_type = ml_result.get("attack_type", "")
    confidence  = ml_result.get("confidence", 0.0)

    icon = "[OK]"
    if "ATTACK" in ml_label.upper():
        icon = "[!!]"
    elif "SUSPICIOUS" in ml_label.upper():
        icon = "[? ]"

    print(
        f"  {icon} ML  src={src_ip:<15}  "
        f"type={attack_type:<22}  conf={confidence:.3f}"
    )

    # اتخذ إجراء فوري لو ML قالت ATTACK بثقة عالية
    if "ATTACK" in ml_label.upper() and confidence > 0.85:
        take_action(ml_label, src_ip, attack_type=attack_type)


# ══════════════════════════════════════════════════════════════
# 🔁  Aggregate Analysis Thread  (كل ANALYSIS_INTERVAL ثانية)
# ══════════════════════════════════════════════════════════════
def aggregate_analysis_loop():
    """
    Thread يشتغل كل ANALYSIS_INTERVAL ثانية ويحلل الـ rolling window
    باستخدام:
      - brute_force_detector
      - malware_detector
      - ddos_detector_module
    ثم يتخذ إجراء على كل IP مشبوه.
    """
    while True:
        time.sleep(ANALYSIS_INTERVAL)

        with _window_lock:
            window = list(_rolling_window)

        if not window:
            continue

        print(f"\n{'='*60}")
        print(f"  [~] Aggregate Analysis  ({len(window)} flows in window)")
        print(f"{'='*60}")

        # ── DDoS ─────────────────────────────────────────────
        ddos_verdicts   = detect_ddos_from_flows(window)

        # ── Brute Force ───────────────────────────────────────
        brute_verdicts  = bruteforce_verdict_by_ip(window)

        # ── Malware ───────────────────────────────────────────
        malware_verdicts = malware_verdict_by_ip(window)

        # ── Collect all IPs seen in this window ───────────────
        all_ips = set()
        for f in window:
            ip = f.get("Src IP") or f.get("Source IP", "unknown")
            all_ips.add(ip)

        acted = set()
        for ip in all_ips:
            ddos_v   = ddos_verdicts.get(ip,    "NORMAL")
            brute_v  = brute_verdicts.get(ip,   "NORMAL")
            malware_v = malware_verdicts.get(ip, "NORMAL")

            # Fuse rule-based only (ML already acted per-flow)
            dummy_ml = {"result": "NORMAL", "confidence": 0.0}
            final, reason = fusion(dummy_ml, ddos_v, brute_v, malware_v)

            if final in ("ATTACK", "SUSPICIOUS"):
                flags = []
                if ddos_v    == "ATTACK": flags.append("DDoS")
                if brute_v   == "ATTACK": flags.append("BruteForce")
                if malware_v in ("ATTACK", "SUSPICIOUS"):
                    flags.append(f"Malware({malware_v})")
                flags_str = "+".join(flags) or reason

                icon = "[!!]" if final == "ATTACK" else "[? ]"
                print(
                    f"  {icon} [{final:<10}]  src={ip:<16}  "
                    f"detectors={flags_str}"
                )
                take_action(final, ip, attack_type=flags_str)
                acted.add(ip)

        if not acted:
            print("  [OK] No aggregate threats detected in this window.")
        print()


# ══════════════════════════════════════════════════════════════
# ⏰  Flow Timeout Flusher  (يُرسل التدفقات المنتهية)
# ══════════════════════════════════════════════════════════════
def flow_timeout_flusher():
    while True:
        time.sleep(1.0)
        now = time.time()
        expired = []

        with flow_lock:
            for key, flow in flow_table.items():
                if flow["last_seen"] > 0 and (now - flow["last_seen"]) >= FLOW_TIMEOUT_SEC:
                    expired.append((key, dict(flow)))

        for key, snapshot in expired:
            process_completed_flow(key, snapshot)
            with flow_lock:
                flow_table.pop(key, None)


# ══════════════════════════════════════════════════════════════
# 📥  Packet Handler
# ══════════════════════════════════════════════════════════════
def on_packet(pkt):
    key, src_ip, dst_ip = get_flow_key(pkt)
    if key is None:
        return

    pkt_data = parse_packet(pkt, src_ip)

    with flow_lock:
        flow = flow_table[key]
        if flow["src_ip"] is None:
            flow["src_ip"]   = src_ip
            flow["dst_ip"]   = dst_ip
            flow["src_port"] = key[1]
            flow["dst_port"] = key[3]

        flow["packets"].append(pkt_data)
        flow["last_seen"] = pkt_data["time"]

        if len(flow["packets"]) >= MAX_FLOW_PACKETS:
            snapshot = dict(flow)
            flow_table.pop(key, None)

    if len(flow_table.get(key, {}).get("packets", [])) == 0:
        # تم المسح داخل الـ lock → شغّل في thread منفصل
        threading.Thread(
            target=process_completed_flow,
            args=(key, snapshot),
            daemon=True,
        ).start()


# ══════════════════════════════════════════════════════════════
# 🚀  Entry Point
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  [*] Unified Live IDS Agent — Full Integration")
    print(f"  Flow Timeout    : {FLOW_TIMEOUT_SEC}s")
    print(f"  Max Pkts/Flow   : {MAX_FLOW_PACKETS}")
    print(f"  Analysis Window : {ROLLING_WINDOW_SIZE} flows")
    print(f"  Analysis Every  : {ANALYSIS_INTERVAL}s")
    print(f"  ML API          : {API_URL}")
    print("=" * 60)
    print()
    print("  Active Detectors:")
    print("    [1] ML (XGBoost + IsoForest)  <- per completed flow")
    print("    [2] DDoS (PPS rule)           <- every 10s on window")
    print("    [3] Brute Force (attempts)    <- every 10s on window")
    print("    [4] Malware (beacon+exfil)    <- every 10s on window")
    print()

    # Thread 1 — flush expired flows
    t1 = threading.Thread(target=flow_timeout_flusher, daemon=True)
    t1.start()

    # Thread 2 — aggregate analysis (BruteForce + Malware + DDoS)
    t2 = threading.Thread(target=aggregate_analysis_loop, daemon=True)
    t2.start()

    # Main thread — packet capture
    print("[*] Sniffing on all interfaces... (Ctrl+C to stop)\n")
    sniff(filter="ip", prn=on_packet, store=False)