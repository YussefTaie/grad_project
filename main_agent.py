"""
╔══════════════════════════════════════════════════════════════╗
║              UNIFIED CYBER ATTACK DETECTION AGENT            ║
║                                                              ║
║  Pipeline:                                                   ║
║    Traffic (PCAP / CSV) → Flow Extraction                    ║
║    → DDoS Detection + ML Prediction → Fusion → Decision      ║
║                                                              ║
║  Entry point: python main_agent.py [--mode pcap|csv] [args]  ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import csv
import argparse
import logging
from collections import defaultdict

# ── Encoding fix for Windows terminals ─────────────────────────────────────────
sys.stdout.reconfigure(encoding="utf-8")

# ── Logging setup ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("UnifiedAgent")


# ==============================================================================
# MODULE IMPORTS  (all existing modules stay untouched)
# ==============================================================================

# ML predictor
from predict import predict as ml_predict

# DDoS detector
from ddos_detector_module import detect_ddos_from_flows

# Behavioral detectors (DNS beacon, Port diversity, C2)
from behavioral_detectors import BehavioralAnalyzer

# ── NEW: Modular Attack Detectors ──────────────────────────────────────────────
from brute_force_detector import bruteforce_verdict_by_ip
from malware_detector     import malware_verdict_by_ip
# FIX 1 + FIX 5 — shared, consistent PPS calculation
from flow_utils           import compute_pps


# ==============================================================================
# SECTION 1 — FLOW EXTRACTION
# Reads flows either from an existing CSV or by processing a PCAP on the fly.
# ==============================================================================

def extract_flows_from_pcap(pcap_path: str) -> list[dict]:
    """
    Build per-second windowed flows from a PCAP file.
    Replicates the logic in flow_builder.py without modifying it.
    """
    try:
        from scapy.all import rdpcap, IP, TCP
    except ImportError:
        log.error("Scapy is not installed. Run:  pip install scapy")
        return []

    log.info(f"Reading PCAP: {pcap_path}")
    packets = rdpcap(pcap_path)

    flows = defaultdict(list)

    def get_flow_key(pkt):
        if IP in pkt and TCP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            if (src, sport) < (dst, dport):
                return (src, sport, dst, dport)
            return (dst, dport, src, sport)
        return None

    for pkt in packets:
        key = get_flow_key(pkt)
        if key:
            flows[key].append(pkt)

    log.info(f"Total flows identified: {len(flows)}")

    TIME_WINDOW = 1  # seconds (matches flow_builder.py)
    rows = []

    for key, pkts in flows.items():
        src, sport, dst, dport = key
        pkts = sorted(pkts, key=lambda x: x.time)
        start_time = pkts[0].time
        window = []

        def flush_window(win, s_ip, s_port, d_ip, d_port):
            if not win:
                return
            sizes    = [len(p) for p in win]
            duration = float(win[-1].time - win[0].time)
            rows.append({
                "Src IP":              s_ip,
                "Src Port":            s_port,
                "Dst IP":              d_ip,
                "Dst Port":            d_port,
                "Flow Duration":       duration,
                "Total Packets":       len(win),
                "Total Bytes":         sum(sizes),
                # FIX 1 + FIX 5: use shared compute_pps() with 0.01s floor
                "Packets per Second":  compute_pps(len(win), duration),
                "Bytes per Second":    sum(sizes) / max(duration, 0.01),
            })

        for pkt in pkts:
            if pkt.time - start_time <= TIME_WINDOW:
                window.append(pkt)
            else:
                flush_window(window, src, sport, dst, dport)
                start_time = pkt.time
                window = [pkt]

        flush_window(window, src, sport, dst, dport)  # last window

    log.info(f"Extracted {len(rows)} flow records from PCAP")
    return rows


def load_flows_from_csv(csv_path: str) -> list[dict]:
    """Load pre-built flow records from a CSV file (e.g. flows.csv)."""
    rows = []
    log.info(f"Loading flows from CSV: {csv_path}")
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    log.info(f"Loaded {len(rows)} flow records")
    return rows


# ==============================================================================
# SECTION 2 — DDoS DETECTION  (rule-based, per-IP PPS analysis)
# ==============================================================================

def run_ddos_detection(flows: list[dict]) -> dict[str, str]:
    """
    Run the original DDoS detection logic on the flow list.
    Returns a mapping: { src_ip → "ATTACK" | "NORMAL" }
    """
    log.info("Running DDoS detection...")
    results = detect_ddos_from_flows(flows)
    attack_count = sum(1 for v in results.values() if v == "ATTACK")
    log.info(f"DDoS scan complete — {attack_count} attacking IP(s) found")
    return results


# ==============================================================================
# SECTION 3 — ML PREDICTION  (XGBoost + Isolation Forest)
# ==============================================================================

def run_ml_prediction(flow: dict) -> dict:
    """
    Run the existing ML predict() function (from predict.py) on a single flow.
    Returns the raw result dict: { "result": "...", "confidence": float }
    """
    return ml_predict(flow)


# ==============================================================================
# SECTION 4 — FUSION  (Decision Engine)
# ==============================================================================

def fusion(
    ddos_result:   str,
    brute_result:  str,
    malware_result: str,
    ml_result:     dict,
) -> str:
    """
    Combine all 4 detection signals into one final verdict.

    Priority (hard rules first):
      1. DDoS detector   ATTACK  -> ATTACK
      2. Brute Force     ATTACK  -> ATTACK
      3. Malware         ATTACK  -> ATTACK
      4. ML              ATTACK  -> ATTACK
      5. Malware         SUSPICIOUS or ML SUSPICIOUS -> SUSPICIOUS
      6. Otherwise                -> NORMAL
    """
    ml_label = ml_result.get("result", "").upper()

    if ddos_result == "ATTACK":
        return "ATTACK"

    if brute_result == "ATTACK":
        return "ATTACK"

    if malware_result == "ATTACK":
        return "ATTACK"

    if "ATTACK" in ml_label:
        return "ATTACK"

    if malware_result == "SUSPICIOUS" or "SUSPICIOUS" in ml_label:
        return "SUSPICIOUS"

    return "NORMAL"


# ==============================================================================
# SECTION 5 — MAIN PIPELINE
# ==============================================================================

def run_pipeline(flows: list[dict]):
    """
    Core pipeline:
      flows -> DDoS (bulk) + BruteForce (bulk) + Malware (bulk)
             + ML (per-flow) + Behavioral (per-flow)
             -> fusion -> decision -> output
    """
    if not flows:
        log.warning("No flows to process. Exiting.")
        return

    # ── Step A: Bulk rule-based detectors ──────────────────────────────────────
    ddos_results   = run_ddos_detection(flows)

    log.info("Running Brute Force detection...")
    brute_results  = bruteforce_verdict_by_ip(flows)   # {src_ip -> verdict}
    brute_count    = sum(1 for v in brute_results.values() if v == "ATTACK")
    log.info(f"Brute Force scan complete -- {brute_count} attacking IP(s) found")

    log.info("Running Malware Behavior detection...")
    malware_results = malware_verdict_by_ip(flows)      # {src_ip -> verdict}
    mal_count       = sum(1 for v in malware_results.values() if v == "ATTACK")
    log.info(f"Malware scan complete -- {mal_count} attacking IP(s) found")

    # ── Step B: Behavioral (per-flow, stateful) ────────────────────────────────
    analyzer = BehavioralAnalyzer()

    # ── Step C: Per-flow ML + fusion ───────────────────────────────────────────
    log.info("Starting per-flow ML prediction and fusion...\n")

    summary = {"ATTACK": 0, "SUSPICIOUS": 0, "NORMAL": 0, "ERROR": 0, "BEHAVIORAL": 0}

    for flow in flows:
        src_ip = flow.get("Src IP") or flow.get("Source IP") or "unknown"

        # -- Verdicts for this src_ip from bulk detectors --
        ddos_verdict   = ddos_results.get(src_ip,    "NORMAL")
        brute_verdict  = brute_results.get(src_ip,   "NORMAL")
        malware_verdict = malware_results.get(src_ip, "NORMAL")

        # -- ML verdict for this flow --
        ml_result = run_ml_prediction(flow)

        if "ERROR" in ml_result.get("result", "").upper():
            log.warning(f"[{src_ip}] ML error: {ml_result.get('error')}")
            summary["ERROR"] += 1
            continue

        # -- Fuse all 4 signals --
        final = fusion(ddos_verdict, brute_verdict, malware_verdict, ml_result)

        confidence  = ml_result.get("confidence", 0.0)
        attack_type = ml_result.get("attack_type", "")

        # Annotation: show which detectors fired
        flags = []
        if ddos_verdict    == "ATTACK": flags.append("DDoS")
        if brute_verdict   == "ATTACK": flags.append("BruteForce")
        if malware_verdict in ("ATTACK", "SUSPICIOUS"): flags.append(f"Malware({malware_verdict})")
        flags_str = ",".join(flags) if flags else "-"

        icon = {"ATTACK": "[!!]", "SUSPICIOUS": "[? ]", "NORMAL": "[OK]"}.get(final, "[??]")

        print(
            f"{icon} [{final:<10}]  src={src_ip:<15}  "
            f"flags={flags_str:<25}  type={attack_type:<20}  conf={confidence:.3f}"
        )

        summary[final] = summary.get(final, 0) + 1

        # -- Behavioral (DNS beacon, Port diversity, C2) --
        behavioral_alerts = analyzer.process_flow(flow)
        for alert in behavioral_alerts:
            b_icon = "[!!]" if "ATTACK" in alert["result"] else "[? ]"
            print(
                f"  {b_icon} [BEHAVIORAL]  detector={alert['detector']:<18}  "
                f"{alert['detail']}"
            )
            summary["BEHAVIORAL"] += 1

    # ── Step D: Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  DETECTION SUMMARY")
    print("=" * 70)
    print(f"  [!!] ATTACK           : {summary['ATTACK']}")
    print(f"  [? ] SUSPICIOUS       : {summary['SUSPICIOUS']}")
    print(f"  [OK] NORMAL           : {summary['NORMAL']}")
    print(f"  [~~] BEHAVIORAL ALERTS: {summary['BEHAVIORAL']}")
    print(f"  [XX] ERRORS           : {summary['ERROR']}")
    print("=" * 70)


# ==============================================================================
# SECTION 6 — CLI ENTRY POINT
# ==============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Unified Cyber Attack Detection Agent",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["pcap", "csv"],
        default="csv",
        help=(
            "Input mode:\n"
            "  csv   → read flows from an existing CSV   (default)\n"
            "  pcap  → extract flows from a raw PCAP file"
        ),
    )
    parser.add_argument(
        "--input",
        default="flows.csv",
        help="Path to input file (PCAP or CSV).  Default: flows.csv",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print("\n" + "=" * 60)
    print("  UNIFIED CYBER ATTACK DETECTION AGENT")
    print(f"  Mode  : {args.mode.upper()}")
    print(f"  Input : {args.input}")
    print("=" * 60 + "\n")

    # ── Load / extract flows ───────────────────────────────────────────────────
    if args.mode == "pcap":
        flows = extract_flows_from_pcap(args.input)
    else:
        flows = load_flows_from_csv(args.input)

    # ── Run the unified pipeline ───────────────────────────────────────────────
    run_pipeline(flows)


if __name__ == "__main__":
    main()
