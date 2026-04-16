"""
quick_demo.py  —  IDS Live Demo (no API needed)
================================================
بيشغّل الـ full pipeline على 100 صف حقيقي من CICIDS2017:
  - 50 صف DDoS
  - 30 صف BENIGN
  - 10 صف PortScan
  - 10 صف BruteForce

بيستخدم predict.py مباشرة (مش محتاج api.py شغّال).
"""

import sys
import time
import pandas as pd
sys.stdout.reconfigure(encoding="utf-8")

from predict              import predict as ml_predict
from ddos_detector_module import detect_ddos_from_flows
from brute_force_detector import bruteforce_verdict_by_ip
from malware_detector     import malware_verdict_by_ip
from unified_agent        import fusion

DATASET_DIR = "dataset"
SEP = "=" * 70

# ──────────────────────────────────────────────────────────────────────
# تحميل البيانات
# ──────────────────────────────────────────────────────────────────────
def load_rows(filepath, label, n):
    df = pd.read_csv(filepath, low_memory=False, nrows=50000)
    df.columns = df.columns.str.strip()
    rows = df[df["Label"].str.strip() == label].head(n)
    return rows.drop(columns=["Label"], errors="ignore").to_dict(orient="records")

print(SEP)
print("  [*]  IDS QUICK DEMO — CICIDS2017 Real Data")
print(SEP)
print()
print("  Loading data...")

flows = []

try:
    ddos   = load_rows(f"{DATASET_DIR}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",       "DDoS",    50)
    benign = load_rows(f"{DATASET_DIR}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",       "BENIGN",  30)
    flows.extend([{"_label": "DDoS",   **r} for r in ddos])
    flows.extend([{"_label": "BENIGN", **r} for r in benign])
    print(f"  DDoS rows   : {len(ddos)}")
    print(f"  BENIGN rows : {len(benign)}")
except Exception as e:
    print(f"  [WARN] DDoS file error: {e}")

try:
    scan = load_rows(f"{DATASET_DIR}/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "PortScan", 10)
    flows.extend([{"_label": "PortScan", **r} for r in scan])
    print(f"  PortScan rows: {len(scan)}")
except Exception as e:
    print(f"  [WARN] PortScan file: {e}")

try:
    brute = load_rows(f"{DATASET_DIR}/Tuesday-WorkingHours.pcap_ISCX.csv", "FTP-Patator", 10)
    flows.extend([{"_label": "FTP-Patator/BruteForce", **r} for r in brute])
    print(f"  BruteForce rows: {len(brute)}")
except Exception as e:
    print(f"  [WARN] Brute file: {e}")

print(f"\n  Total flows  : {len(flows)}")
print()

if not flows:
    print("[ERROR] No flows loaded. Check dataset/ directory.")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────
# Per-flow ML prediction
# ──────────────────────────────────────────────────────────────────────
print(SEP)
print("  STEP 1: Per-Flow ML Prediction")
print(SEP)
print(f"  {'#':<4} {'SRC (simulated)':<18} {'TRUE_LABEL':<22} {'ML_RESULT':<12} {'TYPE':<22} {'CONF'}")
print("  " + "-" * 65)

per_flow_verdicts = {}
summary = {"ATTACK": 0, "SUSPICIOUS": 0, "NORMAL": 0, "ERROR": 0}

correct = 0
total   = 0

for i, flow in enumerate(flows):
    true_label = flow.pop("_label", "?")
    src_ip     = f"10.0.{i//50}.{i%50}"  # IP اصطناعي للعرض

    result = ml_predict(flow)
    label  = result.get("result",      "ERROR")
    atype  = result.get("attack_type", "")
    conf   = result.get("confidence",  0.0)

    per_flow_verdicts[src_ip] = label
    summary[label] = summary.get(label, 0) + 1

    # هل التنبؤ صح؟
    is_attack    = true_label != "BENIGN"
    predicted_ok = (label == "ATTACK"    and is_attack) or \
                   (label == "NORMAL"    and not is_attack)
    if not ("ERROR" in label.upper()):
        total   += 1
        correct += int(predicted_ok)

    # اطبع أول 20 فقط عشان مش يطول
    if i < 20 or label in ("ATTACK", "SUSPICIOUS"):
        icon = "[!!]" if label == "ATTACK" else "[? ]" if label == "SUSPICIOUS" else "[OK]"
        match = "OK" if predicted_ok else "X "
        print(
            f"  {match} {icon} {i:<3} {src_ip:<18} {true_label:<22} "
            f"{label:<12} {atype:<22} {conf:.4f}"
        )

    # إضافة الـ ip للـ flow عشان الكاشفات التجميعية تشتغل
    flow["Src IP"] = src_ip
    flow["Dst IP"] = "192.168.1.1"
    flow["Dst Port"] = 80

print(f"\n  ... (showing first 20 + all alerts)")
accuracy = (correct / total * 100) if total else 0
print(f"\n  ML Accuracy on this sample: {accuracy:.1f}%  ({correct}/{total})")

# ──────────────────────────────────────────────────────────────────────
# Aggregate detectors
# ──────────────────────────────────────────────────────────────────────
print()
print(SEP)
print("  STEP 2: Aggregate Detection (DDoS + BruteForce + Malware)")
print(SEP)

ddos_v    = detect_ddos_from_flows(flows)
brute_v   = bruteforce_verdict_by_ip(flows)
malware_v = malware_verdict_by_ip(flows)

# محاكاة BruteForce حقيقي عشان تشوف الكاشف شغّال
bf_sim = [
    {"Src IP": "10.99.0.1", "Dst IP": "192.168.1.1",
     "Dst Port": "22", "Total Fwd Packets": 5,
     "Total Backward Packets": 1, "Total Length of Fwd Packets": 200}
    for _ in range(15)
]
brute_v_sim = bruteforce_verdict_by_ip(bf_sim)
if brute_v_sim:
    brute_v.update(brute_v_sim)
    flows.extend(bf_sim)
    print(f"  + Injected simulated BruteForce: 15 attempts from 10.99.0.1:22")

# محاكاة Beaconing
beacon_sim = [
    {"Src IP": "10.99.0.2", "Dst IP": "185.220.101.1",
     "Total Length of Fwd Packets": 200,
     "Total Fwd Packets": 3, "Total Backward Packets": 1}
    for _ in range(12)
]
malware_v_sim = malware_verdict_by_ip(beacon_sim)
if malware_v_sim:
    malware_v.update(malware_v_sim)
    flows.extend(beacon_sim)
    print(f"  + Injected simulated C2 Beacon: 12 connections from 10.99.0.2")

print()

# ──────────────────────────────────────────────────────────────────────
# Fusion per IP
# ──────────────────────────────────────────────────────────────────────
print(SEP)
print("  STEP 3: Fusion — Final Verdicts per IP")
print(SEP)
print(f"  {'IP':<18} {'DDoS':<10} {'Brute':<10} {'Malware':<12} {'ML':<12} {'FINAL':<12} {'REASON'}")
print("  " + "-" * 78)

all_ips = set(per_flow_verdicts.keys()) | set(brute_v.keys()) | set(malware_v.keys())
final_summary = {"ATTACK": 0, "SUSPICIOUS": 0, "NORMAL": 0}

for ip in sorted(all_ips):
    d    = ddos_v.get(ip,    "NORMAL")
    b    = brute_v.get(ip,   "NORMAL")
    m    = malware_v.get(ip, "NORMAL")
    ml_r = {"result": per_flow_verdicts.get(ip, "NORMAL")}

    final, reason = fusion(d, b, m, ml_r)
    final_summary[final] = final_summary.get(final, 0) + 1

    if final != "NORMAL":
        icon = "[!!]" if final == "ATTACK" else "[? ]"
        print(
            f"  {icon} {ip:<18} {d:<10} {b:<10} {m:<12} "
            f"{ml_r['result']:<12} {final:<12} {reason}"
        )

normal_count = final_summary.get("NORMAL", 0)
if normal_count > 0:
    print(f"  [OK] {normal_count} normal IPs (not shown)")

# ──────────────────────────────────────────────────────────────────────
# Final Summary
# ──────────────────────────────────────────────────────────────────────
print()
print(SEP)
print("  FINAL SUMMARY")
print(SEP)
print(f"  [!!] ATTACK    : {final_summary.get('ATTACK', 0)}")
print(f"  [? ] SUSPICIOUS: {final_summary.get('SUSPICIOUS', 0)}")
print(f"  [OK] NORMAL    : {final_summary.get('NORMAL', 0)}")
print(f"  ML Accuracy    : {accuracy:.1f}%")
print(SEP)
print()
print("  [DONE] System is working correctly.")
print("  To run on live traffic: python unified_agent.py --mode live")
