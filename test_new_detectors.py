"""test_new_detectors.py — quick verification script"""
import json

print("=== Testing brute_force_detector ===")
from brute_force_detector import detect_bruteforce, bruteforce_verdict_by_ip

flows_bf = [
    {"Src IP": "10.0.0.1", "Dst IP": "192.168.1.1",
     "Dst Port": "22", "Total Packets": 2}
    for _ in range(15)
]
bf_results = detect_bruteforce(flows_bf)
print(f"  Brute Force alerts  : {len(bf_results)}")
print(f"  Verdict by IP       : {bruteforce_verdict_by_ip(flows_bf)}")

print()
print("=== Testing malware_detector ===")
from malware_detector import detect_malware, malware_verdict_by_ip

flows_mal = []
for i in range(12):
    flows_mal.append({
        "Src IP": "10.0.0.50", "Dst IP": "185.1.1.1",
        "Total Length of Fwd Packets": 200,
        "Total Fwd Packets": 3, "Total Backward Packets": 1,
    })
flows_mal.append({
    "Src IP": "10.0.0.60", "Dst IP": "8.8.8.8",
    "Total Length of Fwd Packets": 3_000_000,
    "Total Fwd Packets": 500, "Total Backward Packets": 1,
})

mal_results = detect_malware(flows_mal)
print(f"  Malware alerts: {len(mal_results)}")
for a in mal_results:
    print(f"    [{a['result']}] {a['reason']}")
print(f"  Verdict by IP : {malware_verdict_by_ip(flows_mal)}")

print()
print("=== Testing fusion() in main_agent ===")
from main_agent import fusion

cases = [
    ("NORMAL", "ATTACK",    "NORMAL",     {"result": "NORMAL", "confidence": 0.1}, "brute=ATTACK -> ATTACK"),
    ("NORMAL", "NORMAL",    "ATTACK",     {"result": "NORMAL", "confidence": 0.1}, "malware=ATTACK -> ATTACK"),
    ("ATTACK", "NORMAL",    "NORMAL",     {"result": "NORMAL", "confidence": 0.1}, "ddos=ATTACK -> ATTACK"),
    ("NORMAL", "NORMAL",    "SUSPICIOUS", {"result": "NORMAL", "confidence": 0.1}, "malware=SUSPICIOUS -> SUSPICIOUS"),
    ("NORMAL", "NORMAL",    "NORMAL",     {"result": "NORMAL", "confidence": 0.1}, "all NORMAL -> NORMAL"),
]

all_ok = True
for ddos, brute, malware, ml, expected_desc in cases:
    result = fusion(ddos, brute, malware, ml)
    expected_verdict = expected_desc.split("->")[1].strip()
    status = "OK" if result == expected_verdict else "FAIL"
    if status == "FAIL":
        all_ok = False
    print(f"  [{status}] {expected_desc} | got={result}")

print()
if all_ok:
    print("[PASS] All tests passed.")
else:
    print("[FAIL] Some tests failed — check fusion() logic.")
