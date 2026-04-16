"""
test_redteam_pipeline.py
Tests the Red Team -> IDS/IPS pipeline integration end-to-end.
Requires the ML API to be running, but falls back to rule-based detection.
"""
import logging, sys
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

from red_team_agent import (
    simulate_bruteforce, simulate_ddos,
    simulate_ransomware, simulate_malware,
    get_results, _print_summary
)
from action_manager import get_all_incidents

print("=" * 60)
print("  RED TEAM -> IDS/IPS INTEGRATION TEST")
print("  (Flows injected into pipeline via run_aggregate)")
print("=" * 60)

print("\n[Wave 1] BruteForce Attack (medium intensity)")
simulate_bruteforce(intensity="medium")

print("\n[Wave 2] DDoS Attack (medium intensity)")
simulate_ddos(intensity="medium")

print("\n[Wave 3] Malware C2 Beaconing (medium intensity)")
simulate_malware(intensity="medium")

print("\n[Wave 4] Ransomware Spread (medium intensity)")
simulate_ransomware(intensity="medium")

print("\n" + "=" * 60)
print("  RESULTS")
print("=" * 60)

_print_summary()

print("\nIncident Registry (non-CLEAN hosts):")
for inc in get_all_incidents():
    print(f"  ip={inc['ip']} status={inc['status']} threat={inc['threat']}")

print("\nDone.")
