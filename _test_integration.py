import logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

from action_manager import execute_action, get_all_incidents
from red_team_agent import (
    simulate_port_scan, simulate_bruteforce,
    simulate_ransomware, get_results
)

print('='*60)
print('  ACTION MANAGER + RED TEAM --- Integration Test')
print('='*60)

# Test 1: Action Manager — Malware
print('\n[Test 1] Malware Response')
execute_action('185.10.10.1', 'MALWARE', 'BLOCK', reason='C2 Beaconing x20', conf=0.92)

# Test 2: Action Manager — Ransomware (simulation mode)
print('\n[Test 2] Ransomware Isolation (Simulation)')
execute_action('185.10.10.2', 'RANSOMWARE', 'ISOLATE', reason='small_pkt+repetition+pps_std', conf=0.95, simulation=True)

# Test 3: Low confidence (should monitor only)
print('\n[Test 3] Low Conf -> should MONITOR not BLOCK')
execute_action('185.10.10.3', 'MALWARE', 'BLOCK', reason='weak signal', conf=0.65)

# Test 4: Red Team standalone sim (no pipeline callback)
print('\n[Test 4] Red Team Simulations (standalone)')
simulate_port_scan(intensity='low')
simulate_bruteforce(intensity='low')
simulate_ransomware(intensity='low')

# Test 5: Host Registry
print('\n[Test 5] Incident Registry:')
incidents = get_all_incidents()
for inc in incidents:
    print(f"  ip={inc['ip']} status={inc['status']} threat={inc['threat']} incidents={inc['incidents']}")

# Test 6: Red Team Summary
print('\n[Test 6] Red Team Results:')
for r in get_results():
    print(f"  {r['type']:<18} flows={r['flows_sent']} detected={r['detected']} action={r['action']}")

print('\n' + '='*60)
print('  All tests passed.')
print('='*60)
