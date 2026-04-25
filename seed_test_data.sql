-- =======================================================
-- seed_test_data.sql  —  Insert realistic test data
-- =======================================================
-- Run:
--   psql -U postgres -d ids_system -f seed_test_data.sql
-- =======================================================

-- ── HOSTS ────────────────────────────────────────────────
INSERT INTO hosts (ip, status, first_seen, last_seen) VALUES
    ('185.74.21.9',    'COMPROMISED', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '5 minutes'),
    ('91.214.44.132',  'MONITORED',   NOW() - INTERVAL '1 hour',  NOW() - INTERVAL '10 minutes'),
    ('103.88.201.70',  'ISOLATED',    NOW() - INTERVAL '3 hours', NOW() - INTERVAL '15 minutes'),
    ('45.155.205.19',  'COMPROMISED', NOW() - INTERVAL '90 minutes', NOW() - INTERVAL '8 minutes'),
    ('172.16.90.11',   'SEEN',        NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '2 minutes'),
    ('10.15.4.2',      'MONITORED',   NOW() - INTERVAL '45 minutes', NOW() - INTERVAL '3 minutes')
ON CONFLICT (ip) DO UPDATE SET last_seen = NOW();

-- ── DETECTIONS ───────────────────────────────────────────
INSERT INTO detections (src_ip, result, attack_type, confidence, iso_flag, detected_at) VALUES
    ('185.74.21.9',   'ATTACK',     'DDOS',        0.94, 1, NOW() - INTERVAL '22 minutes'),
    ('91.214.44.132', 'SUSPICIOUS', 'BRUTE_FORCE',  0.76, 1, NOW() - INTERVAL '18 minutes'),
    ('103.88.201.70', 'ATTACK',     'MALWARE',      0.87, 1, NOW() - INTERVAL '16 minutes'),
    ('45.155.205.19', 'ATTACK',     'DDOS',         0.89, 1, NOW() - INTERVAL '13 minutes'),
    ('172.16.90.11',  'NORMAL',     'BENIGN',       0.23, 0, NOW() - INTERVAL '11 minutes'),
    ('10.15.4.2',     'SUSPICIOUS', 'BRUTE_FORCE',  0.68, 0, NOW() - INTERVAL '8 minutes'),
    ('185.74.21.9',   'ATTACK',     'DDOS',         0.96, 1, NOW() - INTERVAL '5 minutes'),
    ('91.214.44.132', 'SUSPICIOUS', 'PORT_SCAN',    0.71, 0, NOW() - INTERVAL '3 minutes');

-- ── FLOWS ────────────────────────────────────────────────
INSERT INTO flows (src_ip, dst_ip, packets, bytes, pps, duration_us, captured_at) VALUES
    ('185.74.21.9',   '10.0.0.14', 9200,  8901220, 28500.0, 2100000, NOW() - INTERVAL '22 minutes'),
    ('91.214.44.132', '10.0.0.27', 1440,   420330,  1850.0,  550000, NOW() - INTERVAL '18 minutes'),
    ('103.88.201.70', '10.0.0.31',  640,   321000,   940.0,  480000, NOW() - INTERVAL '16 minutes'),
    ('45.155.205.19', '10.0.0.52', 6110,  5060980, 15200.0, 1200000, NOW() - INTERVAL '13 minutes'),
    ('172.16.90.11',  '10.0.0.6',   120,    17280,   160.0,   90000, NOW() - INTERVAL '11 minutes'),
    ('10.15.4.2',     '10.0.0.19',  420,   109440,   680.0,  320000, NOW() - INTERVAL '8 minutes'),
    ('185.74.21.9',   '10.0.0.14', 11400,10200000, 31000.0, 2300000, NOW() - INTERVAL '5 minutes');

-- ── ACTIONS ──────────────────────────────────────────────
INSERT INTO actions (ip, action_type, reason, acted_at) VALUES
    ('103.88.201.70', 'BLOCK',    'Malicious SMB execution attempts',       NOW() - INTERVAL '15 minutes'),
    ('185.74.21.9',   'BLOCK',    'Sustained DDOS flood — volumetric',      NOW() - INTERVAL '20 minutes'),
    ('91.214.44.132', 'MONITOR',  'SSH brute-force threshold exceeded',     NOW() - INTERVAL '17 minutes'),
    ('45.155.205.19', 'BLOCK',    'High-confidence DDOS classification',    NOW() - INTERVAL '12 minutes'),
    ('10.15.4.2',     'MONITOR',  'Repeated failed authentication events',  NOW() - INTERVAL '7 minutes');

-- ── BLOCKED_IPS ──────────────────────────────────────────
INSERT INTO blocked_ips (ip, reason, blocked_at) VALUES
    ('103.88.201.70', 'Malicious payload delivery pattern',   NOW() - INTERVAL '15 minutes'),
    ('185.74.21.9',   'Persistent DDOS flood',                NOW() - INTERVAL '20 minutes'),
    ('45.155.205.19', 'High-confidence volumetric attack',    NOW() - INTERVAL '12 minutes')
ON CONFLICT (ip) DO NOTHING;

-- ── ALERTS ───────────────────────────────────────────────
INSERT INTO alerts (ip_address, alert_type, message, is_read, created_at) VALUES
    ('185.74.21.9',   'ATTACK',     'Sustained volumetric DDOS flood detected on edge ingress.',           FALSE, NOW() - INTERVAL '22 minutes'),
    ('91.214.44.132', 'SUSPICIOUS', 'Repeated SSH authentication attempts exceeded threshold (>50/min).',  FALSE, NOW() - INTERVAL '18 minutes'),
    ('103.88.201.70', 'BLOCK',      'Firewall block applied — malicious SMB behavior confirmed.',          TRUE,  NOW() - INTERVAL '15 minutes'),
    ('45.155.205.19', 'ATTACK',     'High-confidence DDOS from external host. Auto-block triggered.',     FALSE, NOW() - INTERVAL '13 minutes'),
    ('172.16.90.11',  'SUSPICIOUS', 'Anomalous east-west traffic burst — internal host under review.',    TRUE,  NOW() - INTERVAL '11 minutes'),
    ('10.15.4.2',     'SUSPICIOUS', 'Brute-force pattern detected. Host placed under active monitoring.', FALSE, NOW() - INTERVAL '7 minutes'),
    ('185.74.21.9',   'ATTACK',     'Second DDOS wave detected from same source. Escalating response.',   FALSE, NOW() - INTERVAL '5 minutes'),
    ('103.88.201.70', 'BLOCK',      'Malware C2 beaconing confirmed. Host fully isolated.',               FALSE, NOW() - INTERVAL '3 minutes');

-- ── Verify ───────────────────────────────────────────────
SELECT 'hosts'       AS tbl, COUNT(*) AS rows FROM hosts
UNION ALL
SELECT 'detections',  COUNT(*) FROM detections
UNION ALL
SELECT 'flows',       COUNT(*) FROM flows
UNION ALL
SELECT 'actions',     COUNT(*) FROM actions
UNION ALL
SELECT 'blocked_ips', COUNT(*) FROM blocked_ips
UNION ALL
SELECT 'alerts',      COUNT(*) FROM alerts;

SELECT 'Seed data inserted successfully.' AS result;
