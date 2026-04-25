import re

sql_path = r'd:\CIC\Last semester 2026\Graduation Project\MachineLearning\Cyber-Attack-AI\db.sql'
db_path  = r'd:\CIC\Last semester 2026\Graduation Project\MachineLearning\Cyber-Attack-AI\db.py'

sql = open(sql_path, encoding='utf-8').read()
db  = open(db_path,  encoding='utf-8').read()

print('=== db.sql statistics ===')
tables  = re.findall(r'CREATE TABLE IF NOT EXISTS (\w+)', sql)
indexes = re.findall(r'CREATE INDEX IF NOT EXISTS (\w+)', sql)
print(f'  Tables  : {len(tables)} -> {tables}')
print(f'  Indexes : {len(indexes)}')
for idx in indexes:
    print(f'    {idx}')

print()
print('=== Compatibility: db.py queries vs db.sql schema ===')

checks = [
    # label,                           pattern in db.sql
    ('hosts.ip column exists',         'ip         TEXT'),
    ('hosts UNIQUE(ip)',               'hosts_ip_unique UNIQUE (ip)'),
    ('hosts default SEEN',            "DEFAULT 'SEEN'"),
    ('flows.duration_us',              'duration_us DOUBLE PRECISION'),
    ('flows.captured_at',              'captured_at TIMESTAMP'),
    ('flows.bytes BIGINT',             'bytes       BIGINT'),
    ('detections.detected_at',         'detected_at TIMESTAMP'),
    ('actions.ip column (not ip_addr)','    ip          TEXT'),
    ('actions.acted_at',               'acted_at    TIMESTAMP'),
    ('blocked_ips.ip column',          '    ip         TEXT'),
    ('blocked_ips UNIQUE(ip)',         'blocked_ips_ip_unique UNIQUE (ip)'),
    ('alerts.ip_address column',       'ip_address  TEXT'),
    ('alerts.is_read default FALSE',   'DEFAULT FALSE'),
    ('idx_alerts_created_at',          'idx_alerts_created_at'),
    ('idx_alerts_ip',                  'idx_alerts_ip'),
    ('idx_alerts_type',                'idx_alerts_type'),
    ('idx_alerts_unread',              'idx_alerts_unread'),
    ('idx_flows_src_ip',               'idx_flows_src_ip'),
    ('idx_flows_dst_ip',               'idx_flows_dst_ip'),
    ('idx_detections_src_ip',          'idx_detections_src_ip'),
    ('IF NOT EXISTS on all tables',    'CREATE TABLE IF NOT EXISTS'),
    ('ANALYZE at end',                 'ANALYZE alerts'),
]

all_ok = True
for label, pattern in checks:
    found = pattern in sql
    mark  = 'OK' if found else 'MISSING'
    if not found:
        all_ok = False
    print(f'  [{mark:^7}] {label}')

print()
print('RESULT:', 'ALL COMPATIBLE' if all_ok else 'FIX REQUIRED')
