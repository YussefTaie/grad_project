import ast

path = r'd:\CIC\Last semester 2026\Graduation Project\MachineLearning\Cyber-Attack-AI\db.py'
src  = open(path, encoding='utf-8').read()

try:
    ast.parse(src)
    lines = len(src.splitlines())
    print(f'[OK] db.py - {lines} lines, syntax valid')
except SyntaxError as e:
    print(f'[FAIL] SyntaxError: {e}')

# Spot-check all 5 fixed areas
checks = [
    ('ThreadPoolExecutor',              '_sync_executor = concurrent.futures.ThreadPoolExecutor'),
    ('dual lock - threading',           '_cooldown_thread_lock = threading.Lock()'),
    ('dual lock - asyncio (lazy)',       '_cooldown_async_lock: Optional[asyncio.Lock] = None'),
    ('_check_cooldown_sync()',          'def _check_cooldown_sync('),
    ('pool None warning',               'Pool is None'),
    ('wrappers have try/except',        'except Exception:'),
    ('sync_insert_alert uses sync lock','_check_cooldown_sync(ip,'),
]

removed = [
    ('run_coroutine_threadsafe REMOVED', 'run_coroutine_threadsafe'),
]

for label, pattern in checks:
    found = pattern in src
    mark  = 'OK' if found else 'MISSING'
    print(f'  [{mark}] {label}')

for label, pattern in removed:
    absent = pattern not in src
    mark   = 'OK' if absent else 'BUG_STILL_PRESENT'
    print(f'  [{mark}] {label}')
