"""
action.py — Response Engine with Deduplication + Whitelist
===========================================================
التحسينات:
  1. Whitelist  — قائمة IPs لا تُحجب أبداً (gateway، DNS، localhost)
  2. Deduplication — نفس الـ IP مش بيتحجب أكتر من مرة كل COOLDOWN_SEC
  3. Severity Logging — بيسجّل كل إجراء مع الوقت والسبب
"""

import os
import time
import socket
import logging
from collections import defaultdict
from config import DDOS_PPS_THRESHOLD

log = logging.getLogger("ActionEngine")

# ──────────────────────────────────────────────────────────────
# ⏱️ Deduplication cooldown (ثانية)
# ──────────────────────────────────────────────────────────────
COOLDOWN_SEC = 60.0  # منع تكرار الحجب لنفس الـ IP خلال دقيقة

_last_action: dict = defaultdict(float)   # ip -> timestamp آخر إجراء


# ──────────────────────────────────────────────────────────────
# 🛡️ Whitelist — لموش بتحجبها أبداً
# ──────────────────────────────────────────────────────────────
def _build_whitelist() -> set:
    wl = {
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "8.8.8.8",     # Google DNS
        "8.8.4.4",     # Google DNS backup
        "1.1.1.1",     # Cloudflare DNS
    }
    # أضف الـ IP المحلي للجهاز تلقائياً
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        wl.add(local_ip)
    except Exception:
        pass
    # أضف default gateway لو عارفينه
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
            capture_output=True, text=True, timeout=3
        )
        gw = result.stdout.strip()
        if gw:
            wl.add(gw)
            log.info(f"[Whitelist] Gateway detected: {gw}")
    except Exception:
        pass
    return wl


WHITELIST: set = _build_whitelist()


# ──────────────────────────────────────────────────────────────
# ✅ تحقق من الـ Cooldown
# ──────────────────────────────────────────────────────────────
def _is_on_cooldown(ip: str) -> bool:
    now = time.time()
    last = _last_action[ip]
    if last == 0:
        return False
    elapsed = now - last
    if elapsed < COOLDOWN_SEC:
        remaining = COOLDOWN_SEC - elapsed
        log.debug(f"[DEDUP] {ip} still on cooldown ({remaining:.0f}s left)")
        return True
    return False


def _mark_action(ip: str):
    _last_action[ip] = time.time()


# ──────────────────────────────────────────────────────────────
# 🔴 Block IP
# ──────────────────────────────────────────────────────────────
def block_ip(ip: str, reason: str = "ATTACK"):
    if ip in WHITELIST:
        log.warning(f"[WHITELIST] Skipping block for protected IP: {ip}")
        return

    if _is_on_cooldown(ip):
        log.info(f"[DEDUP] Block skipped for {ip} — already acted recently")
        return

    _mark_action(ip)
    log.warning(f"[BLOCK] Blocking {ip} | Reason: {reason}")
    print(f"  >> [BLOCK] {ip} | {reason}")

    rule_name = f"IDS_Block_{ip.replace('.', '_')}"
    os.system(
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}" dir=in action=block remoteip={ip} '
        f'> nul 2>&1'
    )


# ──────────────────────────────────────────────────────────────
# 🟡 Monitor IP
# ──────────────────────────────────────────────────────────────
def monitor_ip(ip: str, reason: str = "SUSPICIOUS"):
    if ip in WHITELIST:
        return

    if _is_on_cooldown(ip):
        return

    _mark_action(ip)
    log.info(f"[MONITOR] Flagging {ip} for monitoring | Reason: {reason}")
    print(f"  >> [MONITOR] {ip} | {reason}")


# ──────────────────────────────────────────────────────────────
# 🟢 Allow IP
# ──────────────────────────────────────────────────────────────
def allow_ip(ip: str):
    pass   # لا إجراء — طبيعي


# ──────────────────────────────────────────────────────────────
# 🧠 Main Decision
# ──────────────────────────────────────────────────────────────
def take_action(result: str, ip: str, attack_type: str = ""):
    """
    يتخذ الإجراء المناسب بناءً على نتيجة التصنيف.

    Args:
        result:      "ATTACK" / "SUSPICIOUS" / "NORMAL" (أو بأي حروف)
        ip:          IP المصدر
        attack_type: نوع الهجوم للـ logging (اختياري)
    """
    label = result.upper()
    reason = attack_type if attack_type else label

    if "ATTACK" in label:
        block_ip(ip, reason=reason)

    elif "SUSPICIOUS" in label:
        monitor_ip(ip, reason=reason)

    else:
        allow_ip(ip)


# ──────────────────────────────────────────────────────────────
# 🔓 Unblock IP (utility)
# ──────────────────────────────────────────────────────────────
def unblock_ip(ip: str):
    """يحذف قاعدة الحجب من Windows Firewall."""
    rule_name = f"IDS_Block_{ip.replace('.', '_')}"
    os.system(f'netsh advfirewall firewall delete rule name="{rule_name}" > nul 2>&1')
    _last_action[ip] = 0   # reset cooldown
    log.info(f"[UNBLOCK] Removed firewall rule for {ip}")
    print(f"  >> [UNBLOCK] {ip}")