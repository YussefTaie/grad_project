import requests
import time
import os
from dotenv import load_dotenv

# تحميل متغيرات البيئة
load_dotenv()

# 🔐 اقرأ المفاتيح من البيئة (مش من الكود)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ALIENVAULT_OTX_KEY = os.getenv("ALIENVAULT_OTX_KEY")

cache = {}

def check_ip_reputation(ip: str) -> int:
    now = time.time()

    # 🧠 Cache لمدة 5 دقائق
    if ip in cache and now - cache[ip]["time"] < 300:
        return cache[ip]["score"]

    score = 0

    # 🔴 AbuseIPDB API
    try:
        res = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 30
            },
            timeout=5
        )
        data = res.json()
        score += data["data"]["abuseConfidenceScore"]
    except Exception as e:
        print("[INTEL] AbuseIPDB error:", e)

    # 🔵 VirusTotal API
    try:
        res = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY
            },
            timeout=5
        )
        data = res.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        # عدد engines اللي قالت malicious
        score += stats.get("malicious", 0) * 10
    except Exception as e:
        print("[INTEL] VirusTotal error:", e)

    # 🟣 AlienVault OTX API
    try:
        res = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={
                "X-OTX-API-KEY": ALIENVAULT_OTX_KEY
            },
            timeout=5
        )
        data = res.json()

        pulses = data.get("pulse_info", {}).get("count", 0)

        if pulses > 0:
            score += min(pulses * 5, 40)
    except Exception as e:
        print("[INTEL] OTX error:", e)

    # 🔥 Normalize النتيجة من 0 → 100
    final_score = min(score, 100)

    cache[ip] = {
        "score": final_score,
        "time": now
    }

    print(f"[INTEL] {ip} → score={final_score}")

    return final_score