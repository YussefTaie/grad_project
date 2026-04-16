"""
behavioral_detectors.py — كاشفات سلوكية للـ Malware والـ Phishing
===================================================================
3 كاشفات مبنية على قواعد (بنفس أسلوب ddos_detector_module.py):

  1. DNSBeaconDetector   — يرصد معدل استعلامات DNS العالي من IP واحد
                           (علامة C2 أو exfiltration عبر DNS)

  2. PortDiversityDetector — يرصد التواصل مع عدد كبير من IPs مختلفة
                             في نافذة زمنية قصيرة (scanning أو phishing kit)

  3. C2BeaconDetector    — يرصد الاتصالات الدورية المنتظمة
                           (انحراف معياري منخفض = اتصال آلي = C2 beacon)

الاستخدام:
  from behavioral_detectors import BehavioralAnalyzer
  analyzer = BehavioralAnalyzer()
  # عند كل تدفق جديد:
  alerts = analyzer.process_flow(flow_dict)
  for alert in alerts:
      print(alert)
"""

import time
import numpy as np
from collections import defaultdict
from config import (
    DNS_QUERY_THRESHOLD,
    PORT_DIVERSITY_THRESHOLD,
    C2_BEACON_STD_THRESHOLD,
    C2_MIN_CONNECTIONS,
)

# نافذة زمنية بالثوانٍ لتقييم السلوك
WINDOW_SEC = 60.0


# ══════════════════════════════════════════════════════════════
# 🔬 الكاشف 1: DNS Beacon Detector
# ══════════════════════════════════════════════════════════════
class DNSBeaconDetector:
    """
    يرصد معدل عالٍ لاستعلامات DNS من IP واحد خلال دقيقة —
    ده ممكن يكون:
      - C2 beacon عبر DNS tunneling
      - Data exfiltration
      - Malware يحاول الاتصال بمنافذ متعددة
    """

    def __init__(self):
        # { src_ip → [(timestamp, query_count)] }
        self._queries: dict = defaultdict(list)

    def record(self, src_ip: str, is_dns: bool = False) -> dict | None:
        """
        سجّل حدث DNS من src_ip.
        يرجع dict تنبيه لو تم الكشف، أو None.
        """
        if not is_dns:
            return None

        now = time.time()
        self._queries[src_ip].append(now)

        # احذف الأحداث اللي خرجت من النافذة
        self._queries[src_ip] = [
            t for t in self._queries[src_ip] if now - t <= WINDOW_SEC
        ]

        count = len(self._queries[src_ip])
        if count >= DNS_QUERY_THRESHOLD:
            return {
                "detector":    "DNSBeacon",
                "src_ip":      src_ip,
                "result":      "⚠️ SUSPICIOUS",
                "attack_type": "🦠 DNS Beacon / Possible C2",
                "detail":      f"{count} DNS queries in last {WINDOW_SEC:.0f}s",
                "confidence":  min(1.0, count / (DNS_QUERY_THRESHOLD * 2)),
            }
        return None


# ══════════════════════════════════════════════════════════════
# 🔬 الكاشف 2: Port/IP Diversity Detector
# ══════════════════════════════════════════════════════════════
class PortDiversityDetector:
    """
    يرصد IP يتواصل مع عدد كبير من IPs وجهة مختلفة في دقيقة —
    ده ممكن يكون:
      - Phishing kit بيتصل بـ C2 servers كتير
      - Network scanning
      - Botnet بيحاول الانتشار
    """

    def __init__(self):
        # { src_ip → [(timestamp, dst_ip)] }
        self._contacts: dict = defaultdict(list)

    def record(self, src_ip: str, dst_ip: str) -> dict | None:
        """
        سجّل اتصال src_ip بـ dst_ip.
        يرجع dict تنبيه لو تم الكشف، أو None.
        """
        now = time.time()
        self._contacts[src_ip].append((now, dst_ip))

        # احذف الأحداث القديمة
        self._contacts[src_ip] = [
            (t, ip) for t, ip in self._contacts[src_ip]
            if now - t <= WINDOW_SEC
        ]

        unique_dsts = len(set(ip for _, ip in self._contacts[src_ip]))
        if unique_dsts >= PORT_DIVERSITY_THRESHOLD:
            return {
                "detector":    "PortDiversity",
                "src_ip":      src_ip,
                "result":      "⚠️ SUSPICIOUS",
                "attack_type": "🔍 Scanning / Phishing Spread",
                "detail":      f"{unique_dsts} unique dst IPs in last {WINDOW_SEC:.0f}s",
                "confidence":  min(1.0, unique_dsts / (PORT_DIVERSITY_THRESHOLD * 2)),
            }
        return None


# ══════════════════════════════════════════════════════════════
# 🔬 الكاشف 3: C2 Beacon Regularity Detector
# ══════════════════════════════════════════════════════════════
class C2BeaconDetector:
    """
    يرصد اتصالات دورية منتظمة من نفس IP لنفس الوجهة —
    البرمجيات الخبيثة بتتصل بـ C2 server كل N ثانية بانتظام شبه كامل،
    معناه الانحراف المعياري للفترات بين الاتصالات لازم يكون منخفض جداً.
    """

    def __init__(self):
        # { (src_ip, dst_ip) → [timestamps] }
        self._connections: dict = defaultdict(list)

    def record(self, src_ip: str, dst_ip: str) -> dict | None:
        """
        سجّل اتصال جديد.
        يرجع dict تنبيه لو تم الكشف، أو None.
        """
        now = time.time()
        pair = (src_ip, dst_ip)
        self._connections[pair].append(now)

        # نحتاج على الأقل C2_MIN_CONNECTIONS نقطة للتقييم
        if len(self._connections[pair]) < C2_MIN_CONNECTIONS:
            return None

        # احذف القديم
        self._connections[pair] = [
            t for t in self._connections[pair]
            if now - t <= WINDOW_SEC * 5  # نافذة أكبر للـ beacon
        ]

        timestamps = sorted(self._connections[pair])
        intervals = [timestamps[i+1] - timestamps[i]
                     for i in range(len(timestamps)-1)]

        if len(intervals) < C2_MIN_CONNECTIONS - 1:
            return None

        mean_interval = float(np.mean(intervals))
        std_interval  = float(np.std(intervals))

        # لو الانحراف المعياري صغير جداً مقارنةً بالمتوسط → اتصال آلي
        if mean_interval > 0 and (std_interval / mean_interval) < C2_BEACON_STD_THRESHOLD:
            return {
                "detector":    "C2Beacon",
                "src_ip":      src_ip,
                "result":      "🚨 ATTACK",
                "attack_type": "🦠 C2 Beacon / Malware Callback",
                "detail": (
                    f"Regular connections every {mean_interval:.1f}s "
                    f"(std={std_interval:.2f}) to {dst_ip}"
                ),
                "confidence":  max(0.0, 1.0 - (std_interval / mean_interval)),
            }
        return None


# ══════════════════════════════════════════════════════════════
# 🧠 BehavioralAnalyzer — واجهة موحّدة للكاشفات الثلاثة
# ══════════════════════════════════════════════════════════════
class BehavioralAnalyzer:
    """
    الاستخدام:
        analyzer = BehavioralAnalyzer()

        for flow in flows:
            alerts = analyzer.process_flow(flow)
            for alert in alerts:
                print(alert)
    """

    def __init__(self):
        self.dns_detector      = DNSBeaconDetector()
        self.diversity_detector = PortDiversityDetector()
        self.c2_detector       = C2BeaconDetector()

    def process_flow(self, flow: dict) -> list[dict]:
        """
        يحلل تدفق واحد ويرجع قائمة بالتنبيهات (فاضية لو مفيش).

        الـ flow dict لازم يحتوي على:
          - "Src IP" أو "Source IP"
          - "Dst IP" أو "Destination IP" أو "dst_ip"
          - "Destination Port" (اختياري)
        """
        alerts = []

        src_ip = (
            flow.get("Src IP") or flow.get("Source IP") or
            flow.get("src_ip") or "unknown"
        )
        dst_ip = (
            flow.get("Dst IP") or flow.get("Destination IP") or
            flow.get("dst_ip") or "unknown"
        )
        dst_port = int(flow.get("Destination Port", 0))

        # ── هل ده استعلام DNS؟ (منفذ 53) ─────────────────────
        is_dns = (dst_port == 53)
        alert = self.dns_detector.record(src_ip, is_dns=is_dns)
        if alert:
            alerts.append(alert)

        # ── تنوع الوجهات ──────────────────────────────────────
        alert = self.diversity_detector.record(src_ip, dst_ip)
        if alert:
            alerts.append(alert)

        # ── انتظام الاتصال (C2 beacon) ────────────────────────
        alert = self.c2_detector.record(src_ip, dst_ip)
        if alert:
            alerts.append(alert)

        return alerts


# ══════════════════════════════════════════════════════════════
# 🧪 اختبار مباشر
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    analyzer = BehavioralAnalyzer()

    print("🧪 اختبار DNS Beacon...")
    for i in range(60):
        alerts = analyzer.process_flow({
            "Src IP": "10.0.0.5",
            "Dst IP": "8.8.8.8",
            "Destination Port": 53,
        })
        for a in alerts:
            print(f"  🚨 {a['detector']}: {a['detail']} — {a['attack_type']}")

    print("\n🧪 اختبار Port Diversity...")
    for i in range(35):
        alerts = analyzer.process_flow({
            "Src IP": "10.0.0.6",
            "Dst IP": f"192.168.1.{i}",
            "Destination Port": 80,
        })
        for a in alerts:
            print(f"  🚨 {a['detector']}: {a['detail']} — {a['attack_type']}")

    print("\n🧪 اختبار C2 Beacon...")
    import time as _time
    for i in range(8):
        alerts = analyzer.process_flow({
            "Src IP": "10.0.0.7",
            "Dst IP": "185.220.101.1",
            "Destination Port": 443,
        })
        for a in alerts:
            print(f"  🚨 {a['detector']}: {a['detail']} — {a['attack_type']}")
        _time.sleep(0.01)  # في الاختبار بنضغط الوقت

    print("\n✅ الاختبار انتهى")
