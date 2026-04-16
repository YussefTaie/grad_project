"""
test_suite.py  —  Comprehensive IDS Test Suite
===============================================
الاختبارات:
  1.  Unit  — brute_force_detector
  2.  Unit  — malware_detector
  3.  Unit  — behavioral_detectors
  4.  Unit  — compute_features (flow feature extraction)
  5.  Unit  — fusion logic  (unified_agent + main_agent)
  6.  Unit  — action engine  (whitelist + dedup)
  7.  Integ — CSV mode       (one-shot analysis on sample data)
  8.  Integ — API health     (يحتاج api.py شغّال)
  9.  Integ — API predict    (يحتاج api.py شغّال)
  10. Integ — Full pipeline  (CSV + API end-to-end)

الاستخدام:
  python test_suite.py             # كل الاختبارات
  python test_suite.py -v          # verbose
  python test_suite.py TestFusion  # فئة واحدة بس
"""

import sys
import os
import csv
import json
import time
import unittest
import tempfile
import importlib

# ── Encoding fix ──────────────────────────────────────────────
sys.stdout.reconfigure(encoding="utf-8")

# ── Paths ─────────────────────────────────────────────────────
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════

def _make_flows(src, dst, port, count):
    """إنشاء count تدفق من src→dst:port."""
    return [
        {"Src IP": src, "Dst IP": dst, "Dst Port": port,
         "Total Packets": 5, "Total Bytes": 500,
         "Total Fwd Packets": 4, "Total Backward Packets": 1,
         "Total Length of Fwd Packets": 400,
         "Flow Duration": 0.5}
        for _ in range(count)
    ]

def _make_pkt_data(n_fwd=10, n_bwd=5, syn=3, fin=1, ack=10,
                   src="10.0.0.1", dst="192.168.1.1",
                   sport=12345, dport=80):
    """بيانات flow خام (قبل compute_features)."""
    now = time.time()
    pkts = []
    for i in range(n_fwd):
        pkts.append({"time": now + i*0.1, "size": 100,
                     "direction": "fwd",
                     "SYN": i < syn, "FIN": i < fin,
                     "ACK": i < ack, "RST": False,
                     "PSH": False, "URG": False})
    for i in range(n_bwd):
        pkts.append({"time": now + (n_fwd + i)*0.1, "size": 60,
                     "direction": "bwd",
                     "SYN": False, "FIN": False,
                     "ACK": True, "RST": False,
                     "PSH": False, "URG": False})
    return {
        "src_ip": src, "dst_ip": dst,
        "src_port": sport, "dst_port": dport,
        "packets": pkts,
    }


# ══════════════════════════════════════════════════════════════
# 1. TEST — BRUTE FORCE DETECTOR
# ══════════════════════════════════════════════════════════════
class TestBruteForceDetector(unittest.TestCase):

    def setUp(self):
        from brute_force_detector import detect_bruteforce, bruteforce_verdict_by_ip
        self.detect     = detect_bruteforce
        self.verdict    = bruteforce_verdict_by_ip

    def test_attack_detected_above_threshold(self):
        """15 flows على نفس src/dst/port → ATTACK"""
        flows = _make_flows("10.0.0.1", "192.168.1.1", "22", 15)
        results = self.detect(flows)
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0]["result"], "ATTACK")

    def test_normal_below_threshold(self):
        """5 flows فقط → لا alerts"""
        flows = _make_flows("10.0.0.2", "192.168.1.2", "80", 5)
        results = self.detect(flows)
        self.assertEqual(len(results), 0)

    def test_verdict_by_ip_attack(self):
        """bruteforce_verdict_by_ip يرجع ATTACK للـ IP المهاجم"""
        flows = _make_flows("10.0.0.99", "192.168.1.1", "22", 20)
        verdicts = self.verdict(flows)
        self.assertEqual(verdicts.get("10.0.0.99"), "ATTACK")

    def test_multiple_sources(self):
        """مهاجم + مستخدم طبيعي في نفس المجموعة"""
        bad  = _make_flows("10.0.0.1", "192.168.1.1", "22", 15)
        good = _make_flows("10.0.0.2", "192.168.1.1", "80", 3)
        verdicts = self.verdict(bad + good)
        self.assertEqual(verdicts.get("10.0.0.1"), "ATTACK")
        self.assertIsNone(verdicts.get("10.0.0.2"))   # مش موجود = NORMAL

    def test_different_ports_not_combined(self):
        """نفس الـ src ولكن ports مختلفة → مش بتتجمع في نفس المجموعة"""
        flows = []
        for port in range(10):
            flows += _make_flows("10.0.0.5", "192.168.1.1", str(port), 2)
        # كل port عنده 2 محاولة فقط < threshold=10
        results = self.detect(flows)
        self.assertEqual(len(results), 0)


# ══════════════════════════════════════════════════════════════
# 2. TEST — MALWARE DETECTOR
# ══════════════════════════════════════════════════════════════
class TestMalwareDetector(unittest.TestCase):

    def setUp(self):
        from malware_detector import detect_malware, malware_verdict_by_ip
        self.detect  = detect_malware
        self.verdict = malware_verdict_by_ip

    def test_beaconing_attack(self):
        """12 اتصال من نفس src→dst → Beaconing ATTACK"""
        flows = [
            {"Src IP": "10.0.0.50", "Dst IP": "185.220.1.1",
             "Total Length of Fwd Packets": 200,
             "Total Fwd Packets": 3, "Total Backward Packets": 2}
            for _ in range(12)
        ]
        results = self.detect(flows)
        beacon = [r for r in results if "Beaconing" in r["reason"]]
        self.assertTrue(len(beacon) > 0)
        self.assertEqual(beacon[0]["result"], "ATTACK")

    def test_beaconing_suspicious(self):
        """7 اتصالات من نفس src→dst → SUSPICIOUS (بين 5 و 10)"""
        flows = [
            {"Src IP": "10.0.0.51", "Dst IP": "185.220.1.2",
             "Total Length of Fwd Packets": 200,
             "Total Fwd Packets": 3, "Total Backward Packets": 2}
            for _ in range(7)
        ]
        results = self.detect(flows)
        beacon = [r for r in results if "Beaconing" in r["reason"]]
        self.assertTrue(len(beacon) > 0)
        self.assertEqual(beacon[0]["result"], "SUSPICIOUS")

    def test_exfiltration_attack(self):
        """3MB outbound → Exfiltration ATTACK"""
        flows = [{
            "Src IP": "10.0.0.60", "Dst IP": "8.8.8.8",
            "Total Length of Fwd Packets": 3_000_000,
            "Total Fwd Packets": 500, "Total Backward Packets": 1,
        }]
        results = self.detect(flows)
        exfil = [r for r in results if "Exfiltration" in r.get("reason", "")]
        self.assertTrue(len(exfil) > 0)
        self.assertEqual(exfil[0]["result"], "ATTACK")

    def test_asymmetry_suspicious(self):
        """نسبة fwd/bwd = 200 → SUSPICIOUS"""
        flows = [{
            "Src IP": "10.0.0.70", "Dst IP": "192.168.1.1",
            "Total Length of Fwd Packets": 5000,
            "Total Fwd Packets": 200, "Total Backward Packets": 1,
        }]
        results = self.detect(flows)
        asym = [r for r in results if "Asymmetric" in r.get("reason", "")]
        self.assertTrue(len(asym) > 0)
        self.assertEqual(asym[0]["result"], "SUSPICIOUS")

    def test_normal_traffic(self):
        """حركة مرور طبيعية → لا alerts"""
        flows = [
            {"Src IP": "10.0.0.1", "Dst IP": "8.8.8.8",
             "Total Length of Fwd Packets": 1000,
             "Total Fwd Packets": 10, "Total Backward Packets": 8}
            for _ in range(3)
        ]
        results = self.detect(flows)
        attacks = [r for r in results if r["result"] == "ATTACK"]
        self.assertEqual(len(attacks), 0)

    def test_verdict_worst_case(self):
        """malware_verdict_by_ip يرجع أشد حكم لو IP ظهر في أكثر من نمط"""
        flows = []
        # Beaconing
        for _ in range(12):
            flows.append({"Src IP": "10.0.0.88", "Dst IP": "185.1.1.1",
                         "Total Length of Fwd Packets": 200,
                         "Total Fwd Packets": 3, "Total Backward Packets": 1})
        # Exfiltration
        flows.append({"Src IP": "10.0.0.88", "Dst IP": "8.8.8.8",
                      "Total Length of Fwd Packets": 3_000_000,
                      "Total Fwd Packets": 500, "Total Backward Packets": 1})
        verdicts = self.verdict(flows)
        self.assertEqual(verdicts.get("10.0.0.88"), "ATTACK")


# ══════════════════════════════════════════════════════════════
# 3. TEST — BEHAVIORAL DETECTORS
# ══════════════════════════════════════════════════════════════
class TestBehavioralDetectors(unittest.TestCase):

    def setUp(self):
        from behavioral_detectors import BehavioralAnalyzer
        self.Analyzer = BehavioralAnalyzer

    def test_dns_beaconing(self):
        """أكثر من 50 استعلام DNS → تنبيه"""
        analyzer = self.Analyzer()
        alerts = []
        for i in range(60):
            flow = {
                "Src IP": "10.0.0.1",
                "Dst Port": 53,
                "Destination Port": 53,
                "Protocol": 17,
            }
            alerts += analyzer.process_flow(flow)
        dns_alerts = [a for a in alerts if "DNS" in a.get("detector", "")]
        self.assertTrue(len(dns_alerts) > 0)

    def test_no_false_positives_normal(self):
        """3 اتصالات عادية → لا تنبيهات"""
        analyzer = self.Analyzer()
        alerts = []
        for i in range(3):
            flow = {"Src IP": "192.168.1.1", "Dst Port": 443,
                    "Destination Port": 443}
            alerts += analyzer.process_flow(flow)
        self.assertEqual(len(alerts), 0)


# ══════════════════════════════════════════════════════════════
# 4. TEST — COMPUTE FEATURES
# ══════════════════════════════════════════════════════════════
class TestComputeFeatures(unittest.TestCase):

    def setUp(self):
        from unified_agent import compute_features
        self.compute = compute_features

    def test_basic_structure(self):
        """الـ output يحتوي على الـ keys الأساسية"""
        data = _make_pkt_data(n_fwd=5, n_bwd=3, syn=1)
        feat = self.compute(data)
        self.assertIsNotNone(feat)
        required = [
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "SYN Flag Count", "ACK Flag Count", "Packets per Second",
        ]
        for k in required:
            self.assertIn(k, feat, f"Missing key: {k}")

    def test_fwd_bwd_count(self):
        """عدد الـ fwd/bwd packages صحيح"""
        data = _make_pkt_data(n_fwd=8, n_bwd=4)
        feat = self.compute(data)
        self.assertEqual(feat["Total Fwd Packets"],      8)
        self.assertEqual(feat["Total Backward Packets"], 4)

    def test_syn_flag_count(self):
        """عدد SYN flags صحيح"""
        data = _make_pkt_data(n_fwd=10, syn=3)
        feat = self.compute(data)
        self.assertEqual(feat["SYN Flag Count"], 3)

    def test_empty_packets_returns_none(self):
        """تدفق بدون حزم → None"""
        data = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                "src_port": 100, "dst_port": 200, "packets": []}
        feat = self.compute(data)
        self.assertIsNone(feat)

    def test_flow_duration_positive(self):
        """مدة التدفق دائماً موجبة"""
        data = _make_pkt_data(n_fwd=5, n_bwd=2)
        feat = self.compute(data)
        self.assertGreater(feat["Flow Duration"], 0)

    def test_packets_per_second_positive(self):
        """معدل الحزم/ثانية دائماً موجب"""
        data = _make_pkt_data(n_fwd=10, n_bwd=5)
        feat = self.compute(data)
        self.assertGreater(feat["Packets per Second"], 0)


# ══════════════════════════════════════════════════════════════
# 5. TEST — FUSION LOGIC
# ══════════════════════════════════════════════════════════════
class TestFusion(unittest.TestCase):

    def setUp(self):
        from unified_agent import fusion
        self.fusion = fusion

    def _ml(self, label, atype="", conf=0.5):
        return {"result": label, "attack_type": atype, "confidence": conf}

    def test_ddos_takes_priority(self):
        """DDoS ATTACK يتغلب على كل حاجة"""
        v, r = self.fusion("ATTACK", "NORMAL", "NORMAL", self._ml("NORMAL"))
        self.assertEqual(v, "ATTACK")
        self.assertIn("DDoS", r)

    def test_bruteforce_second_priority(self):
        """BruteForce ATTACK يكسب لو DDoS NORMAL"""
        v, r = self.fusion("NORMAL", "ATTACK", "NORMAL", self._ml("NORMAL"))
        self.assertEqual(v, "ATTACK")
        self.assertIn("BruteForce", r)

    def test_malware_third_priority(self):
        """Malware ATTACK يكسب لو DDoS+BruteForce NORMAL"""
        v, r = self.fusion("NORMAL", "NORMAL", "ATTACK", self._ml("NORMAL"))
        self.assertEqual(v, "ATTACK")
        self.assertIn("Malware", r)

    def test_ml_fourth_priority(self):
        """ML ATTACK يكسب لو كل الباقي NORMAL"""
        v, r = self.fusion("NORMAL", "NORMAL", "NORMAL", self._ml("ATTACK", "DDoS"))
        self.assertEqual(v, "ATTACK")

    def test_malware_suspicious(self):
        """Malware SUSPICIOUS → final SUSPICIOUS"""
        v, r = self.fusion("NORMAL", "NORMAL", "SUSPICIOUS", self._ml("NORMAL"))
        self.assertEqual(v, "SUSPICIOUS")

    def test_ml_suspicious(self):
        """ML SUSPICIOUS → final SUSPICIOUS"""
        v, r = self.fusion("NORMAL", "NORMAL", "NORMAL", self._ml("SUSPICIOUS"))
        self.assertEqual(v, "SUSPICIOUS")

    def test_all_normal(self):
        """كل حاجة NORMAL → NORMAL"""
        v, r = self.fusion("NORMAL", "NORMAL", "NORMAL", self._ml("NORMAL"))
        self.assertEqual(v, "NORMAL")

    def test_ddos_overrides_ml_normal(self):
        """DDoS ATTACK حتى لو ML قالت NORMAL"""
        v, _ = self.fusion("ATTACK", "NORMAL", "NORMAL", self._ml("NORMAL", conf=0.01))
        self.assertEqual(v, "ATTACK")


# ══════════════════════════════════════════════════════════════
# 6. TEST — ACTION ENGINE
# ══════════════════════════════════════════════════════════════
class TestActionEngine(unittest.TestCase):

    def setUp(self):
        import action
        # Reset cooldown state between tests
        action._last_action.clear()
        self.action = action

    def test_whitelist_protected(self):
        """localhost مش بيتحجب أبداً"""
        # No exception should be raised, and no OS command runs
        with unittest.mock.patch("os.system") as mock_sys:
            self.action.block_ip("127.0.0.1", reason="TEST")
            mock_sys.assert_not_called()

    def test_dedup_prevents_double_block(self):
        """نفس الـ IP مش بيتحجب مرتين في نفس الـ cooldown window"""
        with unittest.mock.patch("os.system") as mock_sys:
            self.action.block_ip("10.99.99.1", reason="TEST1")
            self.action.block_ip("10.99.99.1", reason="TEST2")
            # يجب أن يتم الاتصال مرة واحدة فقط
            self.assertEqual(mock_sys.call_count, 1)

    def test_take_action_attack_calls_block(self):
        """take_action('ATTACK', ip) → block_ip"""
        with unittest.mock.patch.object(self.action, "block_ip") as mock_block:
            self.action.take_action("ATTACK", "10.88.88.1")
            mock_block.assert_called_once()

    def test_take_action_suspicious_calls_monitor(self):
        """take_action('SUSPICIOUS', ip) → monitor_ip"""
        with unittest.mock.patch.object(self.action, "monitor_ip") as mock_mon:
            self.action.take_action("SUSPICIOUS", "10.88.88.2")
            mock_mon.assert_called_once()

    def test_take_action_normal_no_action(self):
        """take_action('NORMAL', ip) → لا إجراء"""
        with unittest.mock.patch("os.system") as mock_sys:
            self.action.take_action("NORMAL", "10.88.88.3")
            mock_sys.assert_not_called()


# ══════════════════════════════════════════════════════════════
# 7. INTEGRATION — CSV MODE (no API needed)
# ══════════════════════════════════════════════════════════════
class TestCSVMode(unittest.TestCase):

    def _make_sample_csv(self, path: str):
        """ينشئ CSV بـ 20 صف — 10 DDoS + 10 طبيعي."""
        rows = []
        headers = [
            "Source IP", "Destination IP", "Source Port", "Destination Port",
            "Protocol", "Flow Duration", "Total Fwd Packets",
            "Total Backward Packets", "Total Length of Fwd Packets",
            "Total Length of Bwd Packets", "SYN Flag Count", "ACK Flag Count",
            "FIN Flag Count", "Packets per Second",
        ]
        for i in range(10):  # DDoS-like
            rows.append([
                f"10.0.0.{i}", "192.168.1.1", 12000+i, 80,
                6, 100000, 500, 2, 25000, 100,
                498, 2, 0, 5000,
            ])
        for i in range(10):  # Normal
            rows.append([
                f"192.168.1.{i}", "8.8.8.8", 50000+i, 443,
                6, 500000, 10, 8, 1000, 800,
                1, 15, 1, 20,
            ])
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(headers)
            w.writerows(rows)

    def test_csv_loads_correctly(self):
        """CSV بيتقرأ وبيرجع عدد صحيح من الصفوف"""
        import pandas as pd
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, dir=PROJECT_DIR
        ) as tmp:
            self._make_sample_csv(tmp.name)
            path = tmp.name

        try:
            df = pd.read_csv(path)
            df.columns = df.columns.str.strip()
            self.assertEqual(len(df), 20)
            self.assertIn("Source IP", df.columns)
        finally:
            os.unlink(path)

    def test_brute_force_on_csv_rows(self):
        """تشغيل brute_force_detector على صفوف CSV"""
        from brute_force_detector import detect_bruteforce

        # محاكاة: 15 صف بنفس src/dst/port
        flows = [
            {"Src IP": "10.0.0.1", "Dst IP": "192.168.1.1",
             "Dst Port": "22", "Total Packets": 3}
            for _ in range(15)
        ]
        results = detect_bruteforce(flows)
        self.assertTrue(any(r["result"] == "ATTACK" for r in results))

    def test_malware_on_csv_rows(self):
        """تشغيل malware_detector على صفوف CSV"""
        from malware_detector import detect_malware

        flows = [
            {"Src IP": "10.0.0.50", "Dst IP": "185.0.0.1",
             "Total Length of Fwd Packets": 200,
             "Total Fwd Packets": 3, "Total Backward Packets": 1}
            for _ in range(12)
        ]
        results = detect_malware(flows)
        self.assertTrue(any(r["result"] == "ATTACK" for r in results))

    def test_aggregate_analysis_mixed_traffic(self):
        """run_aggregate على traffic مختلط"""
        from unified_agent import run_aggregate
        import unittest.mock as mock

        flows_attack = _make_flows("10.0.0.1", "192.168.1.1", "22", 15)
        flows_normal = _make_flows("10.0.0.2", "8.8.8.8", "443", 3)

        with mock.patch("unified_agent.take_action") as mock_act:
            run_aggregate(flows_attack + flows_normal)
            # يجب أن يُستدعى take_action على الأقل مرة للـ IP المهاجم
            self.assertTrue(mock_act.called)


# ══════════════════════════════════════════════════════════════
# 8-10. INTEGRATION — API  (تحتاج api.py شغّال)
# ══════════════════════════════════════════════════════════════
import requests as _req

def _api_is_up(url="http://127.0.0.1:5000/health"):
    try:
        r = _req.get(url, timeout=2)
        return r.status_code == 200
    except Exception:
        return False

API_UP = _api_is_up()


@unittest.skipUnless(API_UP, "API not running — start api.py first")
class TestAPIHealth(unittest.TestCase):

    BASE = "http://127.0.0.1:5000"

    def test_health_endpoint(self):
        """/health بيرجع status ok"""
        r = _req.get(f"{self.BASE}/health", timeout=3)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("model_mode", data)

    def test_health_model_mode_field(self):
        """model_mode بيكون binary أو multiclass"""
        r = _req.get(f"{self.BASE}/health", timeout=3)
        data = r.json()
        self.assertIn(data["model_mode"], ["binary", "multiclass"])


@unittest.skipUnless(API_UP, "API not running — start api.py first")
class TestAPIPredict(unittest.TestCase):

    BASE = "http://127.0.0.1:5000"

    def _predict(self, payload):
        r = _req.post(f"{self.BASE}/predict",
                      json=payload, timeout=5)
        self.assertEqual(r.status_code, 200)
        return r.json()

    def test_predict_returns_required_fields(self):
        """الـ response يحتوي على كل الـ fields"""
        payload = {"Destination Port": 443, "Total Fwd Packets": 5,
                   "SYN Flag Count": 1}
        data = self._predict(payload)
        for key in ["result", "attack_type", "confidence", "iso_flag", "class_id"]:
            self.assertIn(key, data)

    def test_predict_result_valid_label(self):
        """result دائماً ATTACK أو SUSPICIOUS أو NORMAL"""
        payload = {"Destination Port": 80, "Total Fwd Packets": 10}
        data = self._predict(payload)
        self.assertIn(data["result"].upper(),
                      ["ATTACK", "SUSPICIOUS", "NORMAL", "ERROR"])

    def test_predict_confidence_in_range(self):
        """confidence بين 0 و 1"""
        payload = {"Destination Port": 80, "Total Fwd Packets": 10}
        data = self._predict(payload)
        self.assertGreaterEqual(data["confidence"], 0.0)
        self.assertLessEqual(   data["confidence"], 1.0)

    def test_predict_ddos_like_flow(self):
        """
        تدفق يشبه DDoS → الـ API يرجع response صحيح دائماً.
        ملاحظة: النموذج محتاج 74 ميزة للحكم الدقيق؛ هنا نبعت جزء منها
        فبنتحقق من بنية الـ response فقط وليس من القرار.
        """
        payload = {
            "Destination Port": 80,
            "Total Fwd Packets": 5000,
            "SYN Flag Count": 4998,
            "FIN Flag Count": 0,
            "ACK Flag Count": 1,
            "Flow Duration": 500000,
            "Total Length of Fwd Packets": 250000,
        }
        data = self._predict(payload)
        # نتحقق من بنية الـ response فقط
        self.assertIn(data["result"], ["ATTACK", "SUSPICIOUS", "NORMAL"])
        self.assertIsInstance(data["confidence"], float)
        self.assertIsInstance(data["class_id"],   int)

    def test_predict_normal_flow(self):
        """تدفق HTTPS طبيعي → confidence للـ BENIGN عالية"""
        payload = {
            "Destination Port": 443,
            "Total Fwd Packets": 12,
            "Total Backward Packets": 10,
            "SYN Flag Count": 1,
            "FIN Flag Count": 1,
            "ACK Flag Count": 20,
            "Flow Duration": 800000,
            "Flow IAT Mean": 0.05,
        }
        data = self._predict(payload)
        # لو النموذج multiclass، BENIGN class_id = 0
        if data.get("class_id") == 0:
            self.assertEqual(data["result"], "NORMAL")


@unittest.skipUnless(API_UP, "API not running — start api.py first")
class TestEndToEnd(unittest.TestCase):
    """Pipeline كامل: بنشغّل run_aggregate مع API call حقيقي."""

    def test_full_pipeline_benign_flows(self):
        """20 تدفق طبيعي → aggregate لا يعطي ATTACK"""
        from unified_agent import run_aggregate
        import unittest.mock as mock

        flows = [
            {"Src IP": f"192.168.1.{i}", "Dst IP": "8.8.8.8",
             "Dst Port": "443", "Total Packets": 5,
             "Total Length of Fwd Packets": 500,
             "Total Fwd Packets": 3, "Total Backward Packets": 2}
            for i in range(20)
        ]

        attacked_ips = []
        with mock.patch("unified_agent.take_action",
                        side_effect=lambda v, ip, **kw: attacked_ips.append(ip) if v == "ATTACK" else None):
            run_aggregate(flows)

        # مفيش IP يستاهل ATTACK من 20 تدفق طبيعي
        self.assertEqual(len(attacked_ips), 0,
                         f"False positives: {attacked_ips}")

    def test_full_pipeline_bruteforce_attack(self):
        """15 تدفق BruteForce → يجب أن يُحجب الـ IP"""
        from unified_agent import run_aggregate
        import unittest.mock as mock

        flows = _make_flows("10.0.0.77", "192.168.1.1", "22", 15)

        blocked_ips = []
        with mock.patch("unified_agent.take_action",
                        side_effect=lambda v, ip, **kw: blocked_ips.append(ip) if v == "ATTACK" else None):
            run_aggregate(flows)

        self.assertIn("10.0.0.77", blocked_ips)


# ══════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import unittest.mock   # make sure mock is importable

    print("=" * 60)
    print("  IDS TEST SUITE")
    print("=" * 60)
    if API_UP:
        print("  [OK] API is running — API tests ENABLED")
    else:
        print("  [--] API not detected — API tests SKIPPED")
        print("       Start api.py to enable API tests")
    print("=" * 60 + "\n")

    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()

    # كل الـ test classes
    for cls in [
        TestBruteForceDetector,
        TestMalwareDetector,
        TestBehavioralDetectors,
        TestComputeFeatures,
        TestFusion,
        TestActionEngine,
        TestCSVMode,
        TestAPIHealth,
        TestAPIPredict,
        TestEndToEnd,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
