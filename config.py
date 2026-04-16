"""
config.py — مصدر حقيقة واحد لكل ثوابت النظام
===============================================
كل الملفات لازم تـ import منه، متحطش ثوابت في أكتر من مكان.
"""

# ==============================
# 🎯 عتبات القرار (XGBoost)
# ==============================
THRESHOLD_HIGH_ATTACK    = 0.75   # فوقيها → ATTACK مؤكد
THRESHOLD_MEDIUM_ATTACK  = 0.50   # فوقيها + ISO → ATTACK
THRESHOLD_SUSPICIOUS     = 0.30   # فوقيها → SUSPICIOUS

# ==============================
# 🌲 Isolation Forest
# ==============================
ISO_CONTAMINATION = 0.10          # نسبة الـ anomalies المتوقعة في التدريب

# ==============================
# 🌊 DDoS Rule-Based
# ==============================
DDOS_PPS_THRESHOLD = 150          # حزمة/ثانية
DDOS_MIN_ALERTS    = 3            # عدد مرات تجاوز العتبة قبل الإعلان

# ==============================
# 🕐 Flow Accumulator (Agent الحي)
# ==============================
FLOW_TIMEOUT_SEC   = 5.0          # ثوانٍ من السكون قبل إرسال التدفق
MAX_FLOW_PACKETS   = 500          # حد أقصى للحزم في تدفق واحد قبل الإرسال

# ==============================
# 🚨 Behavioral Detectors
# ==============================
DNS_QUERY_THRESHOLD      = 50     # استعلام DNS / دقيقة من IP واحد → مشبوه
PORT_DIVERSITY_THRESHOLD = 30     # عدد IPs وجهة مختلفة / دقيقة → مشبوه
C2_BEACON_STD_THRESHOLD  = 0.5   # انحراف معياري منخفض لفترات الاتصال → C2 beacon
C2_MIN_CONNECTIONS       = 5     # حد أدنى للاتصالات قبل تقييم النمط الدوري

# ==============================
# 🗺️ خريطة تصنيف الهجمات (متعدد الفئات)
# ==============================
ATTACK_LABEL_MAP = {
    'BENIGN':                       0,
    'DDoS':                         1,
    'PortScan':                     2,
    'FTP-Patator':                  3,
    'SSH-Patator':                  3,
    'DoS Hulk':                     4,
    'DoS GoldenEye':                4,
    'DoS slowloris':                4,
    'DoS Slowhttptest':             4,
    'Heartbleed':                   4,
    # WebAttack (class 5) - present in Thursday files
    'Web Attack \u2013 Brute Force':    5,
    'Web Attack \u2013 XSS':            5,
    'Web Attack \u2013 Sql Injection':  5,
    # Fallback without dash (some CSV variants)
    'Web Attack - Brute Force':     5,
    'Web Attack - XSS':             5,
    'Web Attack - Sql Injection':   5,
    # Malware/Botnet mapped to 5 if WebAttack absent, else 6
    # We use 5 here to keep classes contiguous when WebAttack IS present
    'Bot':                          5,
    'Infiltration':                 5,
}

ATTACK_CLASS_NAMES = {
    0: 'BENIGN',
    1: 'DDoS',
    2: 'PortScan',
    3: 'BruteForce',
    4: 'DoS',
    5: 'WebAttack/Malware',
}

# ==============================
# 🌐 Flask API
# ==============================
API_HOST = "127.0.0.1"
API_PORT = 5000
API_URL  = f"http://{API_HOST}:{API_PORT}/predict"
