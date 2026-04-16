"""
diagnose_flow.py  —  Flow Alert Diagnostic
===========================================
بيجاوب على سؤال: "ليه الـ flows مش بتطلع alerts؟"

يتحقق من:
  1. مطابقة الأعمدة (model columns vs CSV columns)
  2. بعت صف DDoS حقيقي للـ API وشافوا الـ response
  3. بعت صف بكل الأعمدة صفر وشاف النموذج بيرجع إيه
  4. حسب عدد الأعمدة الـ zero بعد preprocessing
"""

import sys, json, glob, joblib
import pandas as pd
import numpy as np
import requests

sys.stdout.reconfigure(encoding="utf-8")

API_URL = "http://127.0.0.1:5000/predict"
DATASET_DIR = "dataset"

SEP = "=" * 60

# ─────────────────────────────────────────────────────────────
# 1. تحميل أعمدة النموذج
# ─────────────────────────────────────────────────────────────
print(SEP)
print("  STEP 1: Model Expected Columns")
print(SEP)

try:
    model_cols = joblib.load("xgb_model_multiclass_columns.pkl")
    print(f"  Model expects {len(model_cols)} columns:")
    for c in model_cols:
        print(f"    '{c}'")
except Exception as e:
    print(f"  [ERROR] Cannot load columns.pkl: {e}")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
# 2. قراءة صف DDoS حقيقي من الـ dataset
# ─────────────────────────────────────────────────────────────
print()
print(SEP)
print("  STEP 2: Real DDoS Row from Dataset")
print(SEP)

ddos_files = glob.glob(f"{DATASET_DIR}/*DDos*.csv") + glob.glob(f"{DATASET_DIR}/*DDoS*.csv")
if not ddos_files:
    print("  [WARN] No DDoS CSV found in dataset/")
    real_ddos_row = None
else:
    df_ddos = pd.read_csv(ddos_files[0], low_memory=False, nrows=200)
    df_ddos.columns = df_ddos.columns.str.strip()
    # خذ صف DDoS فعلي
    ddos_rows = df_ddos[df_ddos["Label"].str.strip() == "DDoS"] if "Label" in df_ddos.columns else df_ddos
    if len(ddos_rows) == 0:
        ddos_rows = df_ddos  # خذ أي صف

    real_ddos_row = ddos_rows.iloc[0].to_dict()
    print(f"  File: {ddos_files[0]}")
    print(f"  CSV columns ({len(df_ddos.columns)}): {list(df_ddos.columns[:10])} ...")
    print(f"  Label: {real_ddos_row.get('Label', 'N/A')}")

    # فحص تطابق الأعمدة
    csv_cols   = set(df_ddos.columns)
    model_set  = set(model_cols)
    matched    = csv_cols & model_set
    csv_only   = csv_cols - model_set
    model_only = model_set - csv_cols

    print(f"\n  Column matching:")
    print(f"    Matched (both)    : {len(matched)}")
    print(f"    CSV only (ignored): {len(csv_only)}")
    print(f"    Model only (zero) : {len(model_only)} ← هذي بيتحطلها 0")
    if model_only:
        print(f"    Model-only cols   : {sorted(model_only)}")

# ─────────────────────────────────────────────────────────────
# 3. بعت الصف الحقيقي للـ API وشوف الـ response
# ─────────────────────────────────────────────────────────────
print()
print(SEP)
print("  STEP 3: API Test with Real DDoS Row")
print(SEP)

def call_api(payload):
    try:
        r = requests.post(API_URL, json=payload, timeout=5)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}"}
    except requests.exceptions.ConnectionError:
        return {"error": "API NOT RUNNING — start api.py first"}
    except Exception as e:
        return {"error": str(e)}

if real_ddos_row:
    # إزالة الـ label قبل الإرسال
    payload = {k: v for k, v in real_ddos_row.items() if k != "Label"}
    result  = call_api(payload)
    print(f"  Real DDoS row result: {json.dumps(result, indent=4)}")

# ─────────────────────────────────────────────────────────────
# 4. بعت صف بكل الأعمدة الصح بـ قيم DDoS اصطناعية
# ─────────────────────────────────────────────────────────────
print()
print(SEP)
print("  STEP 4: API Test with Full Feature DDoS (Synthetic)")
print(SEP)

# بنملأ كل الأعمدة المتوقعة بـ zeros، ثم بنحط القيم الـ DDoS
full_ddos = {col: 0.0 for col in model_cols}
full_ddos.update({
    "Destination Port":              80,
    "Flow Duration":                 500000,
    "Total Fwd Packets":             5000,
    "Total Backward Packets":        5,
    "Total Length of Fwd Packets":   250000,
    "Total Length of Bwd Packets":   200,
    "Fwd Packet Length Max":         100,
    "Fwd Packet Length Min":         50,
    "Fwd Packet Length Mean":        50.0,
    "SYN Flag Count":                4995,
    "ACK Flag Count":                5,
    "FIN Flag Count":                0,
    "RST Flag Count":                0,
    "Packets per Second":            10000,
    "Flow IAT Mean":                 0.0001,
    "Flow IAT Std":                  0.0001,
    "Packet Length Mean":            50.0,
    "Average Packet Size":           50.0,
})

result2 = call_api(full_ddos)
print(f"  Synthetic DDoS (full features): {json.dumps(result2, indent=4)}")

# ─────────────────────────────────────────────────────────────
# 5. شوف كام عمود بـ 0 بعد الـ preprocessing
# ─────────────────────────────────────────────────────────────
print()
print(SEP)
print("  STEP 5: Zero-Column Analysis")
print(SEP)

if real_ddos_row:
    payload_clean = {k: v for k, v in real_ddos_row.items() if k != "Label"}
    df_test = pd.DataFrame([payload_clean])
    df_test.columns = df_test.columns.str.strip()

    full_df = pd.DataFrame(columns=model_cols)
    for col in df_test.columns:
        if col in full_df.columns:
            full_df.loc[0, col] = df_test[col].values[0]
    full_df = full_df.fillna(0).astype(float)

    zero_cols = (full_df.iloc[0] == 0).sum()
    total     = len(model_cols)
    filled    = total - zero_cols

    print(f"  Total model features   : {total}")
    print(f"  Filled from CSV        : {filled}")
    print(f"  Zeroed (missing/mismatch): {zero_cols}")
    pct = (filled / total) * 100
    print(f"  Coverage               : {pct:.1f}%")

    if pct < 50:
        print()
        print("  [!] ROOT CAUSE FOUND:")
        print(f"      Only {filled}/{total} features are correctly filled.")
        print("      The model sees mostly zeros → predicts BENIGN.")
        print()
        print("  SOLUTIONS:")
        print("  A) Use the CICIDS dataset CSV files directly (they have all columns)")
        print("  B) Rename your CSV columns to match the model's expected names")
        print("  C) Run:  python unified_agent.py --mode csv --input dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

print()
print(SEP)
print("  QUICK FIX: Test with real CICIDS file")
print(SEP)
print("  python unified_agent.py --mode csv --input dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
