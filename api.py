"""
api.py — Flask Prediction API (Auto-detect Binary / Multi-Class)
================================================================
يرجع دلوقتي:
  {
    "result":      "ATTACK" | "SUSPICIOUS" | "NORMAL",
    "attack_type": "DDoS" | "WebAttack" | ... | "BENIGN",
    "confidence":  float,
    "iso_flag":    int,
    "class_id":    int,
    "model_mode":  "multiclass" | "binary"
  }

Isolation Forest policy (upgraded — no retraining required)
------------------------------------------------------------
iso_flag == 1 alone is NOT sufficient to raise SUSPICIOUS.
It must be accompanied by EITHER:
  a) XGBoost predicted a non-BENIGN class, OR
  b) confidence is above THRESHOLD_SUSPICIOUS for the attack class
This prevents normal high-volume traffic from being flagged solely
because the IF model sees statistical deviation.
"""

import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify

from config import (
    THRESHOLD_HIGH_ATTACK, THRESHOLD_MEDIUM_ATTACK, THRESHOLD_SUSPICIOUS,
    ATTACK_CLASS_NAMES, API_HOST, API_PORT,
)

app = Flask(__name__)

# ==============================================================================
# Model Loading — Auto-detect multiclass vs binary
# ==============================================================================
_MULTICLASS_PATH  = "xgb_model_multiclass.pkl"
_use_multiclass   = os.path.exists(_MULTICLASS_PATH)

if _use_multiclass:
    print("[api.py] Multi-class model loaded -> xgb_model_multiclass.pkl")
    xgb_model = joblib.load(_MULTICLASS_PATH)
    scaler    = joblib.load("xgb_model_multiclass_scaler.pkl")
    columns   = joblib.load("xgb_model_multiclass_columns.pkl")
    MODEL_MODE = "multiclass"
else:
    print("[api.py] Binary model loaded (run train_multiclass.py to upgrade)")
    xgb_model = joblib.load("xgb_model.pkl")
    scaler    = joblib.load("scaler.pkl")
    columns   = joblib.load("columns.pkl")
    MODEL_MODE = "binary"

iso_model = joblib.load("iso_model.pkl")


# ==============================================================================
# Preprocessing
# ==============================================================================
def preprocess(sample_dict: dict):
    df = pd.DataFrame([sample_dict])
    df.columns = df.columns.str.strip()

    df.drop(columns=[  
        'Flow ID', 'Source IP', 'Destination IP', 'Timestamp',
        'Flow Bytes/s', 'Flow Packets/s',
        'Fwd Packets/s', 'Bwd Packets/s',
    ], inplace=True, errors='ignore')

    full_df = pd.DataFrame(columns=columns)
    for col in df.columns:
        if col in full_df.columns:
            full_df.loc[0, col] = df[col].values[0]

    full_df = full_df.fillna(0).astype(float)
    return scaler.transform(full_df)


# ==============================================================================
# Prediction Endpoint
# ==============================================================================
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data   = request.json
        sample = preprocess(data)

        # ── Isolation Forest ─────────────────────────────────────────────
        # iso_flag is a *supporting* signal, not a standalone verdict.
        # Requiring multi-signal confirmation drastically cuts false positives
        # on legitimate high-volume traffic.
        iso_raw = iso_model.predict(sample)[0]
        iso     = 1 if iso_raw == -1 else 0

        if _use_multiclass:
            # ── Multi-class ───────────────────────────────────────
            class_id   = int(xgb_model.predict(sample)[0])
            proba      = xgb_model.predict_proba(sample)[0]
            confidence = float(max(proba))

            attack_type = ATTACK_CLASS_NAMES.get(class_id, f"class_{class_id}")
            attack_safe = attack_type.encode("ascii", "ignore").decode().strip()

            if class_id == 0:                           # XGB says BENIGN
                if iso == 1 and confidence < THRESHOLD_SUSPICIOUS:
                    # ISO alone with low XGB certainty → escalate only weakly
                    # (borderline case: very low-confidence BENIGN + anomaly)
                    result      = "SUSPICIOUS"
                    attack_safe = "ANOMALY (IsoForest+LowConf)"
                elif iso == 1 and confidence >= THRESHOLD_SUSPICIOUS:
                    # XGB is confident it's BENIGN but ISO disagrees:
                    # iso signal alone → do NOT escalate (suppress false positive)
                    result      = "NORMAL"
                    attack_safe = "BENIGN"
                else:
                    result      = "NORMAL"
                    attack_safe = "BENIGN"
            else:                                       # XGB says ATTACK class
                if confidence >= THRESHOLD_MEDIUM_ATTACK:
                    result = "ATTACK"
                elif confidence >= THRESHOLD_SUSPICIOUS and iso == 1:
                    # Both ML models agree → ATTACK
                    result = "ATTACK"
                elif confidence >= THRESHOLD_SUSPICIOUS:
                    # XGB says attack but with moderate confidence, ISO silent
                    result = "SUSPICIOUS"
                else:
                    # Low-confidence attack prediction
                    result = "SUSPICIOUS"

        else:
            # ── Binary (fallback) ─────────────────────────────────
            prob       = float(xgb_model.predict_proba(sample)[0][1])
            class_id   = 1 if prob >= 0.5 else 0
            confidence = prob

            if prob > THRESHOLD_HIGH_ATTACK:
                result      = "ATTACK"
                attack_safe = "HIGH CONFIDENCE ATTACK"
            elif prob > THRESHOLD_MEDIUM_ATTACK and iso == 1:
                # Both signals agree at medium confidence → ATTACK
                result      = "ATTACK"
                attack_safe = "MEDIUM CONFIDENCE ATTACK (ML+ISO)"
            elif prob > THRESHOLD_MEDIUM_ATTACK:
                # XGB medium confidence but ISO is silent
                result      = "SUSPICIOUS"
                attack_safe = "MEDIUM CONFIDENCE ATTACK"
            elif prob > THRESHOLD_SUSPICIOUS and iso == 1:
                # Moderate XGB + ISO anomaly → SUSPICIOUS (not ATTACK)
                result      = "SUSPICIOUS"
                attack_safe = "ANOMALY DETECTED"
            elif iso == 1 and prob <= THRESHOLD_SUSPICIOUS:
                # ISO alone with low XGB score → NORMAL, suppress FP
                result      = "NORMAL"
                attack_safe = "BENIGN"
            else:
                result      = "NORMAL"
                attack_safe = "BENIGN"

        icon = {"ATTACK": "[!!]", "SUSPICIOUS": "[?]", "NORMAL": "[OK]"}.get(result, "[?]")
        print(f"{icon} {result:<10} | type={attack_safe:<25} | conf={confidence:.3f} | iso={iso}")

        return jsonify({
            "result":      result,
            "attack_type": attack_safe,
            "confidence":  confidence,
            "iso_flag":    iso,
            "class_id":    class_id,
            "model_mode":  MODEL_MODE,
        })

    except Exception as e:
        return jsonify({"error": str(e), "result": "ERROR"}), 500


# ==============================================================================
# Health Check
# ==============================================================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":     "ok",
        "model_mode": MODEL_MODE,
        "models":     ["xgb", "iso"],
    })


# ==============================================================================
# Baseline Stats Endpoint (diagnostic / observability)
# ==============================================================================
@app.route("/baseline_stats", methods=["GET"])
def baseline_stats():
    """
    Returns the current state of the adaptive baseline engine.
    Useful for operators to monitor what thresholds the system has learned.
    """
    try:
        from baseline_engine import get_engine
        engine = get_engine()
        stats  = engine.stats_summary()
        return jsonify({"status": "ok", "baseline": stats})
    except ImportError:
        return jsonify({"status": "unavailable", "reason": "baseline_engine not loaded"})


# ==============================================================================
# Run
# ==============================================================================
if __name__ == "__main__":
    app.run(host=API_HOST, port=API_PORT, debug=True)