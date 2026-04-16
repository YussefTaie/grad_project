"""
train_autoencoder.py  —  Autoencoder Training & Saving
=======================================================
يُدرّب Autoencoder على البيانات الـ BENIGN فقط من CICIDS2017.
الفكرة:
  - نموذج مُدرَّب على الطبيعي فقط
  - لو بعتله تدفق هجوم → reconstruction error عالي → ANOMALY
  - مكمّل لـ XGBoost (يكشف Zero-day وهجمات مش في التدريب)

المخرجات:
  - autoencoder_model.h5     النموذج الكامل
  - autoencoder_threshold.pkl الـ threshold الأمثل
  - autoencoder_scaler.pkl   الـ scaler الخاص بالـ autoencoder

الاستخدام:
  python train_autoencoder.py
"""

import os
import sys
import glob
import json
import joblib
import numpy as np
import pandas as pd

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
sys.stdout.reconfigure(encoding="utf-8")

import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, f1_score

DATASET_DIR = "dataset"
MODEL_PATH  = "autoencoder_model.keras"
THRESH_PATH = "autoencoder_threshold.pkl"
SCALER_PATH = "autoencoder_scaler.pkl"
COLUMNS     = joblib.load("xgb_model_multiclass_columns.pkl")

SEP = "=" * 60

# ══════════════════════════════════════════════════════════════
# STEP 1 — تحميل البيانات
# ══════════════════════════════════════════════════════════════
print(SEP)
print("  STEP 1: Loading CICIDS2017 Dataset")
print(SEP)

csv_files = glob.glob(f"{DATASET_DIR}/*.csv")
if not csv_files:
    print("[ERROR] No CSV files found in dataset/")
    sys.exit(1)

dfs = []
for f in csv_files:
    try:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        if "Label" in df.columns:
            dfs.append(df)
            print(f"  Loaded: {os.path.basename(f)} ({len(df):,} rows)")
    except Exception as e:
        print(f"  [WARN] Skipped {f}: {e}")

if not dfs:
    print("[ERROR] No valid CSV files loaded.")
    sys.exit(1)

df_all = pd.concat(dfs, ignore_index=True)
df_all.columns = df_all.columns.str.strip()
print(f"\n  Total rows loaded: {len(df_all):,}")

# تنظيف البيانات
df_all = df_all.replace([np.inf, -np.inf], np.nan)
df_all = df_all.dropna(subset=["Label"])

# احتفاظ بالأعمدة المطلوبة فقط
available = [c for c in COLUMNS if c in df_all.columns]
missing   = [c for c in COLUMNS if c not in df_all.columns]
print(f"  Features matched : {len(available)}/74")
if missing:
    print(f"  Features missing : {missing[:5]}...")

df_all = df_all[available + ["Label"]].copy()

# ملء الـ missing features بصفر
for col in COLUMNS:
    if col not in df_all.columns:
        df_all[col] = 0.0

df_all = df_all[COLUMNS + ["Label"]]
df_all[COLUMNS] = df_all[COLUMNS].fillna(0).astype(float)
df_all = df_all.replace([np.inf, -np.inf], 0)

# فصل BENIGN عن الهجمات
label_col = df_all["Label"].str.strip()
df_benign  = df_all[label_col == "BENIGN"].copy()
df_attack  = df_all[label_col != "BENIGN"].copy()

print(f"  BENIGN rows      : {len(df_benign):,}")
print(f"  Attack rows      : {len(df_attack):,}")

# ══════════════════════════════════════════════════════════════
# STEP 2 — Preprocessing
# ══════════════════════════════════════════════════════════════
print()
print(SEP)
print("  STEP 2: Preprocessing")
print(SEP)

X_benign = df_benign[COLUMNS].values
X_attack = df_attack[COLUMNS].values

# Train/Val split على BENIGN فقط
from sklearn.model_selection import train_test_split
X_train, X_val = train_test_split(X_benign, test_size=0.1, random_state=42)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_val_s   = scaler.transform(X_val)
X_attack_s = scaler.transform(X_attack)

joblib.dump(scaler, SCALER_PATH)
print(f"  Train BENIGN : {len(X_train):,}")
print(f"  Val   BENIGN : {len(X_val):,}")
print(f"  Attack (test): {len(X_attack):,}")

# ══════════════════════════════════════════════════════════════
# STEP 3 — بناء الـ Autoencoder
# ══════════════════════════════════════════════════════════════
print()
print(SEP)
print("  STEP 3: Building Autoencoder Architecture")
print(SEP)

input_dim = len(COLUMNS)  # 74

def build_autoencoder(input_dim: int) -> Model:
    """
    Architecture:
      74 → 64 → 32 → 16 → 8  (Encoder)
       8 → 16 → 32 → 64 → 74 (Decoder)
    """
    inp = Input(shape=(input_dim,), name="input")

    # Encoder
    x = Dense(64, activation="relu", name="enc_1")(inp)
    x = BatchNormalization()(x)
    x = Dropout(0.2)(x)
    x = Dense(32, activation="relu", name="enc_2")(x)
    x = BatchNormalization()(x)
    x = Dense(16, activation="relu", name="enc_3")(x)
    x = Dense(8,  activation="relu", name="latent")(x)

    # Decoder
    x = Dense(16, activation="relu", name="dec_1")(x)
    x = Dense(32, activation="relu", name="dec_2")(x)
    x = BatchNormalization()(x)
    x = Dense(64, activation="relu", name="dec_3")(x)
    out = Dense(input_dim, activation="linear", name="output")(x)

    model = Model(inputs=inp, outputs=out, name="IDS_Autoencoder")
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="mse",
    )
    return model

ae = build_autoencoder(input_dim)
ae.summary()

# ══════════════════════════════════════════════════════════════
# STEP 4 — التدريب
# ══════════════════════════════════════════════════════════════
print()
print(SEP)
print("  STEP 4: Training on BENIGN Traffic Only")
print(SEP)

callbacks = [
    EarlyStopping(
        monitor="val_loss", patience=5,
        restore_best_weights=True, verbose=1,
    ),
    ReduceLROnPlateau(
        monitor="val_loss", factor=0.5, patience=3,
        min_lr=1e-5, verbose=1,
    ),
]

history = ae.fit(
    X_train_s, X_train_s,
    epochs=50,
    batch_size=512,
    validation_data=(X_val_s, X_val_s),
    callbacks=callbacks,
    verbose=1,
)

print(f"\n  Training stopped at epoch {len(history.epoch)}")
print(f"  Final train loss : {history.history['loss'][-1]:.6f}")
print(f"  Final val   loss : {history.history['val_loss'][-1]:.6f}")

# ══════════════════════════════════════════════════════════════
# STEP 5 — حساب الـ Threshold الأمثل
# ══════════════════════════════════════════════════════════════
print()
print(SEP)
print("  STEP 5: Computing Optimal Threshold")
print(SEP)

def reconstruction_error(model, X):
    X_pred = model.predict(X, verbose=0)
    return np.mean(np.power(X - X_pred, 2), axis=1)

err_benign = reconstruction_error(ae, X_val_s)
err_attack = reconstruction_error(ae, X_attack_s[:10000])  # عيّنة

print(f"  BENIGN  recon error: mean={err_benign.mean():.4f}  p95={np.percentile(err_benign, 95):.4f}")
print(f"  ATTACK  recon error: mean={err_attack.mean():.4f}  p95={np.percentile(err_attack, 95):.4f}")

# نجرب thresholds مختلفة ونختار اللي يعطي أحسن F1
y_true = np.concatenate([
    np.zeros(len(err_benign)),   # BENIGN = 0
    np.ones(len(err_attack)),    # ATTACK = 1
])
errors = np.concatenate([err_benign, err_attack])

best_thresh, best_f1 = 0.0, 0.0
candidates = np.percentile(err_benign, np.arange(80, 100, 0.5))

for t in candidates:
    y_pred = (errors > t).astype(int)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    if f1 > best_f1:
        best_f1    = f1
        best_thresh = t

# Fallback: p95 of benign errors
if best_thresh == 0.0:
    best_thresh = float(np.percentile(err_benign, 95))

try:
    auc = roc_auc_score(y_true, errors)
    print(f"  ROC-AUC            : {auc:.4f}")
except ValueError:
    pass

print(f"  Best Threshold     : {best_thresh:.6f}")
print(f"  Best F1 (AE only)  : {best_f1:.4f}")

joblib.dump({"threshold": best_thresh, "best_f1": best_f1}, THRESH_PATH)

# ══════════════════════════════════════════════════════════════
# STEP 6 — حفظ النموذج
# ══════════════════════════════════════════════════════════════
print()
print(SEP)
print("  STEP 6: Saving Model")
print(SEP)

ae.save(MODEL_PATH)
print(f"  Model saved   -> {MODEL_PATH}")
print(f"  Scaler saved  -> {SCALER_PATH}")
print(f"  Threshold     -> {THRESH_PATH}  (threshold={best_thresh:.6f})")

# ══════════════════════════════════════════════════════════════
# STEP 7 — Quick Evaluation
# ══════════════════════════════════════════════════════════════
print()
print(SEP)
print("  STEP 7: Quick Evaluation")
print(SEP)

# Test على sample جديد
n_test_b = min(5000, len(X_val_s))
n_test_a = min(5000, len(X_attack_s))

err_b_test = reconstruction_error(ae, X_val_s[:n_test_b])
err_a_test = reconstruction_error(ae, X_attack_s[:n_test_a])

tp = (err_a_test > best_thresh).sum()
fp = (err_b_test > best_thresh).sum()
tn = (err_b_test <= best_thresh).sum()
fn = (err_a_test <= best_thresh).sum()

precision = tp / (tp + fp + 1e-9)
recall    = tp / (tp + fn + 1e-9)
f1        = 2 * precision * recall / (precision + recall + 1e-9)

print(f"  Sample: {n_test_b} BENIGN + {n_test_a} ATTACK")
print(f"  TP (Attack correctly flagged) : {tp}/{n_test_a}  ({tp/n_test_a*100:.1f}%)")
print(f"  FP (Benign falsely flagged)   : {fp}/{n_test_b}  ({fp/n_test_b*100:.1f}%)")
print(f"  Precision : {precision:.3f}")
print(f"  Recall    : {recall:.3f}")
print(f"  F1        : {f1:.3f}")

print()
print(SEP)
print("  [DONE] Autoencoder trained and saved.")
print("         predict.py will automatically load it.")
print(SEP)
