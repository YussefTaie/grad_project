"""
train_multiclass.py - XGBoost Multi-Class Training on CICIDS2017
=================================================================
Loads all 8 CSV files from dataset/, unifies labels into 7 classes,
and saves: xgb_model_multiclass.pkl

Classes:
  0 -> BENIGN
  1 -> DDoS
  2 -> PortScan
  3 -> BruteForce (FTP-Patator, SSH-Patator)
  4 -> DoS (Hulk, GoldenEye, slowloris, Slowhttptest, Heartbleed)
  5 -> WebAttack (Brute Force, XSS, SQL Injection)
  6 -> Malware/Botnet (Bot, Infiltration)

Usage:
  python train_multiclass.py
  python train_multiclass.py --data-dir ./dataset --output xgb_model_multiclass.pkl
"""

import argparse
import glob
import logging
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from config import ATTACK_LABEL_MAP, ATTACK_CLASS_NAMES

# ── Logging (ASCII only - Windows safe) ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("TrainMulticlass")

# ── Columns to drop (same as binary model) ────────────────────────────────────
DROP_COLS = [
    'Flow ID', 'Source IP', 'Destination IP', 'Timestamp',
    'Flow Bytes/s', 'Flow Packets/s',
    'Fwd Packets/s', 'Bwd Packets/s',
]


# ==============================================================================
# LOAD DATA
# ==============================================================================
def load_all_csvs(data_dir: str) -> pd.DataFrame:
    """Read all CSV files in the folder and concatenate them."""
    pattern = f"{data_dir}/*.csv"
    files = sorted(glob.glob(pattern))

    if not files:
        log.error(f"No CSV files found in: {data_dir}")
        sys.exit(1)

    log.info(f"Found {len(files)} files:")
    frames = []
    for f in files:
        log.info(f"  Reading: {f}")
        try:
            df = pd.read_csv(f, encoding="utf-8", low_memory=False)
            frames.append(df)
            log.info(f"  -> {len(df):,} rows")
        except Exception as e:
            log.warning(f"  [WARN] Failed to read {f}: {e}")
            continue

    combined = pd.concat(frames, ignore_index=True)
    log.info(f"\n[OK] Total rows: {len(combined):,}")
    return combined


# ==============================================================================
# PREPROCESS
# ==============================================================================
def preprocess(df: pd.DataFrame):
    """Clean columns, map labels to integers."""

    # Normalize column names
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        log.error("Column 'Label' not found! Check CICIDS2017 files.")
        sys.exit(1)

    # Show original label distribution
    log.info("\nOriginal label distribution:")
    for label, count in df["Label"].value_counts().items():
        log.info(f"  {str(label):<45} -> {count:>10,}")

    # Map labels to integers
    df = df.copy()
    df["Label"] = df["Label"].map(ATTACK_LABEL_MAP)

    # Drop rows with unmapped labels
    unknown = df["Label"].isna().sum()
    if unknown > 0:
        log.warning(f"[WARN] Dropping {unknown:,} rows with unknown labels")
        df = df.dropna(subset=["Label"]).copy()

    df["Label"] = df["Label"].astype(int)

    # Clean values
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    # Drop non-feature columns
    df = df.drop(columns=DROP_COLS, errors="ignore")

    # Show final class distribution
    log.info("\nFinal class distribution:")
    for cls_id, count in df["Label"].value_counts().sort_index().items():
        name = ATTACK_CLASS_NAMES.get(cls_id, str(cls_id))
        # Strip emoji for safe logging
        safe_name = name.encode("ascii", "ignore").decode()
        log.info(f"  [{cls_id}] {safe_name:<25} -> {count:>10,}")

    return df


# ==============================================================================
# TRAIN
# ==============================================================================
def train(df: pd.DataFrame, output_path: str):
    X = df.drop("Label", axis=1)
    y = df["Label"]

    num_classes = y.nunique()
    log.info(f"\nClasses   : {num_classes}")
    log.info(f"Features  : {X.shape[1]}")

    columns = X.columns.tolist()

    # Train/test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    log.info(f"Train     : {len(X_train):,}  |  Test: {len(X_test):,}")

    # Scaling
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ── XGBoost Multi-Class ───────────────────────────────────────
    log.info("\n[*] Training XGBoost multi-class model...")
    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=7,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=num_classes,
        eval_metric="mlogloss",
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=-1,
        random_state=42,
        verbosity=1,
    )
    xgb.fit(
        X_train_s, y_train,
        eval_set=[(X_test_s, y_test)],
        verbose=50,
    )

    # ── Evaluation ───────────────────────────────────────────────
    preds = xgb.predict(X_test_s)
    target_names = []
    for i in sorted(y.unique()):
        name = ATTACK_CLASS_NAMES.get(i, str(i))
        safe = name.encode("ascii", "ignore").decode().strip()
        target_names.append(safe if safe else f"class_{i}")

    log.info("\n" + "=" * 60)
    log.info("[RESULTS] XGBoost Multi-Class Evaluation")
    log.info("=" * 60)
    print(classification_report(y_test, preds, target_names=target_names))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))

    # ── Save artifacts ────────────────────────────────────────────
    base = output_path.replace(".pkl", "")
    joblib.dump(xgb,     f"{base}.pkl")
    joblib.dump(scaler,  f"{base}_scaler.pkl")
    joblib.dump(columns, f"{base}_columns.pkl")

    log.info(f"\n[SAVED] Model   : {base}.pkl")
    log.info(f"[SAVED] Scaler  : {base}_scaler.pkl")
    log.info(f"[SAVED] Columns : {base}_columns.pkl")
    log.info("\n[NEXT] Update api.py + predict.py to use the new model.")
    log.info("       The system will auto-detect it on next startup.")

    return xgb, scaler, columns


# ==============================================================================
# ENTRY POINT
# ==============================================================================
def parse_args():
    p = argparse.ArgumentParser(description="XGBoost Multi-Class Training - CICIDS2017")
    p.add_argument("--data-dir", default="dataset",
                   help="Folder with CSV files (default: dataset/)")
    p.add_argument("--output",   default="xgb_model_multiclass.pkl",
                   help="Output model filename (default: xgb_model_multiclass.pkl)")
    return p.parse_args()


def main():
    args = parse_args()

    print("\n" + "=" * 60)
    print("  [*] CICIDS2017 Multi-Class XGBoost Training")
    print(f"  Data Dir : {args.data_dir}")
    print(f"  Output   : {args.output}")
    print("=" * 60 + "\n")

    df = load_all_csvs(args.data_dir)
    df = preprocess(df)
    train(df, args.output)


if __name__ == "__main__":
    main()
