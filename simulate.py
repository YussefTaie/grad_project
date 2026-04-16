import joblib
import pandas as pd

# تحميل
xgb_model = joblib.load("xgb_model.pkl")
iso_model = joblib.load("iso_model.pkl")
scaler = joblib.load("scaler.pkl")
columns = joblib.load("columns.pkl")

def predict(sample_dict):
    df = pd.DataFrame([sample_dict])

    df.columns = df.columns.str.strip()

    # حذف الأعمدة
    df.drop(columns=[
        'Flow ID', 'Source IP', 'Destination IP', 'Timestamp',
        'Flow Bytes/s', 'Flow Packets/s',
        'Fwd Packets/s', 'Bwd Packets/s'
    ], inplace=True, errors='ignore')

    # ترتيب الأعمدة
    df = df[columns]

    sample = scaler.transform(df)

    xgb_pred = xgb_model.predict(sample)[0]

    iso_pred = iso_model.predict(sample)[0]
    iso_pred = 1 if iso_pred == -1 else 0

    if xgb_pred == 1 or iso_pred == 1:
        return "🚨 ATTACK"
    else:
        return "✅ NORMAL"