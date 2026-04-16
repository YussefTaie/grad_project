import pandas as pd
import numpy as np
import glob

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

def load_all_data(folder_path):
    # 📌 قراءة كل الفايلات
    all_files = glob.glob(folder_path + "/*.csv")

    df_list = []

    for file in all_files:
        try:
            print(f"Loading: {file}")

            df = pd.read_csv(file)

            # ⚠️ لو الفايل فاضي skip
            if df.shape[1] == 0 or df.empty:
                print(f"⚠️ Skipping empty file: {file}")
                continue

            df_list.append(df)

        except Exception as e:
            print(f"❌ Error reading {file}: {e}")
            continue

    # ❌ لو مفيش داتا خالص
    if len(df_list) == 0:
        raise ValueError("❌ No valid CSV files found!")

    # دمج كل الداتا
    df = pd.concat(df_list, ignore_index=True)

    # تنظيف الأعمدة
    df.columns = df.columns.str.strip()

    # تنظيف البيانات
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # حذف الأعمدة غير المهمة
    df.drop(columns=[
        'Flow ID', 'Source IP', 'Destination IP', 'Timestamp'
    ], inplace=True, errors='ignore')

    # إزالة leakage
    df.drop(columns=[
        'Flow Bytes/s', 'Flow Packets/s',
        'Fwd Packets/s', 'Bwd Packets/s'
    ], inplace=True, errors='ignore')

    # ⚠️ تأكد إن Label موجود
    if 'Label' not in df.columns:
        raise ValueError("❌ Column 'Label' not found!")

    # تحويل اللابل
    df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

    # Shuffle
    df = df.sample(frac=1).reset_index(drop=True)

    # فصل
    X = df.drop('Label', axis=1)
    y = df['Label']

    # حفظ الأعمدة
    columns = X.columns

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Scaling
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test, scaler, columns