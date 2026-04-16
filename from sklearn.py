import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier

# ==============================
# 📌 1) قراءة الداتا
# ==============================
df = pd.read_csv(r"d:\CIC\Last semester 2026\Graduation Project\MachineLearningCSV\MachineLearningCVE\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

# ==============================
# 📌 2) تنظيف الأعمدة
# ==============================
df.columns = df.columns.str.strip()

# ==============================
# 📌 3) تنظيف البيانات
# ==============================
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# ==============================
# 📌 4) حذف الأعمدة غير المهمة
# ==============================
df.drop(columns=[
    'Flow ID', 'Source IP', 'Destination IP', 'Timestamp'
], inplace=True, errors='ignore')

# ==============================
# 🚨 5) إزالة الـ Leakage Features (مهم جدًا)
# ==============================
leakage_cols = [
    'Flow Bytes/s',
    'Flow Packets/s'
]

df.drop(columns=leakage_cols, inplace=True, errors='ignore')

# ==============================
# 📌 6) تحويل اللابل
# ==============================
df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

# ==============================
# 📌 7) فصل البيانات
# ==============================
X = df.drop('Label', axis=1)
y = df['Label']

# ==============================
# 📌 8) Train/Test Split
# ==============================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ==============================
# 📌 9) Scaling
# ==============================
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ==============================
# 🟣 10) Isolation Forest
# ==============================
iso_model = IsolationForest(contamination=0.1, random_state=42)
iso_model.fit(X_train_scaled)

iso_preds = iso_model.predict(X_test_scaled)
iso_preds = [1 if x == -1 else 0 for x in iso_preds]

print("\n🟣 Isolation Forest Results:")
print(confusion_matrix(y_test, iso_preds))
print(classification_report(y_test, iso_preds))

# ==============================
# 🔵 11) XGBoost
# ==============================
xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    eval_metric='logloss'
)

xgb_model.fit(X_train_scaled, y_train)

xgb_preds = xgb_model.predict(X_test_scaled)

print("\n🔵 XGBoost Results (After Fix):")
print(confusion_matrix(y_test, xgb_preds))
print(classification_report(y_test, xgb_preds))

# ==============================
# 🔥 12) Hybrid Model
# ==============================
final_preds = []

for i in range(len(xgb_preds)):
    if iso_preds[i] == 1 or xgb_preds[i] == 1:
        final_preds.append(1)
    else:
        final_preds.append(0)

print("\n🔥 Hybrid Model Results:")
print(confusion_matrix(y_test, final_preds))
print(classification_report(y_test, final_preds))