import sys
sys.stdout.reconfigure(encoding='utf-8')
from preprocessing import load_all_data
from models import (
    train_isolation_forest, predict_isolation,
    train_xgboost, predict_xgboost
)
from autoencoder_model import train_autoencoder, predict_autoencoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib


path = r"C:\Users\Yusse\Workspace\Graduation Project\MachineLearningCVE1.1\dataset"

# ==============================
#  Preprocessing
# ==============================
X_train, X_test, y_train, y_test, scaler, columns = load_all_data(path)

# ==============================
# 🟣 Isolation Forest
# ==============================
iso_model = train_isolation_forest(X_train)
iso_preds = predict_isolation(iso_model, X_test)

print("\n Isolation Forest:")
print(confusion_matrix(y_test, iso_preds))
print(classification_report(y_test, iso_preds))

# ==============================
# 🔵 XGBoost
# ==============================
xgb_model = train_xgboost(X_train, y_train)
xgb_preds = predict_xgboost(xgb_model, X_test)

print("\n🔵 XGBoost:")
print(confusion_matrix(y_test, xgb_preds))
print(classification_report(y_test, xgb_preds))

# ==============================
# 🟡 Autoencoder
# ==============================
ae_model = train_autoencoder(X_train, y_train)
ae_preds = predict_autoencoder(ae_model, X_test)

print("\n🟡 Autoencoder:")
print(confusion_matrix(y_test, ae_preds))
print(classification_report(y_test, ae_preds))

# ==============================
# 💀 Hybrid Model
# ==============================
final_preds = []

for i in range(len(X_test)):
    if iso_preds[i] == 1 or xgb_preds[i] == 1 or ae_preds[i] == 1:
        final_preds.append(1)
    else:
        final_preds.append(0)

print("\n🔥 Hybrid Model:")
print(confusion_matrix(y_test, final_preds))
print(classification_report(y_test, final_preds))

# ==============================
# 💾 حفظ الموديلات
# ==============================
joblib.dump(xgb_model, "xgb_model.pkl")
joblib.dump(iso_model, "iso_model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(columns.tolist(), "columns.pkl")

print("\n💾 Models Saved Successfully 🔥")