from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier

def train_isolation_forest(X_train):
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_train)
    return model

def predict_isolation(model, X):
    preds = model.predict(X)
    return [1 if x == -1 else 0 for x in preds]


def train_xgboost(X_train, y_train):
    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        eval_metric='logloss'
    )
    model.fit(X_train, y_train)
    return model

def predict_xgboost(model, X):
    return model.predict(X)