# =========================
# FILE: train.py
# =========================

import pandas as pd
import joblib

from sklearn.model_selection import (
    train_test_split
)

from sklearn.ensemble import (
    RandomForestClassifier
)

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

from features import preprocess_dataset

# =========================================================
# CONFIG
# =========================================================

DATASET_PATH = "data/Dataset.csv"

MODEL_OUTPUT = "model.pkl"

# =========================================================
# LOAD DATASET
# =========================================================

print("[INFO] Loading dataset...")

df = pd.read_csv(DATASET_PATH)

print("\n[INFO] Dataset Shape:")
print(df.shape)

print("\n[INFO] Dataset Columns:")
print(df.columns)

# =========================================================
# FEATURE ENGINEERING
# =========================================================

print("\n[INFO] Processing features...")

X, y = preprocess_dataset(df)

print("\n[INFO] Feature Matrix Shape:")
print(X.shape)

# =========================================================
# TRAIN / TEST SPLIT
# =========================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

print("\n[INFO] Training Samples:", len(X_train))
print("[INFO] Testing Samples :", len(X_test))

# =========================================================
# MODEL
# =========================================================

print("\n[INFO] Training RandomForest model...")

model = RandomForestClassifier(
    n_estimators=500,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# =========================================================
# PREDICTIONS
# =========================================================

print("\n[INFO] Running evaluation...")

preds = model.predict(X_test)

probs = model.predict_proba(X_test)[:, 1]

# =========================================================
# METRICS
# =========================================================

acc = accuracy_score(y_test, preds)

pre = precision_score(y_test, preds)

rec = recall_score(y_test, preds)

f1 = f1_score(y_test, preds)

auc = roc_auc_score(y_test, probs)

print("\n====================================")
print("URLGuardX Lexical Model Results")
print("====================================")

print(f"Accuracy  : {acc * 100:.2f}%")
print(f"Precision : {pre * 100:.2f}%")
print(f"Recall    : {rec * 100:.2f}%")
print(f"F1-Score  : {f1 * 100:.2f}%")
print(f"AUC-ROC   : {auc:.4f}")

# =========================================================
# REPORT
# =========================================================

print("\n=== Classification Report ===\n")

print(
    classification_report(
        y_test,
        preds,
        target_names=[
            "Legitimate",
            "Phishing"
        ]
    )
)

# =========================================================
# CONFUSION MATRIX
# =========================================================

print("\n=== Confusion Matrix ===\n")

print(
    confusion_matrix(
        y_test,
        preds
    )
)

# =========================================================
# FEATURE IMPORTANCE
# =========================================================

print("\n=== Feature Importance ===\n")

feature_importance = sorted(
    zip(X.columns, model.feature_importances_),
    key=lambda x: x[1],
    reverse=True
)

for name, score in feature_importance:

    print(f"{name:35s} : {score:.4f}")

# =========================================================
# SAVE MODEL
# =========================================================
joblib.dump(
    list(X.columns),
    "feature_schema.pkl"
)
joblib.dump(
    model,
    MODEL_OUTPUT
)

print(
    f"\n✅ Model saved to: {MODEL_OUTPUT}"
)
