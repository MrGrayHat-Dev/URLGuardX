# =========================
# FILE: evaluate_ml.py
# =========================

import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from sklearn.preprocessing import LabelEncoder

# =========================================================
# LOAD MODEL
# =========================================================

print("[INFO] Loading trained model...")

model = joblib.load("model.pkl")

# =========================================================
# LOAD FEATURE SCHEMA
# =========================================================

print("[INFO] Loading feature schema...")

expected_features = joblib.load(
    "feature_schema.pkl"
)

print("\n[INFO] Expected Feature Order:")
print(expected_features)

# =========================================================
# LOAD BENCHMARK FEATURES
# =========================================================

print("\n[INFO] Loading benchmark features...")

df = pd.read_csv(
    "benchmark_features.csv"
)

print("[INFO] Shape:", df.shape)

# =========================================================
# LABELS
# =========================================================

y = df["label"]

X = df.drop(columns=["label"])

# =========================================================
# ENCODE CATEGORICALS
# =========================================================

categorical_cols = X.select_dtypes(
    include=["object"]
).columns

for col in categorical_cols:

    le = LabelEncoder()

    X[col] = le.fit_transform(
        X[col].astype(str)
    )

# =========================================================
# CLEAN DATA
# =========================================================

X.replace([np.inf, -np.inf], 0, inplace=True)

X.fillna(0, inplace=True)

# =========================================================
# REMOVE EXTRA COLUMNS
# =========================================================

extra_cols = [
    col for col in X.columns
    if col not in expected_features
]

if len(extra_cols) > 0:

    print("\n[WARNING] Removing extra columns:")
    print(extra_cols)

    X.drop(columns=extra_cols, inplace=True)

# =========================================================
# ADD MISSING COLUMNS
# =========================================================

missing_cols = [
    col for col in expected_features
    if col not in X.columns
]

if len(missing_cols) > 0:

    print("\n[WARNING] Adding missing columns:")
    print(missing_cols)

    for col in missing_cols:

        X[col] = 0

# =========================================================
# FORCE EXACT FEATURE ORDER
# =========================================================

X = X.reindex(
    columns=expected_features,
    fill_value=0
)

# =========================================================
# FORCE FLOAT TYPE
# =========================================================

X = X.astype(float)

print("\n[INFO] Final Feature Shape:")
print(X.shape)

print("\n[INFO] Final Ordered Features:")
print(list(X.columns))

# =========================================================
# PREDICTIONS
# =========================================================

print("\n[INFO] Running predictions...")

probs = model.predict_proba(X)[:, 1]

THRESHOLD = 0.25

preds = (
    probs >= THRESHOLD
).astype(int)
probs = model.predict_proba(X)[:, 1]

# =========================================================
# METRICS
# =========================================================

acc = accuracy_score(y, preds)

pre = precision_score(y, preds)

rec = recall_score(y, preds)

f1 = f1_score(y, preds)

auc = roc_auc_score(y, probs)

# =========================================================
# RESULTS
# =========================================================

print("\n===================================")
print("URLGuardX BENCHMARK RESULTS")
print("===================================")

print(f"Accuracy  : {acc * 100:.2f}%")
print(f"Precision : {pre * 100:.2f}%")
print(f"Recall    : {rec * 100:.2f}%")
print(f"F1-Score  : {f1 * 100:.2f}%")
print(f"AUC-ROC   : {auc:.4f}")

# =========================================================
# CLASSIFICATION REPORT
# =========================================================

print("\n=== Classification Report ===\n")

print(
    classification_report(
        y,
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
        y,
        preds
    )
)