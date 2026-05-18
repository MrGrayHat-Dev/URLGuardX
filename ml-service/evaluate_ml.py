# =========================
# FILE: evaluate_ml.py
# =========================

import re
import math
import pandas as pd
import numpy as np
import joblib
import tldextract

from urllib.parse import urlparse

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

# =========================================================
# CONFIG
# =========================================================

DATASET_PATH = "data/balanced_benchmark_dataset.csv"

MODEL_PATH = "model.pkl"

SCHEMA_PATH = "feature_schema.pkl"

THRESHOLD = 0.50

# =========================================================
# LOAD DATASET
# =========================================================

print("[INFO] Loading balanced dataset for evaluation...")

df = pd.read_csv(
    DATASET_PATH,
    usecols=["url", "label"]
)

df.dropna(inplace=True)

print("\n[INFO] Evaluation Dataset Shape:")

print(
    f"  Benign (0)  : "
    f"{len(df[df['label'] == 0])}"
)

print(
    f"  Phishing (1): "
    f"{len(df[df['label'] == 1])}"
)

# =========================================================
# FEATURE EXTRACTION
# =========================================================

def calculate_entropy(text):

    if not text:
        return 0

    prob = [
        float(text.count(c)) / len(text)
        for c in dict.fromkeys(list(text))
    ]

    return -sum(
        p * math.log2(p)
        for p in prob
    )


def extract_url_features(url):

    url = str(url)

    parsed = urlparse(url)

    ext = tldextract.extract(url)

    domain = parsed.netloc

    path = parsed.path

    query = parsed.query

    url_len = len(url)

    letter_cnt = sum(
        c.isalpha()
        for c in url
    )

    digit_cnt = sum(
        c.isdigit()
        for c in url
    )

    special_cnt = len(
        re.findall(
            r"[^A-Za-z0-9]",
            url
        )
    )

    return {

        "url_len":
            url_len,

        "dom_len":
            len(domain),

        "is_ip":
            1 if re.match(
                r"^\d{1,3}(\.\d{1,3}){3}$",
                domain
            ) else 0,

        "tld_len":
            len(ext.suffix),

        "subdom_cnt":
            len(ext.subdomain.split("."))
            if ext.subdomain else 0,

        "letter_cnt":
            letter_cnt,

        "digit_cnt":
            digit_cnt,

        "special_cnt":
            special_cnt,

        "eq_cnt":
            url.count("="),

        "qm_cnt":
            url.count("?"),

        "amp_cnt":
            url.count("&"),

        "dot_cnt":
            url.count("."),

        "dash_cnt":
            url.count("-"),

        "under_cnt":
            url.count("_"),

        "letter_ratio":
            letter_cnt / url_len
            if url_len else 0,

        "digit_ratio":
            digit_cnt / url_len
            if url_len else 0,

        "spec_ratio":
            special_cnt / url_len
            if url_len else 0,

        "is_https":
            1 if parsed.scheme == "https"
            else 0,

        "slash_cnt":
            url.count("/"),

        "entropy":
            calculate_entropy(url),

        "path_len":
            len(path),

        "query_len":
            len(query)
    }

# =========================================================
# FEATURE ENGINEERING
# =========================================================

print("\n[INFO] Extracting lexical features...")

feature_rows = []

for idx, row in df.iterrows():

    feats = extract_url_features(
        row["url"]
    )

    feats["label"] = row["label"]

    feature_rows.append(feats)

    if idx % 10000 == 0 and idx > 0:

        print(
            f"Processed {idx}/{len(df)}"
        )

feature_df = pd.DataFrame(feature_rows)

feature_df.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)

feature_df.fillna(
    0,
    inplace=True
)

# =========================================================
# FEATURES / LABELS
# =========================================================

y = feature_df["label"].astype(int)

X = feature_df.drop(
    columns=["label"]
).astype(float)

# =========================================================
# LOAD FEATURE SCHEMA
# =========================================================

print("\n[INFO] Loading feature schema...")

expected_features = joblib.load(
    SCHEMA_PATH
)

print("\n[INFO] Expected Feature Order:")

print(expected_features)

# =========================================================
# ALIGN FEATURES
# =========================================================

for col in expected_features:

    if col not in X.columns:

        X[col] = 0

X = X[expected_features]

print("\n[INFO] Final Feature Shape:")

print(X.shape)

# =========================================================
# LOAD MODEL
# =========================================================

print("\n[INFO] Loading trained model...")

model = joblib.load(
    MODEL_PATH
)

# =========================================================
# PREDICTIONS
# =========================================================

print("\n[INFO] Running predictions...")

y_prob = model.predict_proba(X)[:, 1]

y_pred = (
    y_prob >= THRESHOLD
).astype(int)

# =========================================================
# METRICS
# =========================================================

acc = accuracy_score(
    y,
    y_pred
)

prec = precision_score(
    y,
    y_pred
)

rec = recall_score(
    y,
    y_pred
)

f1 = f1_score(
    y,
    y_pred
)

roc_auc = roc_auc_score(
    y,
    y_prob
)

cm = confusion_matrix(
    y,
    y_pred
)

# =========================================================
# REPORT
# =========================================================

report = f"""
====================================
URLGuardX ML Benchmark Evaluation
====================================

Dataset Size: {len(y)} URLs
(Balanced 50/50)

------------------------------------

Threshold : {THRESHOLD}

Accuracy  : {acc:.4%}
Precision : {prec:.4%}
Recall    : {rec:.4%}
F1-Score  : {f1:.4%}
AUC-ROC   : {roc_auc:.4f}

=== Classification Report ===

{classification_report(
    y,
    y_pred,
    target_names=[
        "Legitimate",
        "Phishing"
    ]
)}

=== Confusion Matrix ===

{cm}
"""

print(report)

# =========================================================
# SAVE RESULTS
# =========================================================

with open(
    "benchmark_evaluation.txt",
    "w",
    encoding="utf-8"
) as f:

    f.write(report)

print(
    "\n[DONE] Results saved "
    "to benchmark_evaluation.txt"
)