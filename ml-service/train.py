# =========================
# FILE: train.py
# =========================

import re
import math
import pandas as pd
import numpy as np
import joblib
import tldextract

from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report
)

# =========================================================
# CONFIG
# =========================================================

MODEL_OUTPUT = "model.pkl"

# =========================================================
# LOAD DATASET
# =========================================================

print("[INFO] Loading dataset...")

df = pd.read_csv(
    "data/final_dataset.csv",
    usecols=["url", "label"]
)

df.drop_duplicates(
    subset=["url"],
    inplace=True
)

df.dropna(inplace=True)

print("\n[INFO] Dataset Statistics:")
print(f"Total URLs : {len(df)}")
print(f"Legitimate : {len(df[df['label']==0])}")
print(f"Phishing   : {len(df[df['label']==1])}")

# =========================================================
# BALANCE DATASET
# =========================================================

print("\n[INFO] Balancing dataset...")

legit_df = df[df["label"] == 0]

phish_df = df[df["label"] == 1]

min_count = min(
    len(legit_df),
    len(phish_df)
)

legit_df = legit_df.sample(
    n=min_count,
    random_state=42
)

phish_df = phish_df.sample(
    n=min_count,
    random_state=42
)

df_balanced = pd.concat([
    legit_df,
    phish_df
]).sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

print("\n[INFO] Balanced Dataset:")
print(f"Legitimate : {len(df_balanced[df_balanced['label']==0])}")
print(f"Phishing   : {len(df_balanced[df_balanced['label']==1])}")

# =========================================================
# SAVE BALANCED DATASET
# =========================================================

df_balanced.to_csv(
    "data/final_dataset.csv",
    index=False
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

    # =====================================================
    # GENERALIZABLE LEXICAL FEATURES ONLY
    # =====================================================

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

for idx, row in df_balanced.iterrows():

    feats = extract_url_features(
        row["url"]
    )

    feats["label"] = row["label"]

    feature_rows.append(feats)

    if idx % 20000 == 0 and idx > 0:
        print(
            f"Processed {idx}/{len(df_balanced)}"
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

print("\n[INFO] Final Feature Shape:")
print(X.shape)

# =========================================================
# SAVE FEATURE SCHEMA
# =========================================================

joblib.dump(
    X.columns.tolist(),
    "feature_schema.pkl"
)

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

# =========================================================
# SAVE HOLDOUT BENCHMARK SET
# =========================================================

benchmark_df = df_balanced.iloc[X_test.index][[
    "url",
    "label"
]]

benchmark_df.to_csv(
    "data/benchmark_urls.csv",
    index=False
)

print(
    "\n[INFO] Saved benchmark URLs "
    "to data/benchmark_urls.csv"
)

# =========================================================
# MODEL TRAINING
# =========================================================

print("\n[INFO] Training RandomForest model...")

rf = RandomForestClassifier(

    n_estimators=150,

    max_depth=25,

    min_samples_split=5,

    min_samples_leaf=2,

    max_features="sqrt",

    random_state=42,

    n_jobs=-1
)

rf.fit(
    X_train,
    y_train
)

# =========================================================
# EVALUATION
# =========================================================

print("\n[INFO] Evaluating model...")

y_pred = rf.predict(X_test)

y_prob = rf.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)

prec = precision_score(y_test, y_pred)

rec = recall_score(y_test, y_pred)

f1 = f1_score(y_test, y_pred)

roc_auc = roc_auc_score(y_test, y_prob)

report = f"""
====================================
URLGuardX Generalized Lexical Model
====================================

Accuracy  : {acc:.4%}
Precision : {prec:.4%}
Recall    : {rec:.4%}
F1-Score  : {f1:.4%}
AUC-ROC   : {roc_auc:.4f}

=== Classification Report ===

{classification_report(
    y_test,
    y_pred,
    target_names=[
        "Legitimate",
        "Phishing"
    ]
)}
"""

print(report)

# =========================================================
# SAVE MODEL
# =========================================================

joblib.dump(
    rf,
    MODEL_OUTPUT,
    compress=3
)

print(
    f"\n[DONE] Model saved to: "
    f"{MODEL_OUTPUT}"
)