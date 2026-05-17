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

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, classification_report, confusion_matrix
)

print("[INFO] Loading data/benchmark_urls.csv...")
df_balanced = pd.read_csv("data/benchmark_urls.csv", usecols=["url", "label"])

print(f"\n[INFO] Evaluation Dataset Shape:")
print(f"  Benign (0)  : {len(df_balanced[df_balanced['label'] == 0])}")
print(f"  Phishing (1): {len(df_balanced[df_balanced['label'] == 1])}")

# =========================================================
# FEATURE EXTRACTION LOGIC
# =========================================================
def calculate_entropy(text):
    if not text: return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum(p * math.log2(p) for p in prob)

def extract_url_features(url):
    url = str(url)
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = parsed.netloc
    suffix = ext.suffix
    path   = parsed.path
    query  = parsed.query
    url_len = len(url)
    letter_cnt  = sum(c.isalpha()  for c in url)
    digit_cnt   = sum(c.isdigit()  for c in url)
    special_cnt = len(re.findall(r"[^A-Za-z0-9]", url))
    return {
        "url_len":      url_len,
        "dom":          domain,
        "dom_len":      len(domain),
        "is_ip":        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0,
        "tld":          suffix,
        "tld_len":      len(suffix),
        "subdom_cnt":   len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "letter_cnt":   letter_cnt,
        "digit_cnt":    digit_cnt,
        "special_cnt":  special_cnt,
        "eq_cnt":       url.count("="),
        "qm_cnt":       url.count("?"),
        "amp_cnt":      url.count("&"),
        "dot_cnt":      url.count("."),
        "dash_cnt":     url.count("-"),
        "under_cnt":    url.count("_"),
        "letter_ratio": letter_cnt  / url_len if url_len else 0,
        "digit_ratio":  digit_cnt   / url_len if url_len else 0,
        "spec_ratio":   special_cnt / url_len if url_len else 0,
        "is_https":     1 if parsed.scheme == "https" else 0,
        "slash_cnt":    url.count("/"),
        "entropy":      calculate_entropy(url),
        "path_len":     len(path),
        "query_len":    len(query),
    }

print("\n[INFO] Extracting lexical features...")
feature_rows = []
for idx, row in df_balanced.iterrows():
    feats = extract_url_features(row["url"])
    if feats:
        feats["label"] = row["label"]
        feature_rows.append(feats)

feature_df = pd.DataFrame(feature_rows)

print("[INFO] Encoding categorical features...")
for col in feature_df.select_dtypes(include=["object"]).columns:
    if col == "label": continue
    feature_df[col] = LabelEncoder().fit_transform(feature_df[col].astype(str))

feature_df.replace([np.inf, -np.inf], np.nan, inplace=True)
feature_df.fillna(0, inplace=True)

y = feature_df["label"].astype(int)
X = feature_df.drop(columns=["label"]).astype(float)

# =========================================================
# ALIGN WITH FEATURE SCHEMA
# =========================================================
print("[INFO] Aligning features with training schema...")
expected_features = joblib.load("feature_schema.pkl")
for col in expected_features:
    if col not in X.columns:
        X[col] = 0
X = X[expected_features]

# =========================================================
# EVALUATE
# =========================================================
print("[INFO] Loading trained model...")
model = joblib.load("model.pkl")

print("[INFO] Running predictions...")
y_pred = model.predict(X)
y_prob = model.predict_proba(X)[:, 1]

acc = accuracy_score(y, y_pred)
prec = precision_score(y, y_pred)
rec = recall_score(y, y_pred)
f1 = f1_score(y, y_pred)
roc_auc = roc_auc_score(y, y_prob)

report = f"""====================================
URLGuardX Benchmark Evaluation
====================================
Dataset Size: {len(y)} URLs (Balanced 50/50)
------------------------------------
Accuracy  : {acc:.4%}
Precision : {prec:.4%}
Recall    : {rec:.4%}
F1-Score  : {f1:.4%}
AUC-ROC   : {roc_auc:.4f}

=== Classification Report ===
{classification_report(y, y_pred, target_names=["Legitimate", "Phishing"])}

=== Confusion Matrix ===
{confusion_matrix(y, y_pred)}
"""

print(report)

with open("benchmark_evaluation.txt", "w", encoding="utf-8") as f:
    f.write(report)
print("[DONE] Evaluation saved to benchmark_evaluation.txt")