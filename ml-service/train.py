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
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, classification_report, confusion_matrix
)

# =========================================================
# CONFIG
# =========================================================
MODEL_OUTPUT = "model.pkl"

# =========================================================
# LOAD AND COMBINE DATASETS IN MEMORY
# =========================================================
print("[INFO] Loading datasets into memory...")

# 1. Dataset.csv
try:
    df_main = pd.read_csv('data/Dataset.csv', usecols=['url', 'label'])
except Exception as e:
    print(f"[ERROR] Failed to load Dataset.csv: {e}")
    df_main = pd.DataFrame(columns=['url', 'label'])

# 2. PhishTank (Phishing)
try:
    df_phishtank = pd.read_csv('data/phishtank.csv', usecols=['url'])
    df_phishtank['label'] = 1
except Exception as e:
    print(f"[ERROR] Failed to load phishtank.csv: {e}")
    df_phishtank = pd.DataFrame(columns=['url', 'label'])

# 3. Phishing URL Dataset Unique
try:
    df_unique = pd.read_csv('data/phishing_url_dataset_unique.csv', usecols=['url', 'label'])
except Exception as e:
    print(f"[ERROR] Failed to load phishing_url_dataset_unique.csv: {e}")
    df_unique = pd.DataFrame(columns=['url', 'label'])

print("[INFO] Combining and deduplicating datasets...")
df_all = pd.concat([df_main, df_phishtank, df_unique], ignore_index=True)
df_all.drop_duplicates(subset=['url'], inplace=True)

# =========================================================
# BALANCE THE DATASET
# =========================================================
benign_df = df_all[df_all['label'] == 0]
phish_df = df_all[df_all['label'] == 1]

print(f"\n[INFO] Before Balancing:")
print(f"  Benign (0)  : {len(benign_df)}")
print(f"  Phishing (1): {len(phish_df)}")

# Balance perfectly
min_count = min(len(benign_df), len(phish_df))
benign_df = benign_df.sample(n=min_count, random_state=42)
phish_df = phish_df.sample(n=min_count, random_state=42)

df_balanced = pd.concat([benign_df, phish_df], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\n[INFO] After Balancing (Training Set):")
print(f"  Benign (0)  : {len(df_balanced[df_balanced['label'] == 0])}")
print(f"  Phishing (1): {len(df_balanced[df_balanced['label'] == 1])}")

print("\n[INFO] Saving balanced dataset to data/final_dataset.csv...")
try:
    df_balanced.to_csv('data/final_dataset.csv', index=False)
    print("[INFO] Successfully saved data/final_dataset.csv")
except Exception as e:
    print(f"[WARNING] Failed to save final_dataset.csv (possibly blocked by antivirus): {e}")

# =========================================================
# LEXICAL FEATURE EXTRACTION
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

print("\n[INFO] Extracting lexical features from raw URLs (this may take a minute)...")
feature_rows = []
for idx, row in df_balanced.iterrows():
    feats = extract_url_features(row["url"])
    if feats:
        feats["label"] = row["label"]
        feature_rows.append(feats)
    if idx % 20000 == 0 and idx > 0:
        print(f"  Processed {idx}/{len(df_balanced)}")

feature_df = pd.DataFrame(feature_rows)

# Encode categorical columns
print("[INFO] Encoding categorical features...")
for col in feature_df.select_dtypes(include=["object"]).columns:
    if col == "label": continue
    feature_df[col] = LabelEncoder().fit_transform(feature_df[col].astype(str))

feature_df.replace([np.inf, -np.inf], np.nan, inplace=True)
feature_df.fillna(0, inplace=True)

y = feature_df["label"].astype(int)
X = feature_df.drop(columns=["label"]).astype(float)

print("\n[INFO] Final Feature Matrix Shape:", X.shape)

# Save feature schema for inference
joblib.dump(X.columns.tolist(), "feature_schema.pkl")

# =========================================================
# TRAIN / TEST SPLIT & MODEL TRAINING
# =========================================================
# Split the raw dataframe so we can save the exact 20% holdout URLs
train_df, test_df, y_train, y_test = train_test_split(
    df_balanced, y, test_size=0.2, stratify=y, random_state=42
)

print("\n[INFO] Saving 20% holdout raw URLs to data/benchmark_urls.csv...")
try:
    test_df[['url', 'label']].to_csv('data/benchmark_urls.csv', index=False)
    print("[INFO] Successfully saved data/benchmark_urls.csv")
except Exception as e:
    print(f"[WARNING] Failed to save benchmark_urls.csv: {e}")

# Now split the feature matrix using the exact same random state
X_train, X_test, _, _ = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

print("\n[INFO] Training RandomForest model...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

# =========================================================
# EVALUATION
# =========================================================
print("\n[INFO] Running evaluation...")
y_pred = rf.predict(X_test)
y_prob = rf.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_prob)

report = f"""====================================
URLGuardX Lexical Model Results
====================================
Accuracy  : {acc:.4%}
Precision : {prec:.4%}
Recall    : {rec:.4%}
F1-Score  : {f1:.4%}
AUC-ROC   : {roc_auc:.4f}

=== Classification Report ===
{classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])}
"""

print(report)

# =========================================================
# SAVE MODEL
# =========================================================
joblib.dump(rf, MODEL_OUTPUT)
print(f"\n[DONE] Model saved successfully to: {MODEL_OUTPUT}")
