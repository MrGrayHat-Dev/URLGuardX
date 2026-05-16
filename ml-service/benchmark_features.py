# =========================
# FILE: benchmark_features.py
# =========================

import pandas as pd
import numpy as np
import re
import math
import tldextract

from urllib.parse import urlparse

# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(text):

    prob = [
        float(text.count(c)) / len(text)
        for c in dict.fromkeys(list(text))
    ]

    entropy = -sum([
        p * math.log(p) / math.log(2.0)
        for p in prob
    ])

    return entropy


# =========================================================
# IP DETECTION
# =========================================================

def is_ip(domain):

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    return 1 if re.match(pattern, domain) else 0


# =========================================================
# FEATURE EXTRACTION
# =========================================================

def extract_features(url):

    try:

        parsed = urlparse(url)

        domain = parsed.netloc

        ext = tldextract.extract(url)

        suffix = ext.suffix
        tld = suffix
        # =================================================
        # BASIC FEATURES
        # =================================================

        url_len = len(url)

        dom_len = len(domain)

        dom = domain

        is_https = 1 if parsed.scheme == "https" else 0

        is_ip_addr = is_ip(domain)

        subdom_cnt = (
            len(ext.subdomain.split("."))
            if ext.subdomain else 0
        )

        tld_len = len(suffix)

        path_len = len(parsed.path)

        query_len = len(parsed.query)

        # =================================================
        # COUNTS
        # =================================================

        letter_cnt = sum(c.isalpha() for c in url)

        digit_cnt = sum(c.isdigit() for c in url)

        dot_cnt = url.count(".")

        dash_cnt = url.count("-")

        qm_cnt = url.count("?")

        amp_cnt = url.count("&")

        eq_cnt = url.count("=")

        slash_cnt = url.count("/")

        special_cnt = sum(
            not c.isalnum()
            for c in url
        )

        # =================================================
        # RATIOS
        # =================================================

        digit_ratio = (
            digit_cnt / url_len
            if url_len > 0 else 0
        )
        

        # =================================================
        # ENTROPY
        # =================================================

        entropy = calculate_entropy(url)

        # =================================================
        # FINAL FEATURE VECTOR
        # =================================================

        return {
            "url_len": url_len,
            "dom_len": dom_len,
            "dom": dom,
            "is_https": is_https,
            "is_ip": is_ip_addr,
            "subdom_cnt": subdom_cnt,
            "tld_len": tld_len,
            "path_len": path_len,
            "query_len": query_len,
            "letter_cnt": letter_cnt,
            "digit_cnt": digit_cnt,
            "dot_cnt": dot_cnt,
            "dash_cnt": dash_cnt,
            "qm_cnt": qm_cnt,
            "amp_cnt": amp_cnt,
            "eq_cnt": eq_cnt,
            "slash_cnt": slash_cnt,
            "tld": tld,
            "digit_ratio": digit_ratio,
            "under_cnt": url.count("_"),
            "special_cnt": special_cnt,
            "letter_ratio": (
                letter_cnt / url_len
                if url_len > 0 else 0
            ),

            "spec_ratio": (
                special_cnt / url_len
                if url_len > 0 else 0
            ),

            "entropy": entropy
        }

    except:

        return None


# =========================================================
# MAIN
# =========================================================

print("[INFO] Loading benchmark URLs...")

df = pd.read_csv(
    "phishing_url_dataset_unique.csv"
)

print("[INFO] Dataset Shape:", df.shape)

# =========================================================
# KEEP REQUIRED COLUMNS
# =========================================================

df = df[["url", "label"]]

# =========================================================
# EXTRACT FEATURES
# =========================================================

print("[INFO] Extracting lexical features...")

feature_rows = []

for idx, row in df.iterrows():

    url = row["url"]

    label = row["label"]

    features = extract_features(url)

    if features is None:
        continue

    features["label"] = label

    feature_rows.append(features)

    if idx % 1000 == 0:

        print(
            f"[INFO] Processed {idx}/{len(df)} URLs"
        )

# =========================================================
# CREATE DATAFRAME
# =========================================================

features_df = pd.DataFrame(feature_rows)

# =========================================================
# SAVE
# =========================================================

OUTPUT_FILE = "benchmark_features.csv"

features_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\n===================================")
print("FEATURE EXTRACTION COMPLETED")
print("===================================")

print("\nSaved File:", OUTPUT_FILE)

print("\nShape:", features_df.shape)

print("\nColumns:")
print(features_df.columns)