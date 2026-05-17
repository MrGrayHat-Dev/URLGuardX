import time
import requests
import pandas as pd
import numpy as np

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

API_URL = "https://urlguardx-backend.onrender.com/api/v1/scan"

DATASET_PATH = "data/benchmark_urls.csv"

TIMEOUT = 60
RETRIES = 3

# =========================================================
# LOAD DATASET
# =========================================================

df = pd.read_csv(DATASET_PATH)
# =========================================================
# LIMIT DATASET
# =========================================================

PHISH_LIMIT = 50
LEGIT_LIMIT = 50

phish_df = df[df["label"] == 1].head(PHISH_LIMIT)

legit_df = df[df["label"] == 0].head(LEGIT_LIMIT)

df = pd.concat([
    phish_df,
    legit_df
]).sample(frac=1, random_state=42)

print(
    f"[INFO] Evaluating {len(df)} URLs"
)

url_col = "url"
label_col = "label"

urls = df[url_col].astype(str).values
labels = df[label_col].astype(int).values

# =========================================================
# STORAGE
# =========================================================

truth = []
preds = []
scores = []

latencies = []

table3 = {
    "lexical": [],
    "domain": [],
    "ssl": [],
    "full": []
}

# =========================================================
# HELPERS
# =========================================================

def status_to_binary(status):

    status = str(status).lower()

    if status in [
        "danger",
        "high risk",
        "suspicious",
        "warning",
        "phishing"
    ]:
        return 1

    return 0

# =========================================================
# MAIN LOOP
# =========================================================

for idx, (url, label) in enumerate(zip(urls, labels), start=1):

    success = False

    for retry in range(RETRIES):

        try:

            start = time.time()

            response = requests.post(
                API_URL,
                json={"url": url},
                timeout=TIMEOUT
            )

            latency = time.time() - start

            if response.status_code != 200:
                continue

            data = response.json()

            risk_score = float(
                data.get("riskScore", 0)
            )

            status = data.get("status", "Safe")

            pred = status_to_binary(status)

            # ============================================
            # MODULES
            # ============================================

            modules = data.get("modules", {})

            lexical = modules.get("lexical", {})
            domain = modules.get("domain", {})
            ssl = modules.get("ssl", {})
            blacklist = modules.get("blacklist", {})

            lex_bin = status_to_binary(
                lexical.get("status", "Clean")
            )

            dom_bin = status_to_binary(
                domain.get("status", "Clean")
            )

            ssl_bin = status_to_binary(
                ssl.get("status", "Clean")
            )

            full_bin = pred

            table3["lexical"].append(lex_bin)
            table3["domain"].append(
                1 if (lex_bin or dom_bin) else 0
            )

            table3["ssl"].append(
                1 if (lex_bin or dom_bin or ssl_bin)
                else 0
            )

            table3["full"].append(full_bin)

            truth.append(label)
            preds.append(pred)
            scores.append(risk_score / 100.0)

            latencies.append(latency)

            print(
                f"[{idx}] "
                f"STATUS={status} "
                f"RISK={risk_score}"
            )

            success = True
            break

        except Exception as e:

            print(f"[{idx}] ERROR -> {e}")

    if not success:
        print(f"[{idx}] FAILED")

# =========================================================
# FINAL METRICS
# =========================================================

acc = accuracy_score(truth, preds)
pre = precision_score(truth, preds)
rec = recall_score(truth, preds)
f1 = f1_score(truth, preds)
auc = roc_auc_score(truth, scores)

print("\n===================================")
print("URLGuardX Backend Evaluation")
print("===================================")

print(f"Accuracy  : {acc*100:.2f}%")
print(f"Precision : {pre*100:.2f}%")
print(f"Recall    : {rec*100:.2f}%")
print(f"F1-Score  : {f1*100:.2f}%")
print(f"AUC-ROC   : {auc:.4f}")

# =========================================================
# TABLE III
# =========================================================

print("\n===================================")
print("TABLE III — ABLATION")
print("===================================")

for key, name in [
    ("lexical", "Lexical URL only"),
    ("domain", "+ Domain/WHOIS"),
    ("ssl", "+ SSL Validation"),
    ("full", "+ URLHaus Blacklist")
]:

    p = table3[key]

    a = accuracy_score(truth, p)
    f = f1_score(truth, p)

    print(
        f"{name:30s} "
        f"ACC={a*100:.2f}% "
        f"F1={f*100:.2f}%"
    )

# =========================================================
# SAVE REPORT
# =========================================================

with open("backend_results.txt", "w") as f:

    f.write("URLGuardX Backend Evaluation\n")
    f.write("="*50 + "\n\n")

    f.write(f"Accuracy  : {acc*100:.2f}%\n")
    f.write(f"Precision : {pre*100:.2f}%\n")
    f.write(f"Recall    : {rec*100:.2f}%\n")
    f.write(f"F1-Score  : {f1*100:.2f}%\n")
    f.write(f"AUC-ROC   : {auc:.4f}\n\n")

    f.write("TABLE III\n")

    for key, name in [
        ("lexical", "Lexical URL only"),
        ("domain", "+ Domain/WHOIS"),
        ("ssl", "+ SSL Validation"),
        ("full", "+ URLHaus Blacklist")
    ]:

        p = table3[key]

        a = accuracy_score(truth, p)
        f1v = f1_score(truth, p)

        f.write(
            f"{name}: "
            f"ACC={a*100:.2f}% "
            f"F1={f1v*100:.2f}%\n"
        )

print("\n[INFO] Results saved -> backend_results.txt")