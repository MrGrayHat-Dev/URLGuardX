import time

import numpy as np
import requests
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

# =========================================================
# CONFIG
# =========================================================

API_URL = "https://urlguardx-backend.onrender.com/api/v1/scan"

# Pre-built balanced benchmark: 50 phishing (label=1) + 50 benign (label=0)
# Sourced from phishing_url_dataset_unique.csv — fixed seed for reproducibility
DATASET_PATH = "data/backend_benchmark_100.csv"

TIMEOUT = 60
RETRIES = 3

# =========================================================
# LOAD DATASET
# =========================================================

df = pd.read_csv(DATASET_PATH)

print(
    f"[INFO] Evaluating {len(df)} URLs "
    f"(phishing={int((df['label']==1).sum())}, "
    f"benign={int((df['label']==0).sum())})"
)

url_col   = "url"
label_col = "label"

urls   = df[url_col].astype(str).values
labels = df[label_col].astype(int).values

# =========================================================
# STORAGE
# =========================================================

truth     = []
preds     = []
scores    = []
latencies = []

# Ablation columns — one prediction list per stage
table3 = {
    "lexical"  : [],   # Stage 1 : ML lexical alone
    "blacklist": [],   # Stage 2 : + Blacklist         (cumulative weighted vote)
    "ssl"      : [],   # Stage 3 : + SSL Validation   (cumulative weighted vote)
    "domain"   : [],   # Stage 4 : + Domain / WHOIS   (cumulative weighted vote)
    "full"     : [],   # Stage 5 : Full pipeline decision
}

# =========================================================
# HELPERS
# =========================================================

def overall_to_binary(status: str) -> int:
    """Map the *top-level* backend status to binary.

    RiskScoringEngine.getFinalStatus() emits exactly:
      'High Risk'  (score >= 70) → phishing   → 1
      'Suspicious' (score >= 40) → ambiguous  → 0
      'Safe'       (score <  40) → benign     → 0

    Only 'High Risk' is treated as a definitive positive.
    Threshold lowered from 75 → 70 to improve recall on novel phishing.
    """
    return 1 if str(status).strip().lower() == "high risk" else 0


def module_to_binary(status: str) -> int:
    """Map a *module-level* ModuleResult status to binary.

    ModuleResult emits exactly: 'Clean' | 'Warning' | 'Danger' | 'Skipped'

    Both 'Danger' and 'Warning' mean the module raised a flag → 1.
    'Clean' and 'Skipped' mean no signal                      → 0.
    """
    return 1 if str(status).strip().lower() in ("danger", "warning") else 0


def mock_engine_decision(lex: int, dom: int, ssl_v: int, bl: int = 0) -> int:
    """Mimics the RiskScoringEngine's hard rules for the cumulative ablation stages.

    Since the engine now uses normalized weightage (Rule 2/3b) and boundary
    overrides (Rule 4), a simple linear sum is no longer accurate.
    
    Approximation logic:
      - Rule 1: Blacklist Danger → always High Risk (1)
      - Rule 2/3b: Any 2+ active modules → normalized score ~100 → High Risk (1)
      - Rule 3/Formula: Any 1 module (except Blacklist) → < 70 → Safe/Suspicious (0)
    """
    if bl == 1:
        return 1
    
    if (lex + dom + ssl_v) >= 2:
        return 1
        
    return 0


# =========================================================
# MAIN EVALUATION LOOP
# =========================================================

for idx, (url, label) in enumerate(zip(urls, labels), start=1):

    success = False

    for retry in range(RETRIES):
        try:
            t0 = time.time()
            response = requests.post(
                API_URL,
                json={"url": url},
                timeout=TIMEOUT,
            )
            latency = time.time() - t0

            if response.status_code != 200:
                print(f"[{idx:>3}] HTTP {response.status_code} — retry {retry+1}")
                continue

            data = response.json()

            # ── Top-level fields ──────────────────────────────────────────
            risk_score = float(data.get("riskScore", 0))
            status     = data.get("status", "Safe")
            pred       = overall_to_binary(status)

            # ── Module results ────────────────────────────────────────────
            modules   = data.get("modules", {})
            lexical   = modules.get("lexical",   {})
            domain    = modules.get("domain",    {})
            ssl       = modules.get("ssl",       {})
            blacklist = modules.get("blacklist", {})

            lex_bin = module_to_binary(lexical.get("status",   "Clean"))
            dom_bin = module_to_binary(domain.get("status",    "Clean"))
            ssl_bin = module_to_binary(ssl.get("status",       "Clean"))
            bl_bin  = module_to_binary(blacklist.get("status", "Clean"))

            # ── Ablation stages ───────────────────────────────────────────
            # Stage 1: Lexical (ML) only
            table3["lexical"].append(lex_bin)

            # Stage 2: Lexical + Blacklist  (OR-gate)
            # OR-gate: phishing if EITHER module flags.
            # Weighted vote is unusable here because blacklist (weight=0.73)
            # returns Clean on novel/unlisted URLs, making lex alone (0.27)
            # unable to cross any threshold → predicts all-0.
            table3["blacklist"].append(1 if (lex_bin or bl_bin) else 0)

            # Stage 3: Lexical + Blacklist + SSL  (OR-gate)
            # Same reasoning — ssl and blacklist rarely fire together,
            # so OR-gate correctly shows the additive detection coverage.
            table3["ssl"].append(1 if (lex_bin or bl_bin or ssl_bin) else 0)

            # Stage 4: All modules — Simulated RiskScoringEngine logic
            # Replaces the linear weighted formula to properly account for the 
            # engine's new normalized scoring rules (Rule 2, 3b, 4).
            table3["domain"].append(
                mock_engine_decision(lex_bin, dom_bin, ssl_bin, bl_bin)
            )

            # Stage 5: Full pipeline (final backend decision)
            table3["full"].append(pred)

            truth.append(label)
            preds.append(pred)
            scores.append(risk_score / 100.0)
            latencies.append(latency)

            print(
                f"[{idx:>3}] label={label} pred={pred} "
                f"status={status!r:12s} risk={risk_score:5.1f} "
                f"latency={latency:.2f}s"
            )

            success = True
            break

        except Exception as exc:
            print(f"[{idx:>3}] ERROR (retry {retry+1}/{RETRIES}) → {exc}")

    if not success:
        print(f"[{idx:>3}] FAILED after {RETRIES} retries — URL skipped")

# =========================================================
# GUARD
# =========================================================

if len(truth) == 0:
    print("[ERROR] No successful responses — cannot compute metrics.")
    exit(1)

# =========================================================
# LATENCY STATS
# =========================================================

lat = np.array(latencies)
lat_avg = lat.mean()
lat_p95 = np.percentile(lat, 95)
lat_min = lat.min()
lat_max = lat.max()

# =========================================================
# OVERALL METRICS
# =========================================================

acc = accuracy_score(truth, preds)
pre = precision_score(truth, preds, zero_division=0)
rec = recall_score(truth, preds, zero_division=0)
f1v = f1_score(truth, preds, zero_division=0)
auc = roc_auc_score(truth, scores)

print("\n===================================")
print("URLGuardX Backend Evaluation")
print("===================================")
print(f"URLs evaluated  : {len(truth)} / {len(urls)}")
print(f"Accuracy        : {acc*100:.2f}%")
print(f"Precision       : {pre*100:.2f}%")
print(f"Recall          : {rec*100:.2f}%")
print(f"F1-Score        : {f1v*100:.2f}%")
print(f"AUC-ROC         : {auc:.4f}")
print(f"\nLatency avg     : {lat_avg:.2f}s")
print(f"Latency p95     : {lat_p95:.2f}s")
print(f"Latency min     : {lat_min:.2f}s")
print(f"Latency max     : {lat_max:.2f}s")

# =========================================================
# TABLE III — ABLATION
# =========================================================

ABLATION_ROWS = [
    ("lexical",   "Lexical (ML only)    "),
    ("blacklist", "+ Blacklist          "),
    ("ssl",       "+ SSL Validation     "),
    ("domain",    "+ Domain / WHOIS     "),
    ("full",      "Full Pipeline        "),
]

print("\n===================================")
print("TABLE III — ABLATION")
print("===================================")
print(f"{'Stage':<26}  {'ACC':>7}  {'P':>7}  {'R':>7}  {'F1':>7}")
print("-" * 62)

for key, name in ABLATION_ROWS:
    p   = table3[key]
    a   = accuracy_score(truth, p)
    pr  = precision_score(truth, p, zero_division=0)
    re  = recall_score(truth, p, zero_division=0)
    fk  = f1_score(truth, p, zero_division=0)
    print(
        f"{name:<26}  "
        f"{a*100:6.2f}%  "
        f"{pr*100:6.2f}%  "
        f"{re*100:6.2f}%  "
        f"{fk*100:6.2f}%"
    )

# =========================================================
# CLASSIFICATION REPORT & CONFUSION MATRIX
# =========================================================

print("\n===================================")
print("CLASSIFICATION REPORT")
print("===================================")
print(classification_report(truth, preds, target_names=["Benign", "Phishing"]))

cm = confusion_matrix(truth, preds)
tn, fp, fn, tp = cm.ravel()
print("Confusion Matrix:")
print(f"  TN={tn}  FP={fp}")
print(f"  FN={fn}  TP={tp}")

# =========================================================
# SAVE REPORT
# =========================================================

with open("backend_results.txt", "w") as out:

    out.write("URLGuardX Backend Evaluation\n")
    out.write("=" * 50 + "\n\n")

    out.write(f"URLs evaluated  : {len(truth)} / {len(urls)}\n")
    out.write(f"Accuracy        : {acc*100:.2f}%\n")
    out.write(f"Precision       : {pre*100:.2f}%\n")
    out.write(f"Recall          : {rec*100:.2f}%\n")
    out.write(f"F1-Score        : {f1v*100:.2f}%\n")
    out.write(f"AUC-ROC         : {auc:.4f}\n\n")

    out.write(f"Latency avg     : {lat_avg:.2f}s\n")
    out.write(f"Latency p95     : {lat_p95:.2f}s\n")
    out.write(f"Latency min     : {lat_min:.2f}s\n")
    out.write(f"Latency max     : {lat_max:.2f}s\n\n")

    out.write("TABLE III — Ablation\n")
    out.write(f"{'Stage':<26}  {'ACC':>7}  {'P':>7}  {'R':>7}  {'F1':>7}\n")
    out.write("-" * 62 + "\n")

    for key, name in ABLATION_ROWS:
        p   = table3[key]
        a   = accuracy_score(truth, p)
        pr  = precision_score(truth, p, zero_division=0)
        re  = recall_score(truth, p, zero_division=0)
        fk  = f1_score(truth, p, zero_division=0)
        out.write(
            f"{name:<26}  "
            f"{a*100:6.2f}%  "
            f"{pr*100:6.2f}%  "
            f"{re*100:6.2f}%  "
            f"{fk*100:6.2f}%\n"
        )

    out.write("\nClassification Report\n")
    out.write(classification_report(truth, preds, target_names=["Benign", "Phishing"]))

    out.write("\nConfusion Matrix:\n")
    out.write(f"  TN={tn}  FP={fp}\n")
    out.write(f"  FN={fn}  TP={tp}\n")

print("\n[INFO] Results saved -> backend_results.txt")