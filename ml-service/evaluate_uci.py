# =========================
# FILE: evaluate_uci.py
# =========================

import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
    confusion_matrix,
    ConfusionMatrixDisplay
)

# =========================================================
# LOAD DATASET
# =========================================================

print("[INFO] Loading UCI dataset...")

df = pd.read_csv("uci_phishing.csv")

# =========================================================
# LABEL MAPPING
# =========================================================
# UCI:
#  1  = phishing
# -1  = legitimate

df["Result"] = df["Result"].map({
    -1: 0,
     1: 1
})

# =========================================================
# FEATURES / LABELS
# =========================================================

X = df.drop(columns=["Result"])
y = df["Result"]

# =========================================================
# SPLIT
# =========================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# =========================================================
# MODELS
# =========================================================

models = {
    "Logistic Regression": LogisticRegression(
        max_iter=2000
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        random_state=42,
        n_jobs=-1
    ),

    "Gradient Boosting": GradientBoostingClassifier(
        random_state=42
    )
}

# =========================================================
# STORAGE
# =========================================================

results_lines = []

# =========================================================
# EVALUATION
# =========================================================

print("\n===================================")
print("URLGuardX UCI Benchmark Evaluation")
print("===================================")

best_auc = 0
best_model_name = None

best_probs = None
best_preds = None

for name, model in models.items():

    print(f"\n=== {name} ===")

    model.fit(X_train, y_train)

    preds = model.predict(X_test)

    probs = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, preds)
    pre = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1  = f1_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)

    print(f"Accuracy  : {acc * 100:.2f}%")
    print(f"Precision : {pre * 100:.2f}%")
    print(f"Recall    : {rec * 100:.2f}%")
    print(f"F1-Score  : {f1 * 100:.2f}%")
    print(f"AUC-ROC   : {auc:.4f}")

    results_lines.append(f"\n=== {name} ===")
    results_lines.append(f"Accuracy  : {acc * 100:.2f}%")
    results_lines.append(f"Precision : {pre * 100:.2f}%")
    results_lines.append(f"Recall    : {rec * 100:.2f}%")
    results_lines.append(f"F1-Score  : {f1 * 100:.2f}%")
    results_lines.append(f"AUC-ROC   : {auc:.4f}")

    # =====================================================
    # STORE BEST MODEL
    # =====================================================

    if auc > best_auc:

        best_auc = auc
        best_model_name = name

        best_probs = probs
        best_preds = preds

# =========================================================
# ROC CURVE
# =========================================================

print("\n[INFO] Generating ROC curve...")

fpr, tpr, _ = roc_curve(
    y_test,
    best_probs
)

plt.figure(figsize=(7, 6))

plt.plot(
    fpr,
    tpr,
    linewidth=2,
    label=f"{best_model_name} (AUC = {best_auc:.4f})"
)

plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--"
)

plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")

plt.title(
    "ROC Curve of URLGuardX on UCI Phishing Dataset"
)

plt.legend(loc="lower right")

plt.tight_layout()

plt.savefig(
    "roc_curve.png",
    dpi=300
)

print("[INFO] Saved -> roc_curve.png")

# =========================================================
# CONFUSION MATRIX
# =========================================================

print("[INFO] Generating confusion matrix...")

cm = confusion_matrix(
    y_test,
    best_preds
)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=[
        "Legitimate",
        "Phishing"
    ]
)

disp.plot()

plt.title(
    f"Confusion Matrix ({best_model_name})"
)

plt.tight_layout()

plt.savefig(
    "confusion_matrix.png",
    dpi=300
)

print("[INFO] Saved -> confusion_matrix.png")

# =========================================================
# SAVE RESULTS
# =========================================================

with open(
    "results_summary.txt",
    "w"
) as f:

    f.write(
        "URLGuardX UCI Benchmark Evaluation\n"
    )

    f.write("=" * 50 + "\n")

    for line in results_lines:
        f.write(line + "\n")

    f.write("\n")
    f.write(
        f"Best Model: {best_model_name}\n"
    )

    f.write(
        f"Best AUC: {best_auc:.4f}\n"
    )

print("[INFO] Saved -> results_summary.txt")

# =========================================================
# FINAL PAPER VALUE
# =========================================================

print("\n===================================")
print("FINAL PAPER ROC VALUE")
print("===================================")

print(
    f"ROC curve of URLGuardX on the "
    f"UCI Phishing Dataset "
    f"(AUC = {best_auc:.4f})"
)