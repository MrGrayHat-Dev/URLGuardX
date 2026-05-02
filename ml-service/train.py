import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from features import extract_features


print("Loading dataset...")

df = pd.read_csv("final_dataset.csv")
df = df.dropna()

print("Extracting features...")

X = np.array([extract_features(url) for url in df["URL"]])
y = df["Label"].map({
    "Good": 0,
    "Bad": 1
})

print("Train/Test split...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training model...")

model = RandomForestClassifier(
    n_estimators=500,
    max_depth=25,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Evaluating...")

y_pred = model.predict(X_test)

print("\n===== CLASSIFICATION REPORT =====\n")
print(classification_report(y_test, y_pred))

print("Accuracy:",
      round(accuracy_score(y_test, y_pred) * 100, 2), "%")

joblib.dump(model, "model.pkl")

print("\n✅ model.pkl saved successfully")