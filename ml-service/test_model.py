import joblib
from features import extract_features

model = joblib.load("model.pkl")

urls = [
    "https://www.google.com",
    "https://www.instagram.com",
    "https://www.flipkart.com",
    "http://paypal-login-security-update.xyz"
]

for url in urls:
    features = extract_features(url)
    pred = model.predict([features])[0]
    prob = model.predict_proba([features])[0][1]

    print("\nURL:", url)
    print("Prediction:", "BAD" if pred == 1 else "GOOD")
    print("Confidence:", round(prob * 100, 2), "%")