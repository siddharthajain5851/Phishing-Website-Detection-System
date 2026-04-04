import pandas as pd
import pickle
import re
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# =========================
# LOAD DATA
# =========================
df = pd.read_csv("dataset.csv")

# =========================
# FEATURE ENGINEERING
# =========================
def extract_features(url):
    url = url.lower()

    return [
        len(url),                         # URL length
        url.count("."),                  # number of dots
        url.count("-"),                  # hyphens
        url.count("@"),                  # @ symbols
        int("https" in url),             # https present
        int(any(word in url for word in [
            "login", "verify", "secure", "bank",
            "account", "update", "password",
            "paypal", "free", "gift"
        ])),                              # phishing keywords
    ]

# =========================
# BUILD FEATURES
# =========================
X = np.array([extract_features(u) for u in df["url"]])
y = df["label"]

# =========================
# TRAIN TEST SPLIT
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# =========================
# MODEL (STRONGER)
# =========================
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X_train, y_train)

# =========================
# EVALUATION
# =========================
pred = model.predict(X_test)
print("✅ Accuracy:", accuracy_score(y_test, pred))

# =========================
# SAVE MODEL
# =========================
pickle.dump(model, open("phishing.pkl", "wb"))

print("✅ Model saved successfully")
