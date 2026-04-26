import pandas as pd
import pickle
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score
from sklearn.utils import shuffle

# =========================
# LOAD DATA
# =========================
df = pd.read_csv("dataset.csv")

# Ensure labels numeric
df["label"] = df["label"].astype(int)

# Clean dataset
df = df.dropna()
df = df.drop_duplicates()

# Shuffle dataset
df = shuffle(df, random_state=42)

print(f"📊 Total samples: {len(df)}")

# =========================
# FEATURE ENGINEERING
# =========================
def extract_features(url):
    url = str(url).lower()

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        int("https" in url),
        int(any(word in url for word in [
            "login","verify","secure","bank",
            "account","update","password",
            "free","win","bonus"
        ])),
        int(url.endswith((".xyz",".tk",".ml"))),
        int(url.count(".") > 3),
    ]

# =========================
# SPLIT FIRST (IMPORTANT FIX)
# =========================
X_train_urls, X_test_urls, y_train, y_test = train_test_split(
    df["url"], df["label"], test_size=0.3, random_state=42
)

# =========================
# TEXT FEATURES (TF-IDF)
# =========================
print("🔧 Extracting text features...")

vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1,2)
)

X_train_text = vectorizer.fit_transform(X_train_urls).toarray()
X_test_text = vectorizer.transform(X_test_urls).toarray()

# =========================
# NUMERIC FEATURES
# =========================
print("🔧 Extracting numeric features...")

X_train_num = np.array([extract_features(u) for u in X_train_urls])
X_test_num = np.array([extract_features(u) for u in X_test_urls])

# =========================
# COMBINE FEATURES
# =========================
X_train = np.hstack((X_train_num, X_train_text))
X_test = np.hstack((X_test_num, X_test_text))

# =========================
# MODEL TRAINING
# =========================
print("🤖 Training model...")

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=12,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train, y_train)

# =========================
# EVALUATION
# =========================
pred = model.predict(X_test)
acc = accuracy_score(y_test, pred)

print(f"✅ Accuracy: {round(acc * 100, 2)}%")

# =========================
# SAVE MODEL
# =========================
pickle.dump(model, open("phishing.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("💾 Model saved → phishing.pkl")
print("💾 Vectorizer saved → vectorizer.pkl")