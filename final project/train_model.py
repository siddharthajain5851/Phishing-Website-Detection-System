import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd
import pickle
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Load dataset
df = pd.read_csv("dataset.csv")

# Clean URLs
def clean_url(url):
    return re.sub(r"^https?://(www\.)?", "", url)

df["url"] = df["url"].apply(clean_url)

# Vectorization
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df["url"])
y = df["label"]

# Train model
model = LogisticRegression()
model.fit(X, y)

# Save model and vectorizer
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))
pickle.dump(model, open("phishing.pkl", "wb"))

print("\u2705 Model training complete")
print("vectorizer.pkl and phishing.pkl saved")