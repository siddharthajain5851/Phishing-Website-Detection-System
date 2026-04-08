from flask import Flask, render_template, request
import pickle
import os
import re

app = Flask(__name__)

MODEL_PATH = "phishing.pkl"
VECTORIZER_PATH = "vectorizer.pkl"

model = None
vectorizer = None

# =========================
# LOAD MODEL
# =========================
if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
    model = pickle.load(open(MODEL_PATH, "rb"))
    vectorizer = pickle.load(open(VECTORIZER_PATH, "rb"))
    print("✅ ML model loaded")
else:
    print("⚠️ Using rule-based detection")

# =========================
# TRUSTED DOMAINS
# =========================
trusted_domains = [
    "google.com", "youtube.com", "youtu.be",
    "facebook.com", "instagram.com",
    "amazon.in", "github.com",
    "linkedin.com", "twitter.com"
]

# =========================
# VALID URL CHECK 🔥
# =========================
def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)?'              # http:// or https://
        r'([\da-z\.-]+)\.([a-z\.]{2,})' # domain
        r'([\/\w\.-]*)*\/?$'
    )
    return re.match(regex, url)

# =========================
# CLEAN URL
# =========================
def clean_url(url):
    url = url.lower().strip()
    url = re.sub(r"^https?://(www\.)?", "", url)
    return url

# =========================
# CLASSIFIER 🔥 UPDATED
# =========================
def classify_url(url):

    # ❌ INVALID CHECK FIRST
    if not is_valid_url(url):
        return "Invalid"

    url = clean_url(url)

    # ✅ TRUSTED
    for domain in trusted_domains:
        if domain in url:
            return "Safe"

    # 🤖 ML MODEL
    if model and vectorizer:
        X = vectorizer.transform([url])
        pred = model.predict(X)[0]

        if pred == 1:
            return "Phishing"

    # ⚠️ RULE-BASED CHECKS
    phishing_keywords = [
        "login", "verify", "secure", "bank",
        "update", "password", "account",
        "signin", "confirm", "urgent",
        "free", "bonus", "win", "click"
    ]

    if any(word in url for word in phishing_keywords):
        return "Phishing"

    if "-" in url or url.count(".") > 2:
        return "Phishing"

    return "Safe"

# =========================
# ROUTES
# =========================

@app.route("/")
def splash():
    return render_template("index.html")

@app.route("/home", methods=["GET", "POST"])
def home():
    results = []
    safe = phishing = invalid = 0

    if request.method == "POST":
        urls = request.form.get("urls", "").split("\n")
        urls = [u.strip() for u in urls if u.strip()]

        for url in urls:
            label = classify_url(url)

            if label == "Safe":
                safe += 1
            elif label == "Phishing":
                phishing += 1
            else:
                invalid += 1

            results.append({
                "url": url,
                "label": label
            })

        total = len(urls)

        summary = {
            "total": total,
            "safe": safe,
            "phishing": phishing,
            "invalid": invalid,
            "risk": round((phishing / max(total, 1)) * 100, 2)
        }

        return render_template("home.html", results=results, summary=summary)

    return render_template("home.html", results=None, summary=None)

# =========================
if __name__ == "__main__":
    app.run(debug=True)
