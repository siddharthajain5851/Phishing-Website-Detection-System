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
# LOAD MODEL SAFELY
# =========================
try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    with open(VECTORIZER_PATH, "rb") as f:
        vectorizer = pickle.load(f)
    print("✅ ML model loaded")
except Exception as e:
    print("⚠️ ML model not loaded:", e)
    model = None
    vectorizer = None


# =========================
# TRUSTED DOMAINS
# =========================
trusted_domains = [
    "google.com", "youtube.com", "facebook.com",
    "instagram.com", "amazon.in", "github.com",
    "linkedin.com", "twitter.com", "paypal.com"
]


# =========================
# CLEAN URL
# =========================
def clean_url(url):
    url = url.lower().strip()
    url = re.sub(r"^https?://(www\.)?", "", url)
    return url


# =========================
# VALID URL CHECK
# =========================
def is_valid_url(url):
    return "." in url and len(url) > 5


# =========================
# CLASSIFIER ENGINE
# =========================
def classify_url(url):

    url = clean_url(url)

    if not is_valid_url(url):
        return "Invalid"

    # SAFE DOMAIN CHECK (STRICT)
    for domain in trusted_domains:
        if url == domain or url.endswith("." + domain):
            return "Safe"

    # LOOKALIKE ATTACKS
    if re.search(r"(paypa1|paypai|g00gle|faceb00k|amazan)", url):
        return "Phishing"

    # KEYWORDS
    phishing_keywords = [
        "login", "verify", "secure", "bank",
        "update", "password", "account",
        "signin", "confirm", "urgent",
        "free", "bonus", "win", "click"
    ]

    if any(word in url for word in phishing_keywords):
        return "Phishing"

    # STRUCTURE CHECK
    if "-" in url or url.count(".") > 3:
        return "Phishing"

    # ML MODEL
    if model and vectorizer:
        try:
            X = vectorizer.transform([url])
            if model.predict(X)[0] == 1:
                return "Phishing"
        except:
            pass

    return "Safe"


# =========================
# ROUTES
# =========================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/home", methods=["GET", "POST"])
def home():
    results = []

    safe = 0
    phishing = 0
    invalid = 0

    summary = {
        "total": 0,
        "safe": 0,
        "phishing": 0,
        "invalid": 0,
        "risk": 0
    }

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

        total = len(results)

        summary = {
            "total": total,
            "safe": safe,
            "phishing": phishing,
            "invalid": invalid,
            "risk": round((phishing / max(total, 1)) * 100, 2)
        }

    return render_template("home.html", results=results, summary=summary)


# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
