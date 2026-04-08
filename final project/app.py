from flask import Flask, render_template, request
import pickle
import os
from urllib.parse import urlparse

app = Flask(__name__)

# =========================
# LOAD MODEL
# =========================
model = None
try:
    if os.path.exists("phishing.pkl"):
        model = pickle.load(open("phishing.pkl", "rb"))
        print("✅ ML model loaded")
    else:
        print("❌ Model not found")
except Exception as e:
    print("❌ Error loading model:", e)


# =========================
# CLASSIFIER (PRO VERSION)
# =========================
def classify_url(url):
    url = url.strip().lower()

    # ❌ 1. INVALID INPUT
    if "." not in url or len(url) < 5:
        return "Phishing"

    # 👉 2. EXTRACT DOMAIN
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
    except:
        domain = url

    # remove www
    if domain.startswith("www."):
        domain = domain[4:]

    # ✅ 3. TRUSTED DOMAINS (SHORT LINKS SAFE)
    trusted_domains = [
        "youtu.be", "youtube.com",
        "google.com", "github.com",
        "amazon.in", "facebook.com"
    ]

    if any(td in domain for td in trusted_domains):
        return "Safe"

    # ❌ 4. EXTENSION CHECK
    valid_ext = [".com", ".in", ".org", ".net", ".co", ".gov", ".edu"]

    if not any(domain.endswith(ext) for ext in valid_ext):
        return "Phishing"

    # 🚨 5. SUSPICIOUS WORDS (ONLY DOMAIN)
    suspicious_words = [
        "login", "verify", "secure", "bank",
        "account", "update", "password",
        "signin", "paypal", "apple", "facebook",
        "free", "money", "offer", "urgent"
    ]

    if any(word in domain for word in suspicious_words):
        return "Phishing"

    # 🚨 6. EXTRA RULES (ADVANCED)
    if "-" in domain and any(word in domain for word in ["login", "secure", "bank"]):
        return "Phishing"

    if domain.count(".") > 3:
        return "Phishing"

    # 🤖 7. ML MODEL
    if model:
        try:
            pred = model.predict([url])[0]
            return "Phishing" if pred == 1 else "Safe"
        except:
            pass

    # ✅ FINAL SAFE
    return "Safe"


# =========================
# ROUTE
# =========================
@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    safe = 0
    phishing = 0

    if request.method == "POST":
        urls = request.form.get("urls", "").split("\n")
        urls = [u.strip() for u in urls if u.strip()]

        for url in urls:
            label = classify_url(url)

            if label == "Safe":
                safe += 1
                color = "green"
            else:
                phishing += 1
                color = "red"

            results.append({
                "url": url,
                "label": label,
                "color": color
            })

        total = len(urls)

        summary = {
            "total": total,
            "safe": safe,
            "phishing": phishing,
            "risk": round((phishing / max(total, 1)) * 100, 2)
        }

        return render_template("index.html", results=results, summary=summary)

    return render_template("index.html", results=None, summary=None)


# =========================
# RUN (RENDER READY)
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
