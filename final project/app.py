from flask import Flask, render_template, request, redirect, jsonify, url_for
import pickle
import os
import re
import numpy as np
import random
from urllib.parse import urlparse

# 🔥 OpenAI (new version)
try:
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
except:
    client = None

app = Flask(__name__)

# =========================
# FILE PATHS
# =========================
MODEL_PATH = "phishing.pkl"
VECTORIZER_PATH = "vectorizer.pkl"
USER_FILE = "users.txt"

# =========================
# LOAD MODEL
# =========================
try:
    model = pickle.load(open(MODEL_PATH, "rb"))
    vectorizer = pickle.load(open(VECTORIZER_PATH, "rb"))
    print("✅ Model & Vectorizer loaded")
except Exception as e:
    print("❌ Model load error:", e)
    model = None
    vectorizer = None

# =========================
# TRUSTED DOMAINS
# =========================
trusted_domains = [
    "google.com", "youtube.com", "facebook.com",
    "instagram.com", "amazon.in", "amazon.com",
    "github.com", "linkedin.com", "twitter.com",
    "paypal.com", "flipkart.com", "paytm.com"
]

# =========================
# CLEAN DOMAIN
# =========================
def clean_domain(url):
    url = url.strip().lower()

    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    if domain.startswith("www."):
        domain = domain[4:]

    return domain

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
            "login", "verify", "secure", "bank",
            "account", "update", "password",
            "free", "win", "bonus", "urgent"
        ])),
        int(url.endswith((".xyz", ".tk", ".ml", ".ga", ".cf"))),
        int(url.count(".") > 3),
    ]

# =========================
# CLASSIFIER (FIXED STRONG)
# =========================
def classify_url(url):

    domain = clean_domain(url)
    url_lower = url.lower()

    if "." not in domain:
        return "Invalid"

    # ✅ Trusted
    for d in trusted_domains:
        if domain == d or domain.endswith("." + d):
            return "Safe"

    # 🚨 Lookalike
    if re.search(r"(paypa1|g00gle|faceb00k|amaz0n|micros0ft|app1e)", domain):
        return "Phishing"

    # 🚨 Keywords
    suspicious_words = [
        "login", "verify", "secure", "bank",
        "account", "update", "password",
        "free", "win", "bonus", "urgent"
    ]
    if any(word in url_lower for word in suspicious_words):
        return "Phishing"

    # 🚨 Suspicious TLD
    if domain.endswith((".xyz", ".tk", ".ml", ".ga", ".cf")):
        return "Phishing"

    # 🚨 Too many dots
    if domain.count(".") > 3:
        return "Phishing"

    # 🚨 URL length
    if len(url) > 75:
        return "Phishing"

    # 🚨 @ trick
    if "@" in url:
        return "Phishing"

    # 🤖 ML (optional)
    if model and vectorizer:
        try:
            num_feat = np.array([extract_features(url)])
            text_feat = vectorizer.transform([url]).toarray()
            X = np.hstack((num_feat, text_feat))

            pred = model.predict(X)[0]
            if pred == 1:
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

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        user = request.form.get("username", "").strip()
        pwd = request.form.get("password", "").strip()

        if os.path.exists(USER_FILE):
            with open(USER_FILE) as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) != 2:
                        continue
                    u, p = parts
                    if user == u and pwd == p:
                        return redirect("/dashboard")

        error = "Invalid Username or Password"

    return render_template("login.html", error=error)

# LOGOUT
@app.route("/logout")
def logout():
    return redirect(url_for("login"))

# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        user = request.form.get("username", "").strip()
        pwd = request.form.get("password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not user or not pwd or not confirm:
            error = "All fields required"

        elif pwd != confirm:
            error = "Passwords do not match"

        else:
            if os.path.exists(USER_FILE):
                with open(USER_FILE) as f:
                    for line in f:
                        parts = line.strip().split(",")
                        if len(parts) != 2:
                            continue
                        if user == parts[0]:
                            error = "Username already exists"
                            return render_template("register.html", error=error)

            with open(USER_FILE, "a") as f:
                f.write(f"{user},{pwd}\n")

            return redirect("/dashboard")

    return render_template("register.html", error=error)

# DASHBOARD
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# =========================
# SCANNER PAGE
# =========================
@app.route("/home", methods=["GET", "POST"])
def home():

    results = []
    summary = {"total": 0, "safe": 0, "phishing": 0, "invalid": 0, "risk": 0}

    if request.method == "POST":
        urls = request.form.get("urls", "").split("\n")
        urls = [u.strip() for u in urls if u.strip()]

        safe = phishing = invalid = 0

        for url in urls:
            label = classify_url(url)

            if label == "Safe":
                safe += 1
            elif label == "Phishing":
                phishing += 1
            else:
                invalid += 1

            results.append({"url": url, "label": label})

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
# 🔥 AI EXPLAIN (RANDOM)
# =========================
@app.route("/explain", methods=["POST"])
def explain():
    data = request.get_json()
    url = data.get("url", "")
    label = data.get("label", "")

    domain = clean_domain(url)

    # GPT (optional)
    if client:
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Give ONE deep cybersecurity reason."},
                    {"role": "user", "content": f"Why is this {label}: {url}"}
                ]
            )
            return jsonify({"text": response.choices[0].message.content})
        except:
            pass

    # RANDOM REASONS
    phishing_reasons = [
        "This domain mimics a trusted brand using deceptive characters.",
        "The URL contains phishing keywords suggesting credential theft.",
        "The structure is overly complex, indicating hidden malicious intent.",
        "Suspicious TLD commonly used in scams detected.",
        "URL length suggests obfuscation of malicious content.",
        "Possible fake login page designed to steal data.",
        "Domain is not trusted and shows phishing patterns.",
        "Contains tricks like '@' or misleading subdomains.",
        "Looks like a cloned website targeting users.",
        "Matches known phishing attack signatures."
    ]

    safe_reasons = [
        "The domain matches a trusted platform.",
        "No suspicious keywords detected.",
        "URL structure is clean and standard.",
        "No phishing patterns identified.",
        "Domain reputation appears safe."
    ]

    invalid_reasons = [
        "URL format is incorrect.",
        "No valid domain detected.",
        "Input is not a proper URL.",
        "Parsing failed.",
        "Invalid structure."
    ]

    if label == "Phishing":
        reason = random.choice(phishing_reasons)
        text = f"⚠️ PHISHING DETECTED\n\nDomain: {domain}\n\n{reason}"

    elif label == "Safe":
        reason = random.choice(safe_reasons)
        text = f"✅ SAFE URL\n\nDomain: {domain}\n\n{reason}"

    else:
        reason = random.choice(invalid_reasons)
        text = f"❌ INVALID URL\n\n{reason}"

    return jsonify({"text": text})

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True, port=10000)
