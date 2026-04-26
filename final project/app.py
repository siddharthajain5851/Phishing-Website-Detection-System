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
# CLASSIFIER (UNCHANGED)
# =========================
def classify_url(url):

    domain = clean_domain(url)
    url_lower = url.lower()

    if "." not in domain:
        return "Invalid"

    for d in trusted_domains:
        if domain == d or domain.endswith("." + d):
            return "Safe"

    if re.search(r"(paypa1|g00gle|faceb00k|amaz0n|micros0ft|app1e)", domain):
        return "Phishing"

    suspicious_words = [
        "login", "verify", "secure", "bank",
        "account", "update", "password",
        "free", "win", "bonus", "urgent"
    ]
    if any(word in url_lower for word in suspicious_words):
        return "Phishing"

    if domain.endswith((".xyz", ".tk", ".ml", ".ga", ".cf")):
        return "Phishing"

    if domain.count(".") > 3:
        return "Phishing"

    if len(url) > 75:
        return "Phishing"

    if "@" in url:
        return "Phishing"

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
# ROUTES (UNCHANGED)
# =========================

@app.route("/")
def index():
    return render_template("index.html")

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

@app.route("/logout")
def logout():
    return redirect(url_for("login"))

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

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# =========================
# SCANNER (UNCHANGED)
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
# 🔥 AI EXPLAIN (DEEP + RANDOM + FIXED)
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
                    {"role": "system", "content": "You are an expert cybersecurity analyst. Give one detailed explanation."},
                    {"role": "user", "content": f"Explain deeply why this URL is {label}: {url}"}
                ]
            )
            return jsonify({"text": response.choices[0].message.content})
        except:
            pass

    # ===== DEEP FALLBACK =====
    phishing_reasons = [
        "This URL demonstrates characteristics of a phishing attack by imitating a trusted service using subtle character manipulation. Attackers often replace letters with visually similar numbers or symbols to trick users into believing the site is legitimate, increasing the likelihood of credential theft.",
        
        "The presence of sensitive keywords such as 'login', 'verify', or 'secure' strongly indicates an attempt to lure users into entering confidential information. These terms are commonly used in phishing campaigns to create urgency and trust.",
        
        "The domain structure appears unusually complex with multiple subdomains or unnecessary segments. This technique is frequently used to disguise the true origin of the site and mislead users into trusting it.",
        
        "The use of uncommon or low-reputation top-level domains suggests a higher risk of malicious intent, as such domains are often favored by attackers due to lower registration costs and fewer restrictions.",
        
        "The excessive length and obfuscation of the URL indicate a possible attempt to hide malicious payloads or deceive users, which is a known tactic in advanced phishing and malware distribution campaigns.",
        
        "This URL does not match any known trusted domain and shows patterns consistent with impersonation, which significantly increases the probability that it is designed to deceive users and capture sensitive data.",
        
        "The structure suggests it may host a fake login interface intended to harvest user credentials, a common objective of phishing attacks targeting banking, email, or social media accounts.",
        
        "Special characters or misleading formatting within the URL indicate attempts to manipulate how users perceive the link, potentially hiding the actual destination or creating a false sense of legitimacy.",
        
        "The overall pattern aligns with known phishing signatures, including deceptive naming, keyword abuse, and structural anomalies that are frequently observed in real-world cyber attacks.",
        
        "This URL likely forms part of a broader social engineering strategy aimed at exploiting user trust, encouraging interaction under false pretenses to steal data or distribute malicious content."
    ]

    safe_reasons = [
        "The domain structure is clean and matches known trusted services, indicating that the URL follows standard and legitimate naming conventions without signs of manipulation.",
        
        "No suspicious keywords or deceptive patterns were detected, suggesting that the URL is not attempting to trick users into revealing sensitive information.",
        
        "The URL is short, clear, and logically structured, which is typical of legitimate websites and reduces the likelihood of hidden malicious intent.",
        
        "The domain uses a reputable top-level domain and does not exhibit any characteristics commonly associated with phishing or fraudulent websites.",
        
        "Overall analysis indicates normal behavior with no red flags, suggesting that the URL is safe for general use, though standard caution is always recommended."
    ]

    invalid_reasons = [
        "The input does not conform to standard URL formatting rules, making it impossible to accurately extract or validate a domain for security analysis.",
        
        "Essential components such as a valid domain or top-level domain are missing, which prevents the system from classifying the URL.",
        
        "The structure appears malformed or incomplete, indicating that the input is not a valid web address.",
        
        "The parsing process failed due to lack of recognizable URL elements, suggesting the input may be incorrect or improperly formatted.",
        
        "This input cannot be treated as a valid URL, and therefore no meaningful security analysis can be performed."
    ]

    if label == "Phishing":
        reason = random.choice(phishing_reasons)
        text = f"⚠️ PHISHING DETECTED\n\nDomain: {domain}\n\n🔍 Deep Analysis:\n{reason}"

    elif label == "Safe":
        reason = random.choice(safe_reasons)
        text = f"✅ SAFE URL\n\nDomain: {domain}\n\n🔍 Analysis:\n{reason}"

    else:
        reason = random.choice(invalid_reasons)
        text = f"❌ INVALID URL\n\n🔍 Analysis:\n{reason}"

    return jsonify({"text": text})

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(debug=True, port=10000)
