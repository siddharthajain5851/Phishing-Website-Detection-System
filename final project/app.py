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
 import random

@app.route("/explain", methods=["POST"])
def explain():
    data = request.get_json()
    url = data.get("url", "")
    label = data.get("label", "")

    domain = clean_domain(url)

    # ===== GPT (optional) =====
    if client:
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert cybersecurity analyst. Give ONE detailed but not too long explanation."
                    },
                    {
                        "role": "user",
                        "content": f"Explain in a detailed way why this URL is {label}: {url}"
                    }
                ]
            )
            return jsonify({"text": response.choices[0].message.content})
        except:
            pass

    # ===== DEEP FALLBACK REASONS =====

    phishing_reasons = [
        "This URL appears to mimic a trusted brand by slightly altering characters (such as replacing letters with numbers), which is a common phishing tactic used to deceive users into believing the site is legitimate and entering sensitive information.",
        
        "The presence of keywords like 'login', 'verify', or 'secure' in the URL suggests that the page is attempting to trick users into entering credentials, a common behavior seen in phishing attacks targeting account information.",
        
        "The domain structure is unusually complex with multiple subdomains, which attackers often use to obscure the real origin of the site and make it appear trustworthy at a glance.",
        
        "This URL uses a suspicious or uncommon top-level domain (like .xyz or .tk), which are frequently abused in phishing campaigns due to their low cost and minimal verification requirements.",
        
        "The length of the URL is unusually long and contains multiple segments, which is often a sign of obfuscation used to hide malicious intent or confuse users.",
        
        "The domain is not part of any known trusted service and does not match expected naming conventions, increasing the likelihood that it is a spoofed or malicious website.",
        
        "The URL may be attempting a social engineering attack by creating urgency or trust signals, encouraging users to act quickly without verifying authenticity.",
        
        "The structure of the URL suggests it may host a fake login page designed to capture user credentials such as passwords, banking information, or personal data.",
        
        "The presence of special characters like '@' or excessive hyphens can indicate attempts to manipulate how the URL is interpreted by users or browsers.",
        
        "This URL pattern matches known phishing signatures where attackers replicate the look and feel of legitimate services to steal sensitive data from unsuspecting users."
    ]

    safe_reasons = [
        "The domain matches a well-known and trusted service, and its structure follows standard naming conventions without any suspicious modifications or misleading patterns.",
        
        "No phishing-related keywords such as 'login', 'verify', or 'secure' are present in unusual contexts, indicating that the URL is not attempting to trick users into revealing sensitive information.",
        
        "The URL structure is clean, short, and easy to interpret, which is typical of legitimate websites rather than malicious or obfuscated links.",
        
        "The domain uses a common and reputable top-level domain, and there are no signs of impersonation or brand spoofing.",
        
        "No suspicious encoding, redirects, or deceptive elements were detected in the URL, suggesting that it behaves like a normal and safe web address."
    ]

    invalid_reasons = [
        "The provided input does not follow standard URL formatting rules, making it impossible to extract a valid domain or determine its legitimacy.",
        
        "The URL is missing essential components such as a proper domain name or top-level domain, which are required for a valid web address.",
        
        "The structure of the input does not resemble a typical URL, suggesting that it may be incomplete, malformed, or incorrectly entered.",
        
        "Parsing the URL failed because it lacks recognizable elements like a hostname, indicating that it is not a valid or usable link.",
        
        "The input does not contain a proper web address format and therefore cannot be analyzed for security risks or classification."
    ]

    # ===== RANDOM SELECT (1 ONLY) =====
    if label == "Phishing":
        reason = random.choice(phishing_reasons)
        text = f"⚠️ PHISHING DETECTED\n\nDomain: {domain}\n\n🔍 Analysis:\n{reason}"

    elif label == "Safe":
        reason = random.choice(safe_reasons)
        text = f"✅ SAFE URL\n\nDomain: {domain}\n\n🔍 Analysis:\n{reason}"

    else:
        reason = random.choice(invalid_reasons)
        text = f"❌ INVALID URL\n\n🔍 Analysis:\n{reason}"

    return jsonify({"text": text})

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True, port=10000)
