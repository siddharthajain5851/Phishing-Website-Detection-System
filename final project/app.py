from flask import Flask, render_template, request, redirect, jsonify, url_for
import pickle
import os
import re
import numpy as np
from urllib.parse import urlparse

# 🔥 OpenAI (new version)
try:
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
except:
    client = None  # fallback if not installed / no key

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
            "free", "win", "bonus"
        ])),
        int(url.endswith((".xyz", ".tk", ".ml"))),
        int(url.count(".") > 3),
    ]

# =========================
# CLASSIFIER
# =========================
def classify_url(url):

    domain = clean_domain(url)

    if "." not in domain:
        return "Invalid"

    # ✅ Trusted
    for d in trusted_domains:
        if domain == d or domain.endswith("." + d):
            return "Safe"

    # 🚨 Lookalike
    if re.search(r"(paypa1|g00gle|faceb00k|amaz0n)", domain):
        return "Phishing"

    # 🚨 Brand attack
    if ("paypal" in domain or "amazon" in domain or "google" in domain) and \
       any(word in domain for word in ["login", "secure", "verify", "account"]):
        return "Phishing"

    # 🚨 Suspicious structure
    if domain.count(".") > 4:
        return "Phishing"

    # 🤖 ML
    if model and vectorizer:
        try:
            num_feat = np.array([extract_features(url)])
            text_feat = vectorizer.transform([url]).toarray()
            X = np.hstack((num_feat, text_feat))

            pred = model.predict(X)[0]
            return "Phishing" if pred == 1 else "Safe"
        except Exception as e:
            print("ML error:", e)

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

# ✅ FIXED LOGOUT
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
# 🔥 AI EXPLAIN
# =========================
# =========================
# 🔥 AI EXPLAIN (DEEP ANALYSIS)
# =========================
@app.route("/explain", methods=["POST"])
def explain():
    data = request.get_json()
    url = data.get("url", "")
    label = data.get("label", "")

    domain = clean_domain(url)

    # ===== TRY GPT =====
    if client:
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity analyst. Give deep but concise analysis."},
                    {"role": "user", "content": f"Explain why this URL is {label}: {url}"}
                ]
            )
            return jsonify({"text": response.choices[0].message.content})
        except Exception as e:
            print("⚠️ OpenAI failed:", e)

    # ===== FALLBACK EXTREME ANALYSIS =====

    if label == "Phishing":
        reasons = [
            "1. Domain may imitate trusted brands using slight spelling variations",
            "2. Use of numbers instead of letters (g00gle, paypa1)",
            "3. Suspicious keywords like login/verify present",
            "4. Possible credential harvesting intent",
            "5. Domain structure overly complex",
            "6. Excessive subdomains detected",
            "7. URL length unusually long",
            "8. Use of uncommon TLD (.xyz, .tk, .ml)",
            "9. Missing HTTPS or fake HTTPS usage",
            "10. Embedded misleading paths",
            "11. Hidden redirect patterns possible",
            "12. Domain not matching official brand",
            "13. Use of hyphens to mimic legit domains",
            "14. Possible social engineering attack",
            "15. Fake account verification trap",
            "16. Likely used in phishing campaigns",
            "17. DNS age likely very new",
            "18. Not in trusted whitelist",
            "19. Brand + keyword combo detected",
            "20. Looks like login portal spoof",
            "21. May steal cookies/session",
            "22. Suspicious URL encoding possible",
            "23. Domain impersonation risk",
            "24. Fake payment gateway possibility",
            "25. Could trigger malware download",
            "26. URL entropy high (random chars)",
            "27. Likely blacklisted pattern",
            "28. Social media bait structure",
            "29. Urgency-based wording likely",
            "30. Data exfiltration risk",
            "31. Possible phishing kit deployment",
            "32. Not verified by SSL authority",
            "33. Mismatch between domain & content",
            "34. Credential reuse attack vector",
            "35. Could host fake forms",
            "36. Suspicious redirect chains",
            "37. Likely spoofed UI pages",
            "38. High phishing probability score",
            "39. Looks auto-generated",
            "40. Domain reputation unknown",
            "41. Likely mass phishing usage",
            "42. Short-lived domain lifecycle",
            "43. May bypass filters via tricks",
            "44. Contains bait keywords",
            "45. May target banking credentials",
            "46. Possible API abuse endpoint",
            "47. Fake security alert simulation",
            "48. High-risk classification rules matched",
            "49. ML model flagged suspicious patterns",
            "50. Overall phishing confidence: HIGH"
        ]

        text = "⚠️ PHISHING DETECTED\n\nDomain: {}\n\n".format(domain)
        text += "\n".join(["• " + r for r in reasons])

    elif label == "Safe":
        reasons = [
            "1. Domain matches known trusted service",
            "2. Clean and simple URL structure",
            "3. No suspicious keywords detected",
            "4. Proper HTTPS usage likely",
            "5. No excessive subdomains",
            "6. No impersonation patterns",
            "7. Matches whitelist database",
            "8. No phishing patterns found",
            "9. Stable domain reputation",
            "10. Overall safety confidence: HIGH"
        ]

        text = "✅ SAFE URL\n\nDomain: {}\n\n".format(domain)
        text += "\n".join(["• " + r for r in reasons])

    else:
        reasons = [
            "1. URL format incorrect",
            "2. Missing domain structure",
            "3. No valid TLD detected",
            "4. Possibly incomplete input",
            "5. Parsing failed",
            "6. Domain extraction error",
            "7. Not a valid web address",
            "8. Missing protocol or hostname",
            "9. Input not URL-like",
            "10. Validation failed"
        ]

        text = "❌ INVALID URL\n\n"
        text += "\n".join(["• " + r for r in reasons])

    return jsonify({"text": text})
 

# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True, port=10000)
