from flask import Flask, render_template, request
import pickle
import os

app = Flask(__name__)

# =========================
# LOAD MODEL
# =========================
MODEL_PATH = "phishing.pkl"

model = None

try:
    if os.path.exists(MODEL_PATH):
        model = pickle.load(open(MODEL_PATH, "rb"))
        print("✅ ML model loaded")
    else:
        print("❌ Model file not found")
except Exception as e:
    print("❌ Model load error:", e)
    model = None


# =========================
# CLASSIFIER
# =========================
def classify_url(url):
    url = url.strip().lower()

    # ML prediction
    if model:
        try:
            X = [url]
            pred = model.predict(X)[0]
            return "Phishing" if pred == 1 else "Safe"
        except:
            pass

    # Fallback rules
    phishing_keywords = [
        "login", "verify", "secure", "bank",
        "account", "update", "password",
        "signin", "paypal", "apple", "facebook"
    ]

    return "Phishing" if any(word in url for word in phishing_keywords) else "Safe"


# =========================
# ROUTE
# =========================
@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    safe = 0
    phishing = 0

    if request.method == "POST":
        urls = request.form.get("urls", "").strip().split("\n")
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
# RUN
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
