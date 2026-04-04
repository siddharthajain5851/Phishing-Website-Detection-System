from flask import Flask, render_template, request
import pickle
import numpy as np
import os

app = Flask(__name__)

MODEL_PATH = "phishing.pkl"

model = None

if os.path.exists(MODEL_PATH):
    model = pickle.load(open(MODEL_PATH, "rb"))
    print("✅ ML model loaded")
else:
    print("⚠️ Model not found")


# =========================
# FEATURE FUNCTION
# =========================
def extract_features(url):
    url = url.lower()

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        int("https" in url),
        int(any(word in url for word in [
            "login", "verify", "secure", "bank",
            "account", "update", "password",
            "paypal", "free", "gift"
        ])),
    ]


def classify_url(url):
    features = np.array(extract_features(url)).reshape(1, -1)

    if model:
        pred = model.predict(features)[0]
        return "Phishing" if pred == 1 else "Safe"

    return "Safe"


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    safe = phishing = 0

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=True)
