from flask import Flask, render_template, request
import pickle
import os

app = Flask(__name__)

# Load model
model = None
try:
    if os.path.exists("phishing.pkl"):
        model = pickle.load(open("phishing.pkl", "rb"))
        print("✅ ML model loaded")
    else:
        print("❌ Model not found")
except Exception as e:
    print("❌ Error loading model:", e)


# Classifier
def classify_url(url):
    url = url.strip().lower()

    if model:
        try:
            pred = model.predict([url])[0]
            return "Phishing" if pred == 1 else "Safe"
        except:
            pass

    # fallback
    keywords = ["login", "verify", "bank", "secure", "account"]
    return "Phishing" if any(k in url for k in keywords) else "Safe"


# Route
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


# Run
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
