 from flask import Flask, render_template, request ,jsonify
import pickle
import re

app = Flask(__name__)

# Load trained files
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))
model = pickle.load(open("phishing.pkl", "rb"))

@app.route("/", methods=["GET", "POST"])
def index():
    prediction = ""

    if request.method == "POST":
        url = request.form.get("url")

        cleaned_url = re.sub(r"^https?://(www\.)?", "", url)
        result = model.predict(vectorizer.transform([cleaned_url]))[0]

        if result == "bad":
            prediction = "🚨 This is a PHISHING website"
        else:
            prediction = "✅ This is a SAFE website"

    return render_template("index.html", prediction=prediction)

@app.route("/predict", methods=["POST"])
def predict_api():
    data = request.get_json()
    url = data.get("url")

    cleaned_url = re.sub(r"^https?://(www\.)?", "", url)
    result = model.predict(vectorizer.transform([cleaned_url]))[0]

    if result == "bad":
        output = "Phishing"
    else:
        output = "Safe"

    return jsonify({
        "url": url,
        "prediction": output
    })
if __name__ == "__main__":
    app.run(host="0.0.0.0" , port=10000)
     
