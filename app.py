from flask import Flask, render_template, request
import pandas as pd
import joblib
from feature_extractor import extract_features

app = Flask(__name__)

# Load trained model
model = joblib.load("model.pkl")


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    confidence = None
    url = ""

    if request.method == "POST":

        url = request.form["url"]

        features = extract_features(url)

        feature_names = [
            "url_length",
            "dot_count",
            "hyphen_count",
            "at_count",
            "question_count",
            "equal_count",
            "ampersand_count",
            "slash_count",
            "https",
            "domain_length",
            "digit_count",
            "has_login",
            "has_verify",
            "has_secure",
            "has_update",
            "has_account",
            "has_bank",
            "has_paypal",
            "has_signin",
            "fake_http"
        ]

        features_df = pd.DataFrame([features], columns=feature_names)

        prediction = model.predict(features_df)[0]
        probability = model.predict_proba(features_df)[0]

        confidence = round(max(probability) * 100, 2)

        if prediction == 1:
            result = "Malicious URL"
        else:
            result = "Safe URL"

    return render_template(
        "index.html",
        url=url,
        result=result,
        confidence=confidence
    )


if __name__ == "__main__":
    app.run(debug=True)