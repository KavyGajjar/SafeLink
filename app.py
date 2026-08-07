from flask import Flask, render_template, request
import pandas as pd
import joblib
from feature_extractor import extract_features

app = Flask(__name__)

model = joblib.load("model.pkl")

@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        url = request.form["url"]
        import pandas as pd

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

        print(features_df)
        print("Prediction:", prediction)
        print("Probability:", probability)

        if prediction == 1:
            result = "⚠️ Malicious URL"
        else:
            result = "✅ Safe URL"

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)