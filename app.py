from flask import Flask, render_template, request
import pandas as pd
import joblib
import socket
from urllib.parse import urlparse
from feature_extractor import extract_features
from domain_checker import check_lookalike

app = Flask(__name__)

# Load trained model
model = joblib.load("model.pkl")

FEATURE_NAMES = [
    "url_length", "dot_count", "hyphen_count", "at_count",
    "question_count", "equal_count", "ampersand_count",
    "slash_count", "https", "domain_length", "digit_count",
    "has_login", "has_verify", "has_secure", "has_update",
    "has_account", "has_bank", "has_paypal", "has_signin",
    "fake_http"
]


def validate_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        return False, "Please enter a URL."

    candidate = raw_url
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if (
            parsed.scheme not in ("http", "https")
            or not hostname
            or "." not in hostname
            or " " in candidate
            or parsed.port == 0
        ):
            return False, "Invalid URL format. Please check the address."

        if (
            hostname.startswith(".")
            or hostname.endswith(".")
            or ".." in hostname
            or any(char in hostname for char in ("@", "\\", "_"))
        ):
            return False, "Invalid URL format. Please check the address."

    except ValueError:
        return False, "Invalid URL format. Please check the address."

    return True, candidate


def check_domain_dns(hostname):
    """Check whether DNS resolves the hostname."""
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except socket.gaierror:
        return False
    except OSError:
        # DNS/network problems are inconclusive, not proof of a threat.
        return None


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    confidence = None
    url = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        valid, checked_url = validate_url(url)

        if not valid:
            result = checked_url
        else:
            parsed = urlparse(checked_url)
            hostname = parsed.hostname

            # Localhost and private/local IPs are not public websites.
            try:
                import ipaddress
                ip = ipaddress.ip_address(hostname)
                if not ip.is_global:
                    result = "Local or non-public address — not assessed"
                else:
                    dns_ok = check_domain_dns(hostname)
                    if dns_ok is False:
                        result = "Domain could not be verified"
                    elif dns_ok is None:
                        result = "DNS check unavailable — domain unverified"
            except ValueError:
                # The hostname is a domain name, not a literal IP address.
                dns_ok = check_domain_dns(hostname)
                if dns_ok is False:
                    result = "Domain could not be verified"
                elif dns_ok is None:
                    result = "DNS check unavailable — domain unverified"

             # Check for possible lookalike domains first.
            if result is None:
                lookalike = check_lookalike(checked_url)

                if lookalike["is_lookalike"]:
                    result = (
                        f"Possible lookalike domain! Did you mean "
                        f"{lookalike['suggestion']}?"
                    )

            # Run the ML model only if earlier checks passed.
            if result is None:
                features = extract_features(checked_url)
                features_df = pd.DataFrame(
                    [features],
                    columns=FEATURE_NAMES
                )

                prediction = model.predict(features_df)[0]
                probabilities = model.predict_proba(features_df)[0]
                confidence = round(max(probabilities) * 100, 2)

                if prediction == 1:
                    result = "Potentially Malicious URL"
                else:
                    result = "No Known Threat Detected"

    return render_template(
        "index.html",
        url=url,
        result=result,
        confidence=confidence
    )


if __name__ == "__main__":
    app.run(debug=True)