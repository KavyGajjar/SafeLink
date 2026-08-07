import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from urllib.parse import urlparse

# -----------------------------
# Load Dataset
# -----------------------------
df = pd.read_csv(
    "urlset.csv",
    encoding="latin1",
    on_bad_lines="skip",
    low_memory=False
)

# Remove missing values
df = df.dropna(subset=["domain", "label"])
print(df[["domain", "label"]].head(20))

# -----------------------------
# Feature Extraction Function
# -----------------------------
def extract_features(url):
    parsed = urlparse(str(url))

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("&"),
        url.count("/"),
        int(parsed.scheme == "https"),
        len(parsed.netloc),

        sum(c.isdigit() for c in url),
        int("login" in url.lower()),
        int("verify" in url.lower()),
        int("secure" in url.lower()),
        int("update" in url.lower()),
        int("account" in url.lower()),
        int("bank" in url.lower()),
        int("paypal" in url.lower()),
        int("signin" in url.lower()),
        int("http" in parsed.netloc.lower())
]

# -----------------------------
# Create Feature Matrix
# -----------------------------
print("Extracting features from URLs...")

X = df["domain"].apply(extract_features)

X = pd.DataFrame(
    X.tolist(),
    columns=[
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
)

print(X.head())
print(X.dtypes)

y = df["label"].astype(int)

print("Feature extraction completed.")
print("Dataset Shape:", X.shape)

# -----------------------------
# Train/Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------
# Random Forest Model
# -----------------------------
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# -----------------------------
# Train
# -----------------------------
print("Training model...")

model.fit(X_train, y_train)

# -----------------------------
# Test
# -----------------------------
y_pred = model.predict(X_test)
print(pd.Series(y_pred).value_counts())

accuracy = accuracy_score(y_test, y_pred)

print(f"Accuracy : {accuracy*100:.2f}%")

# -----------------------------
# Save Model
# -----------------------------
joblib.dump(model, "model.pkl")

print("Model saved successfully!")