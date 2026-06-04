import pandas as pd
import joblib

from sklearn.feature_extraction.text import CountVectorizer

from sklearn.linear_model import LogisticRegression

# -----------------------------
# Load Dataset
# -----------------------------

data = pd.read_csv(r"C:\Users\kankrit\OneDrive\Desktop\Projects\phishing-detector\dataset\messages.csv")

X = data["text"]

y = data["label"]

# -----------------------------
# Vectorize Text
# -----------------------------

vectorizer = CountVectorizer()

X_vectorized = vectorizer.fit_transform(X)

# -----------------------------
# Train Model
# -----------------------------

model = LogisticRegression()

model.fit(X_vectorized, y)

# -----------------------------
# Save Model
# -----------------------------

joblib.dump(
    model,
    "model/phishing_model.pkl"
)

joblib.dump(
    vectorizer,
    "model/vectorizer.pkl"
)

print("Phishing model trained successfully!")