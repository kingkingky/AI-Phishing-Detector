import pandas as pd
import re
import joblib

from sklearn.linear_model import LogisticRegression

#feature

def extract_url_features(url):
    
    features = []
    
    #URL length
    features.append(len(url))
    
    #number of dot
    features.append(url.count("."))
    
    #number of hyphens
    features.append(url.count("-"))
    
    #contains https
    features.append(1 if "https" in url else 0)
    
    #suspicious keywords
    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "bank",
        "bonus",
        "free",
        "update"
    ]
    suspicious_score = 0
    
    for word in suspicious_keywords:
        if word in url.lower():
            suspicious_score += 1
            
    features.append(suspicious_score)
    
    #IP detection
    ip_pattern = r"(\\d{1,3}\\.){3}\\d{1,3}"
    
    features.append(
        1 if re.search(ip_pattern, url) else 0
    )
    return features

#Load data
data = pd.read_csv(r"C:\Users\kankrit\OneDrive\Desktop\Projects\phishing-detector\dataset\urls.csv")

X = data["url"]
y = data["label"]

# extract features
X_features = []

for url in X:

    X_features.append(
        extract_url_features(url)
    )
#Train model
model = LogisticRegression()

model.fit(X_features, y)

# save model
joblib.dump(model, "model/url_model.pkl")

print("URL phishing model trained successfully!")

#engineered structural URL features and trained a machine learning classifier for phishing URL detection