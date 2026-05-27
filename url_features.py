#Regular Expression module: using for search pattern of text
import re

def extract_url_features(url):

    features = {}

    # URL length
    features["length"] = len(url)

    # number of dots
    features["dots"] = url.count(".")

    # number of hyphens
    features["hyphens"] = url.count("-")

    # contains HTTPS
    features["https"] = 1 if "https" in url else 0

    # contains suspicious keywords
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

    features["suspicious_keywords"] = suspicious_score

    # detect IP address (regex ex. 192.168.1.1)
    ip_pattern = r"(\\d{1,3}\\.){3}\\d{1,3}"

    features["has_ip"] = 1 if re.search(ip_pattern, url) else 0

    return features


# test
test_url = "http://secure-bank-login.xyz"

result = extract_url_features(test_url)

print(result)

#Engineered URL-based security features including suspicious keyword frequency, URL structure analysis, and IP-address detection