import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.model_selection import train_test_split

from sklearn.linear_model import LogisticRegression

from sklearn.naive_bayes import MultinomialNB

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# -----------------------------------
# Load Dataset
# -----------------------------------

data = pd.read_csv(
    "dataset/messages.csv"
)

X = data["text"]

Y = data["label"]

# -----------------------------------
# Split Dataset
# -----------------------------------

X_train, X_test, Y_train, Y_test = train_test_split(
    X,
    Y,
    test_size=0.2,
    random_state=42,
    stratify=Y
)

# -----------------------------------
# TF-IDF Vectorization
# -----------------------------------

vectorizer = TfidfVectorizer()

X_train_vectorized = vectorizer.fit_transform(
    X_train
)

X_test_vectorized = vectorizer.transform(
    X_test
)

# ===================================
# Logistic Regression
# ===================================

logistic_model = LogisticRegression()

logistic_model.fit(
    X_train_vectorized,
    Y_train
)

logistic_predictions = logistic_model.predict(
    X_test_vectorized
)

logistic_accuracy = accuracy_score(
    Y_test,
    logistic_predictions
)

# ===================================
# Naive Bayes
# ===================================

nb_model = MultinomialNB()

nb_model.fit(
    X_train_vectorized,
    Y_train
)

nb_predictions = nb_model.predict(
    X_test_vectorized
)

nb_accuracy = accuracy_score(
    Y_test,
    nb_predictions
)

# ===================================
# Random Forest
# ===================================

rf_model = RandomForestClassifier()

rf_model.fit(
    X_train_vectorized,
    Y_train
)

rf_predictions = rf_model.predict(
    X_test_vectorized
)

rf_accuracy = accuracy_score(
    Y_test,
    rf_predictions
)

# ===================================
# Results
# ===================================

print("\n==============================")
print(" PHISHING MODEL COMPARISON ")
print("==============================")

# -----------------------------------
# Logistic Regression
# -----------------------------------

print("\n[ Logistic Regression ]")

print(f"Accuracy: {logistic_accuracy:.2f}")

print("\nClassification Report:\n")

print(
    classification_report(
        Y_test,
        logistic_predictions
    )
)

print("Confusion Matrix:\n")

print(
    confusion_matrix(
        Y_test,
        logistic_predictions
    )
)

# -----------------------------------
# Naive Bayes
# -----------------------------------

print("\n==============================")

print("\n[ Naive Bayes ]")

print(f"Accuracy: {nb_accuracy:.2f}")

print("\nClassification Report:\n")

print(
    classification_report(
        Y_test,
        nb_predictions
    )
)

print("Confusion Matrix:\n")

print(
    confusion_matrix(
        Y_test,
        nb_predictions
    )
)

# -----------------------------------
# Random Forest
# -----------------------------------

print("\n==============================")

print("\n[ Random Forest ]")

print(f"Accuracy: {rf_accuracy:.2f}")

print("\nClassification Report:\n")

print(
    classification_report(
        Y_test,
        rf_predictions
    )
)

print("Confusion Matrix:\n")

print(
    confusion_matrix(
        Y_test,
        rf_predictions
    )
)

# ===================================
# Best Model
# ===================================

best_accuracy = max(
    logistic_accuracy,
    nb_accuracy,
    rf_accuracy
)

print("\n==============================")

if best_accuracy == logistic_accuracy:

    print("\nBest Model: Logistic Regression")

elif best_accuracy == nb_accuracy:

    print("\nBest Model: Naive Bayes")

else:

    print("\nBest Model: Random Forest")

print("\n==============================")

# Logistic Regression achieved better performance on phishing classification tasks
# Multiple machine learning models were evaluated for phishing detection,
# including Logistic Regression, Naive Bayes, and Random Forest.