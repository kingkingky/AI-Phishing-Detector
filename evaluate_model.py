import pandas as pd

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import classification_report

# load dataset
data = pd.read_csv(r"C:\Users\kankrit\OneDrive\Desktop\Projects\phishing-detector\dataset\messages.csv")

X = data["text"]
Y = data["label"]

# split dataset
X_train, X_test, Y_train, Y_test = train_test_split(
    X,
    Y,
    test_size=0.2,
    random_state=42
)

# vectorize text
vectorizer = CountVectorizer()

X_train_vectorized = vectorizer.fit_transform(X_train)
X_test_vectorized = vectorizer.transform(X_test)

# Logistic Regression
model = LogisticRegression()

model.fit(X_train_vectorized, Y_train)

predictions = model.predict(X_test_vectorized)

accuracy = accuracy_score(Y_test, predictions)

print("Accuracy:", accuracy)

print("\nConfusion Matrix:")
print(confusion_matrix(Y_test, predictions))

print("Classification Reports:")
print(classification_report(Y_test, predictions))