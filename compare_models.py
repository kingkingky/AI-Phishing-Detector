import pandas as pd

from sklearn.feature_extraction.text import CountVectorizer

from sklearn.model_selection import train_test_split

from sklearn.linear_model import LogisticRegression

from sklearn.naive_bayes import MultinomialNB

from sklearn.metrics import accuracy_score

# load dataset
data = pd.read_csv(r"C:\Users\kankrit\Desktop\Projects\phishing-detector\env\dataset\messages.csv")

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

logistic_model = LogisticRegression()

logistic_model.fit(X_train_vectorized, Y_train)

logistic_predictions = logistic_model.predict(X_test_vectorized)

logistic_accuracy = accuracy_score(
    Y_test,
    logistic_predictions
)

# Naive Bayes
nb_model = MultinomialNB()

nb_model.fit(X_train_vectorized, Y_train)

nb_predictions = nb_model.predict(X_test_vectorized)

nb_accuracy = accuracy_score(
    Y_test,
    nb_predictions
)

# Results
print("\nModel Comparison\n")

print("Logistic Regression Accuracy:")
print(logistic_accuracy)

print("\nNaive Bayes Accuracy:")
print(nb_accuracy)

# best model
if logistic_accuracy > nb_accuracy:

    print("\nBest Model: Logistic Regression")

elif nb_accuracy > logistic_accuracy:

    print("\nBest Model: Naive Bayes")

else:

    print("\nBoth models performed equally")