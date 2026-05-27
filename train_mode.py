import pandas as pd
import joblib

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression

data = pd.read_csv(r"C:\Users\kankrit\Desktop\Projects\phishing-detector\env\dataset\messages.csv")

X = data["text"]
Y = data["label"]

#convert text to numbers
vectorizer = CountVectorizer()

X_vectorizer = vectorizer.fit_transform(X)

#create model
model = LogisticRegression()

model.fit(X_vectorizer, Y)

print("Model training successfully!")

test_message = ["Verify your password immediately"]

test_vector = vectorizer.transform(test_message)

prediction = model.predict(test_vector)

print(prediction)