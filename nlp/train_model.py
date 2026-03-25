import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import re

# ----------- Preprocess Function -------------
def clean_text(text):
    text = text.lower()  # lowercase
    text = re.sub(r'[^a-z0-9\s]', '', text)  # remove special chars
    return text

# ----------- Load Dataset -------------
df = pd.read_csv("data/sms_dataset.csv")

# Convert labels to numeric
df['label'] = df['label'].map({'spam': 1, 'ham': 0})

# Clean text
df['text'] = df['text'].apply(clean_text)

# ----------- Feature Extraction -------------
vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df['text'])
y = df['label']

# ----------- Train Model -------------
model = RandomForestClassifier(n_estimators=20)  # faster for hackathon
model.fit(X, y)

# ----------- Save Model -------------
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model trained successfully!")