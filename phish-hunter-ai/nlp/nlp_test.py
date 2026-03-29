import pickle
import re

# Load model and vectorizer
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# Preprocess function
def clean_text(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', '', text)
    return text

# Predict function
def predict_text(text):
    clean = clean_text(text)
    vector = vectorizer.transform([clean])
    score = model.predict_proba(vector)[0][1] * 100  # spam probability %
    return round(score, 2)

# Example testing
if __name__ == "__main__":
    test_messages = [
        "Congratulations!!! You WON a FREE iPhone!!! Click here now!!!",
        "Hello, can we meet tomorrow for lunch?",
        "Your bank account is blocked. Click http://sbi-verify.xyz/login now!"
    ]

    for msg in test_messages:
        print(f"\nMessage: {msg}")
        print(f"Spam Risk Score: {predict_text(msg)}%")