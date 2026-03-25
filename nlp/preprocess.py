import re
import nltk
from nltk.corpus import stopwords

# Download stopwords (only first time)
nltk.download('stopwords')

def clean_text(text):
    # Convert to lowercase
    text = text.lower()
    
    # Remove special characters
    text = re.sub(r'[^a-zA-Z0-9 ]', '', text)
    
    # Split into words
    words = text.split()
    
    # Remove stopwords (like "is", "the", "and")
    words = [word for word in words if word not in stopwords.words('english')]
    
    return " ".join(words)