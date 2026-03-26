"""
models_lib.py - Shared classes for the Email Fraud Detector.
This prevents pickle AttributeError in app.py.
"""
import re
import numpy as np
import os
import pickle
import sys
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack as sparse_hstack

# ─────────────────────────────────────────────────────
# PICKLE COMPATIBILITY HACK
# ─────────────────────────────────────────────────────
# This "tricks" the pickle loader into finding the class even though 
# it was originally saved from the training script's __main__ scope.
class CombinedFeatureExtractor:
    pass # placeholder for early loading

sys.modules['__main__'].CombinedFeatureExtractor = CombinedFeatureExtractor

# ─────────────────────────────────────────────────────
# TEXT CLEANING (Keep identical to training script)
# ─────────────────────────────────────────────────────

def clean_text(text):
    text = str(text)
    # Only remove headers if they are at the very beginning of the full text
    # Avoid removing "From:", "To:" inside forwarded sections
    header_patterns = [
        r'^(From|To|Subject|Date|Cc|Bcc|Message-ID|Content-Type|Content-Transfer-Encoding):.*$',
        r'^(X-From|X-To|X-cc|X-bcc|X-Folder|X-Origin|X-FileName|Mime-Version):.*$'
    ]
    # Restrict to first 500 characters to protect forwarded headers later in the body
    header_block = text[:500]
    for pattern in header_patterns:
        header_block = re.sub(pattern, '', header_block, flags=re.MULTILINE | re.IGNORECASE)
    
    text = header_block + text[500:]
    
    text = re.sub(r'http\S+', '[URL]', text)
    text = re.sub(r'\S+@\S+', '[EMAIL]', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:2000]

def extract_manual_features(text):
    t = text.lower()
    sents = [s for s in re.split(r'[.!?]', text) if s.strip()]
    words = text.split()

    return [
        int(bool(re.search(r'urgent|immediately|asap|right now|expires|act now', t))),
        len(re.findall(r'urgent|immediately|asap|expires', t)),
        int(bool(re.search(r'http[s]?://\d{1,3}\.\d{1,3}', text))),
        int(bool(re.search(r'bit\.ly|tinyurl|t\.co|goo\.gl', text))),
        len(re.findall(r'http[s]?://', text)),
        int(bool(re.search(r'bank account|account number|sort code|routing number', t))),
        int(bool(re.search(r'wire transfer|bitcoin|western union|payment link', t))),
        int(bool(re.search(r'won|winner|prize|lottery|congratulations you', t))),
        int(bool(re.search(r'nigerian|prince|inheritance|million dollar', t))),
        int(bool(re.search(r'password|verify|confirm your|login|credential|username', t))),
        int(bool(re.search(r'credit card|card number|cvv|pin|security code', t))),
        int(bool(re.search(r'account (setup|locked|suspended|verification)', t))),
        int(bool(re.search(r'immediate (action|attention)|please respond', t))),
        int(bool(re.search(r'dear (customer|client|valued member|representative)', t))),
        int(bool(re.search(r'i hope this (email|message) finds you', t))),
        int(bool(re.search(r'please do not hesitate|feel free to (contact|reach)', t))),
        int(bool(re.search(r'i am writing to (inform|let you know)', t))),
        int(bool(re.search(r'certainly|of course|absolutely|indeed', t))),
        int(bool(re.search(r'best regards|kind regards|sincerely yours', t))),
        len(text),
        len(words),
        len(sents),
        np.mean([len(s.split()) for s in sents]) if sents else 0,
        np.mean([len(w) for w in words]) if words else 0,
        sum(1 for c in text if c.isupper()) / max(len(text), 1),
        text.count('!'),
        text.count('?'),
        text.count('$'),
        len(re.findall(r'\d+', text)),
    ]

class CombinedFeatureExtractor:
    def __init__(self):
        self.tfidf = TfidfVectorizer(
            max_features=10000,
            ngram_range=(1, 2),
            min_df=2,
            stop_words='english',
            sublinear_tf=True
        )

    def fit_transform(self, texts):
        tfidf_sparse = self.tfidf.fit_transform(texts)
        manual = np.array([extract_manual_features(t) for t in texts])
        return sparse_hstack([tfidf_sparse, manual])

    def transform(self, texts):
        tfidf_sparse = self.tfidf.transform(texts)
        manual = np.array([extract_manual_features(t) for t in texts])
        return sparse_hstack([tfidf_sparse, manual])

# Re-assign to ensure the redirect uses the full class definition
sys.modules['__main__'].CombinedFeatureExtractor = CombinedFeatureExtractor

class EmailFraudDetector:
    def __init__(self, model_path):
        with open(model_path, "rb") as f:
            data = pickle.load(f)
        self.model             = data["model"]
        self.feature_extractor = data["feature_extractor"]
        self.model_name        = data["model_name"]
        self.accuracy          = data.get("accuracy", 0)

    def predict(self, text):
        X     = self.feature_extractor.transform([clean_text(text)])
        label = self.model.predict(X)[0]
        proba = self.model.predict_proba(X)[0]
        conf  = proba[list(self.model.classes_).index(label)]

        return {
            "label":           label,
            "confidence":      f"{conf:.2%}",
            "risk_level":      {"legitimate": "LOW RISK 🟢", "phishing": "HIGH RISK 🔴",
                                "ai_phishing": "HIGH RISK 🔴", "ai_legitimate": "LOW RISK 🟢"}.get(label, "MEDIUM RISK 🟡"),
            "is_phishing":     label in ["phishing", "ai_phishing"],
            "is_ai_generated": label in ["ai_phishing", "ai_legitimate"],
            "probabilities":   {l: f"{p:.2%}" for l, p in zip(self.model.classes_, proba)},
        }
