import pickle
import os
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))
from models_lib import EmailFraudDetector, CombinedFeatureExtractor

try:
    model_path = "models/email_fraud_detector.pkl"
    with open(model_path, "rb") as f:
        data = pickle.load(f)
    extractor = data["feature_extractor"]
    print(f"Extractor: {type(extractor)}")
    print(f"TFIDF type: {type(extractor.tfidf)}")
    print(f"Is fitted: {hasattr(extractor.tfidf, 'idf_')}")
except Exception as e:
    print(f"Error: {e}")
