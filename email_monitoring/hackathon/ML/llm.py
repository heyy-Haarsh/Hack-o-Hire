import os
import joblib
import pandas as pd
from dotenv import load_dotenv

# Try to load HF nodes if available (Haystack 1.x)
try:
    from haystack.nodes import PreProcessor, PromptModel, PromptTemplate, PromptNode
    from haystack import Document, Pipeline
    from haystack.document_stores import InMemoryDocumentStore
    from haystack.nodes import BM25Retriever
    HAYSTACK_AVAILABLE = True
except ImportError:
    HAYSTACK_AVAILABLE = False

load_dotenv()
HF_TOKEN = os.getenv("HF_TOKEN")

# Path to the local joblib model we trained
MODEL_PATH = os.path.join(os.getcwd(), '..', '..', 'src', 'models', 'content_classifier.joblib')
if not os.path.exists(MODEL_PATH):
    # Fallback to local path if running from root
    MODEL_PATH = os.path.join('src', 'models', 'content_classifier.joblib')

def return_ans(q):
    print(f"Querying for: {q[:50]}...")
    
    # Try local joblib classification first if haystack is missing or as requested
    if os.path.exists(MODEL_PATH):
        try:
            print("Using local joblib model for classification...")
            clf_pipeline = joblib.load(MODEL_PATH)
            prediction = clf_pipeline.predict([q])[0]
            print(f"Local prediction: {prediction}")
            
            # Map predictions to industry/sentiment if needed
            # For now return the prediction as industry
            return {
                "industry": prediction,
                "sentiment": "neutral", # Default as joblib only trained on industry
                "status": 200,
                "model": "local_joblib"
            }
        except Exception as e:
            print(f"Local joblib prediction failed: {e}")

    # Fallback to Haystack/HF if available
    if HAYSTACK_AVAILABLE and HF_TOKEN:
        try:
            print("Using HF/Haystack model...")
            # (The original original LLM logic would go here, 
            # but since we might be in Haystack 2.x env, this is a placeholder 
            # unless we have the right env)
            pass
        except Exception as e:
            print(f"HF Prediction failed: {e}")

    # Final fallback
    return {
        "industry": "finance",
        "sentiment": "neutral",
        "status": 200,
        "model": "fallback"
    }
