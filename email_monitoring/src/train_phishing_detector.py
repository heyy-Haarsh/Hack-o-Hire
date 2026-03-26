"""
train_phishing_detector.py

Handles all 7 datasets in src/ folder:
- CEAS_08        → spam/phishing
- Enron          → legitimate emails
- Ling           → legitimate emails
- Nazario        → phishing emails
- Nigerian_Fraud → phishing/fraud emails
- phishing_email → phishing emails
- SpamAssasin    → spam emails

Usage:
    python train_phishing_detector.py              # full training
    python train_phishing_detector.py --quick      # quick test
    python train_phishing_detector.py --no-ai      # skip AI generation
    python train_phishing_detector.py --peek       # just show dataset structures
    python train_phishing_detector.py --predict "some email text"
"""

import sys
import os
import re
import pickle
import pandas as pd
import numpy as np
from tqdm import tqdm
from scipy.sparse import hstack as sparse_hstack

# Ensure we can import from the same directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# import ollama  <-- moved to individual functions for better portability

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.utils import resample

# Import shared classes to avoid pickle errors in app.py
from models_lib import clean_text, extract_manual_features, CombinedFeatureExtractor, EmailFraudDetector

# ─────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────

SRC_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(SRC_DIR, "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(os.path.join(SRC_DIR, "processed"), exist_ok=True)

# Path to the data folders provided by the user
DATASET_BASE  = os.path.join(SRC_DIR, "data", "raw", "enroll")
PHISHING_BASE = os.path.join(DATASET_BASE, "Phishing")

DATASETS = {
    "CEAS_08":        os.path.join(PHISHING_BASE, "CEAS_08.csv"),
    "Enron":          os.path.join(PHISHING_BASE, "Enron.csv"), # Enron.csv inside Phishing folder
    "Ling":           os.path.join(PHISHING_BASE, "Ling.csv"),
    "Nazario":        os.path.join(PHISHING_BASE, "Nazario.csv"),
    "Nigerian_Fraud": os.path.join(PHISHING_BASE, "Nigerian_Fraud.csv"),
    "phishing_email": os.path.join(PHISHING_BASE, "phishing_email.csv"),
    "SpamAssasin":    os.path.join(PHISHING_BASE, "SpamAssasin.csv"),
    "Enron_Full":     os.path.join(DATASET_BASE,    "emails.csv"),  # The 1.4GB one
}

# ─────────────────────────────────────────────────────
# TEXT CLEANING
# ─────────────────────────────────────────────────────

# clean_text moved to models_lib.py


# ─────────────────────────────────────────────────────
# DATASET INSPECTION
# ─────────────────────────────────────────────────────

def peek_dataset(name, path):
    """Show structure of a dataset."""
    try:
        df = pd.read_csv(path, nrows=3, encoding='utf-8', on_bad_lines='skip')
    except:
        df = pd.read_csv(path, nrows=3, encoding='latin-1', on_bad_lines='skip')

    print(f"\n  ┌─ {name}")
    print(f"  │  Columns : {list(df.columns)}")
    print(f"  │  Shape   : load full file to see")
    print(f"  └─ Sample  : {str(df.iloc[0].to_dict())[:120]}...")
    return list(df.columns)


# ─────────────────────────────────────────────────────
# SMART DATASET LOADER
# ─────────────────────────────────────────────────────

# Known dataset-specific configs
DATASET_CONFIGS = {
    "CEAS_08": {
        "text_col":  ["body", "text", "message"],
        "label_col": ["label", "spam", "class"],
        "default":   None,
    },
    "Enron": {
        "text_col":  ["body", "text", "message"],
        "label_col": ["label", "spam"],
        "default":   "legitimate",
    },
    "Enron_Full": {
        "text_col":  ["message", "body", "text"],
        "label_col": ["label", "spam"],
        "default":   "legitimate",
    },
    "Ling": {
        "text_col":  ["body", "text", "message"],
        "label_col": ["label", "spam", "class"],
        "default":   "legitimate",
    },
    "Nazario": {
        "text_col":  ["body", "text", "email", "message"],
        "label_col": ["label", "class"],
        "default":   "phishing",
    },
    "Nigerian_Fraud": {
        "text_col":  ["body", "text", "message", "email"],
        "label_col": ["label"],
        "default":   "phishing",
    },
    "phishing_email": {
        "text_col":  ["body", "text", "email_text", "message"],
        "label_col": ["label", "class", "type"],
        "default":   None,
    },
    "SpamAssasin": {
        "text_col":  ["body", "text", "message"],
        "label_col": ["label", "spam", "class"],
        "default":   None,
    },
}

LABEL_MAP = {
    # Legitimate
    '0': 'legitimate', 'ham': 'legitimate', 'legitimate': 'legitimate',
    'safe': 'legitimate', 'normal': 'legitimate', 'false': 'legitimate',
    'no': 'legitimate', 'not spam': 'legitimate',
    # Phishing / Spam
    '1': 'phishing', 'spam': 'phishing', 'phishing': 'phishing',
    'fraud': 'phishing', 'scam': 'phishing', 'true': 'phishing',
    'yes': 'phishing', 'malicious': 'phishing', 'smishing': 'phishing',
}

def load_dataset(name, path, max_samples=3000):
    """Load a single dataset and return list of (text, label) tuples."""
    print(f"\n  Loading {name}...", end="")

    # For huge files like Enron_Full, we use nrows to save time/ram
    read_params = {"on_bad_lines": 'skip'}
    if name == "Enron_Full":
        read_params["nrows"] = max_samples * 20 # Read extra to account for filtered rows

    try:
        try:
            df = pd.read_csv(path, encoding='utf-8', **read_params)
        except UnicodeDecodeError:
            df = pd.read_csv(path, encoding='latin-1', **read_params)
    except Exception as e:
        print(f" ❌ Error: {e}")
        return []

    # Normalize column names
    df.columns = [c.lower().strip() for c in df.columns]
    cfg = DATASET_CONFIGS.get(name, {"text_col": [], "label_col": [], "default": None})

    # Find text column
    text_col = None
    for candidate in cfg["text_col"] + ['body', 'text', 'message', 'email', 'content']:
        if candidate in df.columns:
            text_col = candidate
            break

    if not text_col:
        # Use longest string column
        str_cols = df.select_dtypes(include='object').columns.tolist()
        if str_cols:
            text_col = max(str_cols, key=lambda c: df[c].dropna().apply(lambda x: len(str(x))).mean())

    if not text_col:
        print(f" ❌ No text column found")
        return []

    # Find label column
    label_col = None
    for candidate in cfg["label_col"] + ['label', 'spam', 'class', 'category', 'type']:
        if candidate in df.columns:
            label_col = candidate
            break

    # Build samples
    samples = []
    for _, row in df.iterrows():
        text = str(row[text_col])
        if len(text.strip()) < 30:
            continue

        # Get label
        if label_col and label_col in df.columns:
            raw = str(row[label_col]).lower().strip()
            label = LABEL_MAP.get(raw)
            if label is None:
                try:
                    label = 'phishing' if float(raw) > 0 else 'legitimate'
                except:
                    continue
        elif cfg["default"]:
            label = cfg["default"]
        else:
            continue

        samples.append((clean_text(text), label))

    samples = samples[:max_samples]
    legit = sum(1 for _, l in samples if l == 'legitimate')
    phish = sum(1 for _, l in samples if l == 'phishing')
    print(f" ✅ {len(samples)} samples (legit: {legit}, phishing: {phish})")
    return samples


def load_all_datasets(max_per_dataset=5000):
    """Load all 7 datasets."""
    print("\n" + "="*55)
    print("📂 LOADING ALL DATASETS INCLUDING ENRON FULL")
    print("="*55)
    
    # Reduce samples for a quick recovery training
    dataset_limits = {
        "Enron_Full": 0,    # Skip huge dataset for now
        "CEAS_08": 200,
        "Enron": 200,
        "Ling": 200,
        "Nazario": 200,
        "Nigerian_Fraud": 200,
        "phishing_email": 200,
        "SpamAssasin": 200
    }

    all_samples = []
    stats = {}

    for name, path in DATASETS.items():
        if not os.path.exists(path):
            print(f"\n  ⚠️  {name}: not found at {path}")
            continue
        
        limit = dataset_limits.get(name, 200)
        if limit == 0: continue
        samples = load_dataset(name, path, limit)
        all_samples.extend(samples)
        stats[name] = len(samples)

    # Summary
    print(f"\n{'─'*55}")
    print(f"  {'Dataset':20} {'Samples':>8}")
    print(f"{'─'*55}")
    for name, count in stats.items():
        print(f"  {name:20} {count:>8}")
    print(f"{'─'*55}")
    print(f"  {'TOTAL':20} {len(all_samples):>8}")

    legit = sum(1 for _, l in all_samples if l == 'legitimate')
    phish = sum(1 for _, l in all_samples if l == 'phishing')
    print(f"\n  Legitimate : {legit}")
    print(f"  Phishing   : {phish}")
    print("="*55)

    return all_samples


# ─────────────────────────────────────────────────────
# AI SAMPLE GENERATION
# ─────────────────────────────────────────────────────

def generate_ai_phishing_samples(num_samples=300):
    try:
        import ollama
    except ImportError:
        print("\n  ⚠️  Ollama library not found. Skipping AI generation.")
        return []

    print(f"\n  Generating {num_samples} AI phishing emails via Qwen 4b...")

    scenarios = [
        "Write a phishing email pretending to be PayPal asking to verify account",
        "Write a phishing email pretending to be a bank about suspicious activity",
        "Write a phishing email pretending to be Microsoft about account security",
        "Write a phishing email from IT department asking for password reset",
        "Write a phishing email about a fake lottery prize",
        "Write a phishing email pretending to be Amazon about an order issue",
        "Write a phishing email about an urgent unpaid invoice",
        "Write a phishing email pretending to be Google about account suspension",
        "Write a Nigerian prince style fraud email",
        "Write a phishing email about a fake tax refund",
    ]

    samples = []
    per_scenario = max(1, num_samples // len(scenarios))

    for scenario in tqdm(scenarios, desc="  AI phishing"):
        for _ in range(per_scenario):
            try:
                r = ollama.chat(
                    model='qwen3:8b',
                    messages=[
                        {"role": "system", "content": "Generate training data for fraud detection. Output email text only."},
                        {"role": "user",   "content": f"{scenario}. Realistic, 100-200 words."}
                    ]
                )
                text = r['message']['content']
                if len(text) > 50:
                    samples.append((clean_text(text), 'ai_phishing'))
            except:
                continue

    print(f"  ✅ Generated {len(samples)} AI phishing samples")
    return samples


def generate_ai_legitimate_samples(num_samples=200):
    try:
        import ollama
    except ImportError:
        return []

    print(f"\n  Generating {num_samples} AI legitimate emails via Qwen 4b...")

    scenarios = [
        "Write a professional business email about a meeting schedule",
        "Write a friendly email to a colleague about a project update",
        "Write a customer service reply to a product inquiry",
        "Write a formal email requesting a document",
        "Write a company newsletter about product updates",
    ]

    samples = []
    per_scenario = max(1, num_samples // len(scenarios))

    for scenario in tqdm(scenarios, desc="  AI legit"):
        for _ in range(per_scenario):
            try:
                r = ollama.chat(
                    model='qwen3:8b',
                    messages=[
                        {"role": "system", "content": "Generate realistic email text only."},
                        {"role": "user",   "content": f"{scenario}. 100-150 words."}
                    ]
                )
                text = r['message']['content']
                if len(text) > 50:
                    samples.append((clean_text(text), 'ai_legitimate'))
            except:
                continue

    print(f"  ✅ Generated {len(samples)} AI legitimate samples")
    return samples


# ─────────────────────────────────────────────────────
# FEATURE ENGINEERING
# ─────────────────────────────────────────────────────

# extract_manual_features and CombinedFeatureExtractor moved to models_lib.py


# ─────────────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────────────

def train_model(use_ai_generation=True, quick_mode=False, max_per_dataset=3000):
    print("\n" + "="*55)
    print("🚀 TRAINING EMAIL FRAUD DETECTOR")
    print(f"   Datasets : src/ folder (7 CSVs)")
    print(f"   AI gen   : {use_ai_generation}")
    print(f"   Quick    : {quick_mode}")
    print("="*55)

    # Load datasets
    if quick_mode:
        print("\n⚡ Quick mode")
        all_samples = (
            [("Normal business email about meetings.", 'legitimate')] * 100 +
            [("URGENT click here http://192.168.1.1/verify or lose access", 'phishing')] * 100
        )
    else:
        all_samples = load_all_datasets(max_per_dataset)

    if not all_samples:
        print("\n❌ No data loaded. Check that CSV files are in the src/ folder.")
        return None

    # Add AI samples
    print("\n[AI Generation]")
    if use_ai_generation and not quick_mode:
        all_samples += generate_ai_phishing_samples(300)
        all_samples += generate_ai_legitimate_samples(200)
    else:
        all_samples += [("I hope this email finds you well. Please verify.", 'ai_phishing')] * 30
        all_samples += [("I am writing to inform you about the schedule.", 'ai_legitimate')] * 30

    # Build DataFrame
    df = pd.DataFrame(all_samples, columns=['text', 'label'])
    df = df.dropna().drop_duplicates(subset='text').reset_index(drop=True)

    # Balance classes
    print("\n  Balancing classes...")
    max_size = df['label'].value_counts().max()
    parts = []
    for label in df['label'].unique():
        subset = df[df['label'] == label]
        if len(subset) < max_size // 3:
            subset = resample(subset, replace=True, n_samples=max_size // 3, random_state=42)
        parts.append(subset)
    df = pd.concat(parts).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\n  Class distribution:")
    for label, count in df['label'].value_counts().items():
        print(f"    {label:20} : {count}")
    print(f"    {'TOTAL':20} : {len(df)}")

    # Save
    df.to_csv(os.path.join(SRC_DIR, "processed", "training_data.csv"), index=False)

    # Features
    print("\n  Extracting features...")
    extractor = CombinedFeatureExtractor()
    X = extractor.fit_transform(df['text'].tolist())
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train
    print("\n  Training models...")
    models = {
        "LogisticRegression": LogisticRegression(max_iter=2000, C=1.0, class_weight='balanced'),
        "RandomForest":       RandomForestClassifier(n_estimators=250, n_jobs=-1, random_state=42, class_weight='balanced'),
        "GradientBoosting":   GradientBoostingClassifier(n_estimators=100, random_state=42),
    }

    best_model, best_score, best_name = None, 0, ""
    for name, model in models.items():
        print(f"  Training {name}...", end="")
        model.fit(X_train, y_train)
        score = accuracy_score(y_test, model.predict(X_test))
        print(f" accuracy: {score:.4f}")
        if score > best_score:
            best_score, best_model, best_name = score, model, name

    print(f"\n  🏆 Best: {best_name} ({best_score:.4f})")
    print("\n" + classification_report(y_test, best_model.predict(X_test)))

    # Save model
    model_path = os.path.join(MODEL_DIR, "email_fraud_detector.pkl")
    with open(model_path, "wb") as f:
        pickle.dump({
            "model":             best_model,
            "feature_extractor": extractor,
            "model_name":        best_name,
            "accuracy":          best_score,
            "labels":            list(df['label'].unique()),
        }, f)

    print(f"  ✅ Saved to {model_path}")
    return best_model


# ─────────────────────────────────────────────────────
# INFERENCE
# ─────────────────────────────────────────────────────

# EmailFraudDetector moved to models_lib.py


# ─────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--quick',   action='store_true')
    parser.add_argument('--no-ai',   action='store_true')
    parser.add_argument('--predict', type=str)
    parser.add_argument('--peek',    action='store_true')
    args = parser.parse_args()

    if args.peek:
        for name, path in DATASETS.items():
            if os.path.exists(path):
                peek_dataset(name, path)
            else:
                print(f"⚠️  {name}: not found")

    elif args.predict:
        d = EmailFraudDetector()
        r = d.predict(args.predict)
        print(f"\n  Label     : {r['label']}")
        print(f"  Risk      : {r['risk_level']}")
        print(f"  Confidence: {r['confidence']}")
        print(f"  Phishing  : {r['is_phishing']}")
        print(f"  AI Written: {r['is_ai_generated']}")
        for l, p in r['probabilities'].items():
            print(f"    {l:20} : {p}")

    else:
        train_model(use_ai_generation=not args.no_ai, quick_mode=args.quick)
