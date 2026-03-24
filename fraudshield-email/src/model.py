# src/model.py
import torch
from torch.utils.data import Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import pandas as pd
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import BASE_MODEL, MAX_LENGTH, DEVICE, MODELS_DIR


class EmailDataset(Dataset):
    def __init__(self, csv_path: str, tokenizer):
        df = pd.read_csv(csv_path).dropna(subset=["text", "label"])
        self.texts  = df["text"].tolist()
        self.labels = df["label"].astype(int).tolist()
        self.tok    = tokenizer
        n_legit = sum(1 for l in self.labels if l == 0)
        n_phish = sum(1 for l in self.labels if l == 1)
        print(f"  [{Path(csv_path).stem}] {len(self.labels)} emails "
              f"| legit={n_legit}  phish={n_phish}")

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        enc = self.tok(
            self.texts[idx],
            truncation=True,
            max_length=MAX_LENGTH,
            padding="max_length",
            return_tensors="pt"
        )
        return {
            "input_ids":      enc["input_ids"].squeeze(),
            "attention_mask": enc["attention_mask"].squeeze(),
            "label":          torch.tensor(self.labels[idx], dtype=torch.long)
        }


def load_model(from_saved=False):
    """Load tokenizer + model. from_saved=True loads fine-tuned weights."""
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    saved_path = MODELS_DIR / "phishing_classifier"

    if from_saved and saved_path.exists():
        model = AutoModelForSequenceClassification.from_pretrained(
            str(saved_path)
        ).to(DEVICE)
        print(f"  Loaded fine-tuned model from {saved_path}")
    else:
        model = AutoModelForSequenceClassification.from_pretrained(
            BASE_MODEL, num_labels=2
        ).to(DEVICE)
        print(f"  Loaded base {BASE_MODEL} (not yet fine-tuned)")

    return tokenizer, model


if __name__ == "__main__":
    print("Loading model...")
    tokenizer, model = load_model()
    total = sum(p.numel() for p in model.parameters())
    print(f"Parameters: {total:,}")

    dummy = tokenizer(
        "Test phishing email",
        return_tensors="pt",
        truncation=True,
        max_length=MAX_LENGTH,
        padding="max_length"
    ).to(DEVICE)

    with torch.no_grad():
        out = model(**dummy)

    print(f"Output logits shape: {out.logits.shape}")
    print("model.py OK!")