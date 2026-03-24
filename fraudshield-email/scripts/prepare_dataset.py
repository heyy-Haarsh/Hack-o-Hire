# scripts/prepare_dataset.py
import pandas as pd
import numpy as np
import re
from pathlib import Path
from sklearn.model_selection import train_test_split
from bs4 import BeautifulSoup
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from config import DATA_RAW, DATA_PROC, LEGITIMATE, PHISHING

def clean_email(text: str) -> str:
    if not isinstance(text, str) or len(str(text).strip()) == 0:
        return ""
    text = str(text)
    # Strip HTML
    try:
        text = BeautifulSoup(text, "html.parser").get_text()
    except Exception:
        pass
    # Replace URLs with token (preserve count signal)
    text = re.sub(r"https?://\S+|www\.\S+", " URL ", text)
    # Replace emails with token (PII removal)
    text = re.sub(r"\S+@\S+", " EMAIL ", text)
    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()
    # Truncate to 2000 chars
    return text[:2000]

all_dfs = []

# ── Dataset 1: Enron (SetFit format) ──────────────────────────────
print("Processing Enron spam dataset...")
enron = pd.read_csv(DATA_RAW / "enron_spam.csv")
# Combine subject + message for richer context
enron["clean_text"] = (
    enron["subject"].fillna("") + " " + enron["message"].fillna("")
).apply(clean_email)
# label: 0=legit, 1=spam
enron_df = pd.DataFrame({
    "text":  enron["clean_text"],
    "label": enron["label"].astype(int)
})
enron_df = enron_df[enron_df["text"].str.len() > 20]
print(f"  Enron: {len(enron_df)}  legit={(enron_df.label==0).sum()}  spam={(enron_df.label==1).sum()}")
all_dfs.append(enron_df)

# ── Dataset 2: zefang-liu phishing emails ─────────────────────────
print("Processing zefang-liu phishing dataset...")
phish = pd.read_csv(DATA_RAW / "phishing_emails.csv")
phish["clean_text"] = phish["Email Text"].apply(clean_email)
# "Safe Email" = 0, "Phishing Email" = 1
phish["label"] = phish["Email Type"].apply(
    lambda x: LEGITIMATE if str(x).strip() == "Safe Email" else PHISHING
)
phish_df = pd.DataFrame({
    "text":  phish["clean_text"],
    "label": phish["label"]
})
phish_df = phish_df[phish_df["text"].str.len() > 20]
print(f"  Phishing: {len(phish_df)}  legit={(phish_df.label==0).sum()}  phish={(phish_df.label==1).sum()}")
all_dfs.append(phish_df)

# ── Dataset 3: cybersectony (200k combined) ────────────────────────
print("Processing cybersectony combined dataset...")
combined = pd.read_csv(DATA_RAW / "phishing_combined.csv")
print(f"  Label distribution: {combined['label'].value_counts().to_dict()}")
# Labels: 0=legitimate_email, 1=phishing_email, 2=legitimate_url, 3=phishing_url
# We only want email labels (0 and 1), skip URL labels (2 and 3)
email_only = combined[combined["label"].isin([0, 1])].copy()
email_only["clean_text"] = email_only["content"].apply(clean_email)
email_only = email_only[email_only["clean_text"].str.len() > 20]
cyber_df = pd.DataFrame({
    "text":  email_only["clean_text"],
    "label": email_only["label"].astype(int)
})
print(f"  Cybersectony emails: {len(cyber_df)}  legit={(cyber_df.label==0).sum()}  phish={(cyber_df.label==1).sum()}")
all_dfs.append(cyber_df)

# ── Merge all datasets ─────────────────────────────────────────────
print("\nMerging all datasets...")
merged = pd.concat(all_dfs, ignore_index=True)
merged = merged.drop_duplicates(subset="text")
merged = merged[merged["text"].str.len() > 20]
merged = merged.dropna(subset=["text", "label"])
merged["label"] = merged["label"].astype(int)

print(f"Total: {len(merged)}  legit={(merged.label==0).sum()}  phish={(merged.label==1).sum()}")

# ── Stratified split ───────────────────────────────────────────────
train, temp = train_test_split(merged, test_size=0.3, random_state=42, stratify=merged["label"])
val, test   = train_test_split(temp,   test_size=0.5, random_state=42, stratify=temp["label"])

DATA_PROC.mkdir(parents=True, exist_ok=True)
train.to_csv(DATA_PROC / "train.csv", index=False)
val.to_csv(DATA_PROC   / "val.csv",   index=False)
test.to_csv(DATA_PROC  / "test.csv",  index=False)

print(f"\nSplit sizes:")
print(f"  Train: {len(train)}  legit={(train.label==0).sum()}  phish={(train.label==1).sum()}")
print(f"  Val  : {len(val)}    legit={(val.label==0).sum()}  phish={(val.label==1).sum()}")
print(f"  Test : {len(test)}   legit={(test.label==0).sum()}  phish={(test.label==1).sum()}")
print("\nDataset preparation complete!")