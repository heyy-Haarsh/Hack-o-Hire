# download_datasets.py
from datasets import load_dataset
import pandas as pd
from pathlib import Path

Path("data/raw").mkdir(parents=True, exist_ok=True)

# Dataset 1 — SetFit Enron spam
print("Downloading SetFit/enron_spam...")
try:
    ds1 = load_dataset("SetFit/enron_spam")
    df1 = ds1["train"].to_pandas()
    print(f"  Enron: {len(df1)} emails")
    print(f"  Columns: {df1.columns.tolist()}")
    print(f"  Labels: {df1['label'].value_counts().to_dict()}")
    print(f"  Sample:\n{df1.head(2)}")
    df1.to_csv("data/raw/enron_spam.csv", index=False)
    print("  Saved enron_spam.csv")
except Exception as e:
    print(f"  FAILED: {e}")

print()

# Dataset 2 — zefang-liu phishing emails
print("Downloading zefang-liu/phishing-email-dataset...")
try:
    ds2 = load_dataset("zefang-liu/phishing-email-dataset")
    df2 = ds2["train"].to_pandas()
    print(f"  Phishing: {len(df2)} emails")
    print(f"  Columns: {df2.columns.tolist()}")
    print(f"  Sample:\n{df2.head(2)}")
    df2.to_csv("data/raw/phishing_emails.csv", index=False)
    print("  Saved phishing_emails.csv")
except Exception as e:
    print(f"  FAILED: {e}")

print()

# Dataset 3 — cybersectony large combined dataset
print("Downloading cybersectony/PhishingEmailDetectionv2.0...")
try:
    ds3 = load_dataset("cybersectony/PhishingEmailDetectionv2.0")
    df3 = ds3["train"].to_pandas()
    print(f"  Combined: {len(df3)} rows")
    print(f"  Columns: {df3.columns.tolist()}")
    print(f"  Sample:\n{df3.head(2)}")
    df3.to_csv("data/raw/phishing_combined.csv", index=False)
    print("  Saved phishing_combined.csv")
except Exception as e:
    print(f"  FAILED: {e}")

print()
print("Done — check outputs above for column names and label formats")