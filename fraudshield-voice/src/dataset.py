# src/dataset.py
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import DATA_PROC, BATCH_SIZE, REAL, FAKE


class VoiceDataset(Dataset):
    def __init__(self, split: str):
        base = DATA_PROC / split
        self.seqs   = np.load(base / "sequences.npy")    # [N, 40, T]
        self.aggs   = np.load(base / "aggregates.npy")   # [N, ~260]
        self.labels = np.load(base / "labels.npy")       # [N]
        print(f"  [{split}] loaded {len(self.labels)} samples  "
              f"| real={( self.labels==REAL).sum()}  "
              f"fake={(self.labels==FAKE).sum()}")

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        seq = torch.tensor(self.seqs[idx],   dtype=torch.float32)
        agg = torch.tensor(self.aggs[idx],   dtype=torch.float32)
        lbl = torch.tensor(self.labels[idx], dtype=torch.float32)
        return seq, agg, lbl


def build_loaders():
    print("Loading datasets...")
    train_ds = VoiceDataset("train_split")
    val_ds   = VoiceDataset("val_split")
    test_ds  = VoiceDataset("eval")

    labels = train_ds.labels
    n_real = (labels == REAL).sum()
    n_fake = (labels == FAKE).sum()
    w_real = len(labels) / (2.0 * n_real)
    w_fake = len(labels) / (2.0 * n_fake)
    weights = [w_real if l == REAL else w_fake for l in labels]
    sampler = WeightedRandomSampler(weights, num_samples=len(weights), replacement=True)

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE,
                              sampler=sampler, num_workers=0, pin_memory=True)
    val_loader   = DataLoader(val_ds,   batch_size=BATCH_SIZE,
                              shuffle=False, num_workers=0, pin_memory=True)
    test_loader  = DataLoader(test_ds,  batch_size=BATCH_SIZE,
                              shuffle=False, num_workers=0, pin_memory=True)

    print(f"  Loaders ready — train: {len(train_loader)} batches "
          f"| val: {len(val_loader)} | test: {len(test_loader)}")
    return train_loader, val_loader, test_loader