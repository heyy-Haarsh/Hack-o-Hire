# src/train.py
import torch
import csv
import numpy as np
from torch.utils.data import DataLoader
from torch.optim import AdamW
from transformers import get_linear_schedule_with_warmup
from sklearn.metrics import f1_score, classification_report
from tqdm import tqdm
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from model import EmailDataset, load_model
from config import (DEVICE, MODELS_DIR, OUTPUTS_DIR, DATA_PROC,
                    BATCH_SIZE, EPOCHS, LR, WEIGHT_DECAY)


def train_epoch(model, loader, optimizer, scheduler):
    model.train()
    total_loss = 0
    for batch in tqdm(loader, desc="  train", leave=False):
        optimizer.zero_grad()
        input_ids = batch["input_ids"].to(DEVICE)
        attn_mask = batch["attention_mask"].to(DEVICE)
        labels    = batch["label"].to(DEVICE)
        outputs   = model(input_ids=input_ids,
                          attention_mask=attn_mask,
                          labels=labels)
        outputs.loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        scheduler.step()
        total_loss += outputs.loss.item()
    return total_loss / len(loader)


@torch.no_grad()
def eval_epoch(model, loader):
    model.eval()
    all_preds, all_labels = [], []
    for batch in tqdm(loader, desc="  eval ", leave=False):
        input_ids = batch["input_ids"].to(DEVICE)
        attn_mask = batch["attention_mask"].to(DEVICE)
        preds     = model(input_ids=input_ids,
                          attention_mask=attn_mask).logits.argmax(dim=-1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(batch["label"].numpy())
    f1 = f1_score(all_labels, all_preds, average="binary")
    return f1, all_preds, all_labels


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading tokenizer and model...")
    tokenizer, model = load_model(from_saved=False)

    print("Loading datasets...")
    train_ds = EmailDataset(str(DATA_PROC / "train.csv"), tokenizer)
    val_ds   = EmailDataset(str(DATA_PROC / "val.csv"),   tokenizer)

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE,
                              shuffle=True,  num_workers=0, pin_memory=True)
    val_loader   = DataLoader(val_ds,   batch_size=BATCH_SIZE,
                              shuffle=False, num_workers=0, pin_memory=True)

    optimizer   = AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    total_steps = len(train_loader) * EPOCHS
    scheduler   = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=total_steps // 10,
        num_training_steps=total_steps
    )

    best_f1  = 0.0
    log_path = OUTPUTS_DIR / "training_log.csv"
    with open(log_path, "w", newline="") as f:
        csv.writer(f).writerow(["epoch", "train_loss", "val_f1"])

    print(f"\nTraining {EPOCHS} epochs on {DEVICE}")
    print("=" * 55)

    for epoch in range(1, EPOCHS + 1):
        loss          = train_epoch(model, train_loader, optimizer, scheduler)
        val_f1, _, _  = eval_epoch(model, val_loader)

        status = ""
        if val_f1 > best_f1:
            best_f1 = val_f1
            model.save_pretrained(str(MODELS_DIR / "phishing_classifier"))
            tokenizer.save_pretrained(str(MODELS_DIR / "phishing_classifier"))
            status = "  <-- best saved"

        print(f"Epoch {epoch:02d}/{EPOCHS}  "
              f"loss={loss:.4f}  "
              f"val_F1={val_f1:.4f}{status}")

        with open(log_path, "a", newline="") as f:
            csv.writer(f).writerow([epoch, round(loss, 4), round(val_f1, 4)])

    print("=" * 55)
    print(f"Training complete. Best F1: {best_f1:.4f}")
    print(f"Model saved → models/saved/phishing_classifier/")


if __name__ == "__main__":
    main()