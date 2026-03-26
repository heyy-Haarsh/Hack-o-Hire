# src/train.py
import torch
import torch.nn as nn
import numpy as np
import csv
import argparse
from torch.optim import Adam
from torch.optim.lr_scheduler import CosineAnnealingLR
from sklearn.metrics import roc_curve
from tqdm import tqdm
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from model import DeepfakeVoiceDetector
from dataset import build_loaders
from config import DEVICE, MODELS_DIR, OUTPUTS_DIR, EPOCHS, LR, LR_MIN, WEIGHT_DECAY


def compute_eer(scores, labels):
    """Equal Error Rate — the primary metric. Lower is better."""
    fpr, tpr, _ = roc_curve(labels, scores, pos_label=1)
    fnr = 1 - tpr
    idx = np.nanargmin(np.abs(fpr - fnr))
    return float((fpr[idx] + fnr[idx]) / 2)


def train_epoch(model, loader, optimizer, criterion):
    model.train()
    total_loss = 0
    for seq, agg, lbl in tqdm(loader, desc="  train", leave=False):
        seq, lbl = seq.to(DEVICE), lbl.to(DEVICE)
        optimizer.zero_grad()
        pred = model(seq).squeeze(1)
        loss = criterion(pred, lbl)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        total_loss += loss.item()
    return total_loss / len(loader)


@torch.no_grad()
def eval_epoch(model, loader):
    model.eval()
    all_scores, all_labels = [], []
    for seq, agg, lbl in tqdm(loader, desc="  eval ", leave=False):
        seq = seq.to(DEVICE)
        pred = model(seq).squeeze(1).cpu().numpy()
        all_scores.extend(pred.tolist())
        all_labels.extend(lbl.numpy().tolist())
    eer = compute_eer(all_scores, all_labels)
    return eer, all_scores, all_labels


def main():
    parser = argparse.ArgumentParser(description="Train DeepfakeVoiceDetector")
    parser.add_argument("--finetune", action="store_true",
                        help="Start from existing best_eer.pt instead of random init. "
                             "Uses a lower LR (LR/10) and fewer epochs (EPOCHS//2).")
    args = parser.parse_args()

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    train_loader, val_loader, _ = build_loaders()

    model     = DeepfakeVoiceDetector().to(DEVICE)
    criterion = nn.BCELoss()

    finetune_lr = LR / 10   # gentler LR so we don't overwrite learned weights

    # ── Resume / fine-tune priority ────────────────────────────────
    # 1. checkpoint_latest.pt  (interrupted run → resume)
    # 2. best_eer.pt + --finetune flag  (fine-tune on new data)
    # 3. fresh random init
    start_epoch  = 1
    best_eer     = 1.0
    ckpt_path    = MODELS_DIR / "checkpoint_latest.pt"
    best_pt_path = MODELS_DIR / "best_eer.pt"
    actual_lr    = LR
    actual_epochs = EPOCHS

    if ckpt_path.exists():
        print(f"Resuming from {ckpt_path}...")
        ckpt = torch.load(ckpt_path, map_location=DEVICE)
        model.load_state_dict(ckpt["model"])
        optimizer = Adam(model.parameters(), lr=actual_lr, weight_decay=WEIGHT_DECAY)
        scheduler = CosineAnnealingLR(optimizer, T_max=actual_epochs, eta_min=LR_MIN)
        optimizer.load_state_dict(ckpt["optimizer"])
        scheduler.load_state_dict(ckpt["scheduler"])
        start_epoch = ckpt["epoch"] + 1
        best_eer    = ckpt["best_eer"]
        print(f"  Resumed from epoch {ckpt['epoch']}  best_EER={best_eer:.4f}")

    elif args.finetune and best_pt_path.exists():
        print(f"Fine-tuning from {best_pt_path} ...")
        state = torch.load(best_pt_path, map_location=DEVICE, weights_only=False)
        if isinstance(state, dict) and "model" in state:
            model.load_state_dict(state["model"])
        else:
            model.load_state_dict(state)
        actual_lr     = finetune_lr
        actual_epochs = max(EPOCHS // 2, 10)
        print(f"  LR={actual_lr}  epochs={actual_epochs}  (fine-tune mode)")
        optimizer = Adam(model.parameters(), lr=actual_lr, weight_decay=WEIGHT_DECAY)
        scheduler = CosineAnnealingLR(optimizer, T_max=actual_epochs, eta_min=LR_MIN)

    else:
        if args.finetune:
            print(f"Warning: --finetune set but {best_pt_path} not found. Starting fresh.")
        print(f"Starting fresh training for {actual_epochs} epochs on {DEVICE}")
        optimizer = Adam(model.parameters(), lr=actual_lr, weight_decay=WEIGHT_DECAY)
        scheduler = CosineAnnealingLR(optimizer, T_max=actual_epochs, eta_min=LR_MIN)

    log_path = OUTPUTS_DIR / "training_log.csv"
    if not ckpt_path.exists():
        with open(log_path, "w", newline="") as f:
            csv.writer(f).writerow(["epoch", "train_loss", "val_eer"])

    print("=" * 55)

    for epoch in range(start_epoch, actual_epochs + 1):
        loss          = train_epoch(model, train_loader, optimizer, criterion)
        val_eer, _, _ = eval_epoch(model, val_loader)
        scheduler.step()

        status = ""
        if val_eer < best_eer:
            best_eer = val_eer
            torch.save(model.state_dict(), MODELS_DIR / "best_eer.pt")
            status = "  <-- best saved"

        # Save latest checkpoint every epoch for resume
        torch.save({
            "epoch":     epoch,
            "model":     model.state_dict(),
            "optimizer": optimizer.state_dict(),
            "scheduler": scheduler.state_dict(),
            "best_eer":  best_eer,
        }, ckpt_path)

        print(f"Epoch {epoch:02d}/{actual_epochs}  "
              f"loss={loss:.4f}  "
              f"val_EER={val_eer:.4f}{status}")

        with open(log_path, "a", newline="") as f:
            csv.writer(f).writerow([epoch, round(loss, 4), round(val_eer, 4)])

    print("=" * 55)
    print(f"Training complete. Best EER: {best_eer:.4f}")


if __name__ == "__main__":
    main()