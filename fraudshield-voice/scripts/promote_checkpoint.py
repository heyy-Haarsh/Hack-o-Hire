# scripts/promote_checkpoint.py
import torch
from pathlib import Path

ckpt_path = Path("models/saved/checkpoint_latest.pt")
ckpt = torch.load(str(ckpt_path), map_location="cpu")

print(f"Checkpoint epoch : {ckpt['epoch']}")
print(f"Checkpoint EER   : {ckpt['best_eer']:.4f}")

# Save just model weights
torch.save(ckpt["model"], "models/saved/best_eer.pt")
print("Saved new best_eer.pt from latest checkpoint")