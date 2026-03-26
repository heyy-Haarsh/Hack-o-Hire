# scripts/promote_checkpoint.py
"""
Promotes the best trained model (models/saved/best_eer.pt) to the
email_monitoring inference directory.

Also supports extracting model weights from checkpoint_latest.pt if needed.

Usage:
  python scripts/promote_checkpoint.py            # promote best_eer.pt
  python scripts/promote_checkpoint.py --from-latest  # extract from checkpoint_latest first
"""
import argparse
import shutil
import torch
from pathlib import Path

ROOT        = Path(__file__).parent.parent
SAVED       = ROOT / "models" / "saved"
BEST_PT     = SAVED / "best_eer.pt"
LATEST_CKPT = SAVED / "checkpoint_latest.pt"
DEST        = ROOT.parent / "email_monitoring" / "models" / "best_eer.pt"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-latest", action="store_true",
                        help="Extract model weights from checkpoint_latest.pt first")
    parser.add_argument("--name", default="best_eer.pt",
                        help="Filename to save in email_monitoring/models/ "
                             "(default: best_eer.pt). Use best_eer_v2.pt for "
                             "a second model to run alongside the original.")
    args = parser.parse_args()
    DEST = ROOT.parent / "email_monitoring" / "models" / args.name

    if args.from_latest:
        if not LATEST_CKPT.exists():
            print(f"ERROR: {LATEST_CKPT} not found"); return
        ckpt = torch.load(str(LATEST_CKPT), map_location="cpu")
        print(f"  Checkpoint epoch : {ckpt['epoch']}")
        print(f"  Checkpoint EER   : {ckpt['best_eer']:.4f}")
        torch.save(ckpt["model"], BEST_PT)
        print(f"  Extracted → {BEST_PT.name}")

    if not BEST_PT.exists():
        print(f"ERROR: {BEST_PT} not found. Run training first."); return

    DEST.parent.mkdir(parents=True, exist_ok=True)
    if DEST.exists():
        backup = DEST.with_suffix(".pt.bak")
        shutil.copy2(DEST, backup)
        print(f"  Backed up previous model → {backup.name}")

    shutil.copy2(BEST_PT, DEST)
    size_kb = BEST_PT.stat().st_size // 1024
    print(f"  ✅ Promoted best_eer.pt ({size_kb} KB) → email_monitoring/models/{args.name}")


if __name__ == "__main__":
    main()
