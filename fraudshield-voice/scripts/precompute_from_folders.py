# scripts/precompute_from_folders.py
"""
Generic feature pre-computation for ANY dataset organised as two folders:
  --real  <dir>   folder containing real/bonafide audio (any format)
  --fake  <dir>   folder containing fake/deepfake audio (any format)

Works with WaveFake, ASVspoof2021-DF, custom recordings, or any mix.
Automatically splits into train_split / val_split / eval at 80/10/10.

Usage:
  python scripts/precompute_from_folders.py \\
      --real data/raw/real \\
      --fake data/raw/fake

  # Override split ratios
  python scripts/precompute_from_folders.py \\
      --real data/raw/real --fake data/raw/fake \\
      --train 0.80 --val 0.10 --seed 42

Supported audio formats: .flac .wav .mp3 .m4a .ogg .aac .wma .mp4 .webm
"""

import argparse
import random
import sys
import numpy as np
from pathlib import Path
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from features import load_audio, chunk_audio, extract_sequence, extract_aggregate
from config import DATA_PROC, REAL, FAKE

AUDIO_EXTS = {".flac", ".wav", ".mp3", ".m4a", ".ogg", ".aac", ".wma", ".mp4", ".webm"}


def collect_files(directory: Path) -> list:
    """Recursively collect all audio files under directory."""
    files = []
    for f in sorted(directory.rglob("*")):
        if f.is_file() and f.suffix.lower() in AUDIO_EXTS:
            files.append(f)
    return files


def split_files(files: list, train_ratio: float, val_ratio: float, seed: int):
    """Shuffle and split file list into train / val / eval."""
    rng = random.Random(seed)
    shuffled = files[:]
    rng.shuffle(shuffled)
    n = len(shuffled)
    n_train = int(n * train_ratio)
    n_val   = int(n * val_ratio)
    return (
        shuffled[:n_train],
        shuffled[n_train:n_train + n_val],
        shuffled[n_train + n_val:],
    )


def process_and_save(file_label_pairs: list, out_dir: Path, augment: bool):
    """Extract features for a list of (path, label) pairs and save .npy files."""
    out_dir.mkdir(parents=True, exist_ok=True)
    seqs, aggs, labels = [], [], []
    errors = 0

    for fpath, label in tqdm(file_label_pairs, desc=f"  {out_dir.name}", unit="file"):
        try:
            y      = load_audio(str(fpath))
            chunks = chunk_audio(y)
        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"\n  ⚠  Skipped {fpath.name}: {e}")
            continue
        for chunk in chunks:
            try:
                seqs.append(extract_sequence(chunk, augment=augment))
                aggs.append(extract_aggregate(chunk, augment=augment))
                labels.append(label)
            except Exception:
                errors += 1

    seqs_arr   = np.array(seqs,   dtype=np.float32)
    aggs_arr   = np.array(aggs,   dtype=np.float32)
    labels_arr = np.array(labels, dtype=np.int64)

    np.save(out_dir / "sequences.npy",  seqs_arr)
    np.save(out_dir / "aggregates.npy", aggs_arr)
    np.save(out_dir / "labels.npy",     labels_arr)

    n_real = int((labels_arr == REAL).sum())
    n_fake = int((labels_arr == FAKE).sum())
    print(f"  ✅ {out_dir.name}: {len(labels_arr)} chunks  "
          f"| real={n_real}  fake={n_fake}  "
          f"| seqs={seqs_arr.shape}  errors={errors}")


def main():
    parser = argparse.ArgumentParser(description="Pre-compute features from real/fake audio folders")
    parser.add_argument("--real",  required=True, nargs="+",
                        help="One or more directories containing real/bonafide audio. "
                             "E.g.: --real data/raw/wavefake/real data/raw/myown/real")
    parser.add_argument("--fake",  required=True, nargs="+",
                        help="One or more directories containing fake/deepfake audio. "
                             "E.g.: --fake data/raw/wavefake/fake data/raw/myown/fake")
    parser.add_argument("--train", type=float, default=0.80, help="Train ratio (default 0.80)")
    parser.add_argument("--val",   type=float, default=0.10, help="Val ratio   (default 0.10)")
    parser.add_argument("--seed",  type=int,   default=42,   help="Random seed  (default 42)")
    args = parser.parse_args()

    real_dirs = [Path(d) for d in args.real]
    fake_dirs = [Path(d) for d in args.fake]

    for d in real_dirs + fake_dirs:
        if not d.exists():
            print(f"ERROR: directory not found: {d}"); sys.exit(1)

    print("=" * 60)
    print("FraudShield — Generic Feature Pre-computation")
    print(f"  Real dirs : {[str(d) for d in real_dirs]}")
    print(f"  Fake dirs : {[str(d) for d in fake_dirs]}")
    print(f"  Split     : train={args.train:.0%}  val={args.val:.0%}  "
          f"eval={1-args.train-args.val:.0%}")
    print("=" * 60)

    # Collect files from all supplied directories
    real_files = [f for d in real_dirs for f in collect_files(d)]
    fake_files = [f for d in fake_dirs for f in collect_files(d)]
    print(f"\nFound: {len(real_files)} real files, {len(fake_files)} fake files")

    if not real_files or not fake_files:
        print("ERROR: No audio files found. Check paths and extensions."); sys.exit(1)

    # Split each class independently to maintain balance across splits
    r_train, r_val, r_eval = split_files(real_files, args.train, args.val, args.seed)
    f_train, f_val, f_eval = split_files(fake_files, args.train, args.val, args.seed)

    print(f"\n  train : real={len(r_train)}  fake={len(f_train)}")
    print(f"  val   : real={len(r_val)}    fake={len(f_val)}")
    print(f"  eval  : real={len(r_eval)}   fake={len(f_eval)}")
    print()

    splits = {
        "train_split": (r_train, f_train, True),   # augment=True
        "val_split":   (r_val,   f_val,   False),
        "eval":        (r_eval,  f_eval,  False),
    }

    for split_name, (real_f, fake_f, augment) in splits.items():
        print(f"\n[{split_name}] augment={augment}")
        pairs = [(f, REAL) for f in real_f] + [(f, FAKE) for f in fake_f]
        random.Random(args.seed).shuffle(pairs)
        process_and_save(pairs, DATA_PROC / split_name, augment=augment)

    print("\n" + "=" * 60)
    print("Pre-computation complete!")
    print("Next step:")
    print("  python src/train.py")
    print("  python src/train.py --finetune   ← start from existing best_eer.pt")
    print("=" * 60)


if __name__ == "__main__":
    main()
