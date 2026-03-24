# scripts/precompute_features.py
import numpy as np
import pandas as pd
from pathlib import Path
from tqdm import tqdm
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from features import load_audio, chunk_audio, extract_sequence, extract_aggregate
from config import DATA_RAW, DATA_PROC, REAL, FAKE

PROTOCOLS = Path("data/raw/protocols")

PROTOCOL_FILES = {
    "train": "ASVspoof2019.LA.cm.train.trn.txt",
    "dev":   "ASVspoof2019.LA.cm.eval.trl.txt",   # use eval as dev
    "eval":  "ASVspoof2019.LA.cm.eval.trl.txt",
}

FLAC_DIRS = {
    "train": DATA_RAW / "ASVspoof2019_LA_train" / "flac",
    "dev":   DATA_RAW / "ASVspoof2019_LA_eval"  / "flac", # use eval flac
    "eval":  DATA_RAW / "ASVspoof2019_LA_eval"  / "flac",
}


def parse_label_file(txt_path: Path, flac_dir: Path) -> pd.DataFrame:
    rows = []
    for line in open(txt_path, errors="ignore"):
        parts = line.strip().split()
        if len(parts) < 5:
            continue
        file_id = parts[1]
        label   = parts[-1]
        fpath   = flac_dir / f"{file_id}.flac"
        if fpath.exists():
            rows.append({
                "file":  str(fpath),
                "label": REAL if label == "bonafide" else FAKE
            })
    return pd.DataFrame(rows)


def process_split(split: str):
    txt_path = PROTOCOLS / PROTOCOL_FILES[split]
    flac_dir = FLAC_DIRS[split]

    print(f"\n[{split}] Protocol : {txt_path.name}")
    print(f"[{split}] Flac dir  : {flac_dir}")

    if not flac_dir.exists():
        print(f"  SKIP — flac dir not found: {flac_dir}")
        return

    df = parse_label_file(txt_path, flac_dir)
    print(f"[{split}] Matched   : {len(df)} files  "
          f"| real={(df.label==REAL).sum()}  "
          f"fake={(df.label==FAKE).sum()}")

    if len(df) == 0:
        print("  ERROR: No files matched.")
        return

    seqs, aggs, labels = [], [], []
    errors = 0

    for _, row in tqdm(df.iterrows(), total=len(df),
                       desc=f"  {split}"):
        try:
            y      = load_audio(row["file"])
            chunks = chunk_audio(y)
            for chunk in chunks:
                seqs.append(extract_sequence(chunk))
                aggs.append(extract_aggregate(chunk))
                labels.append(row["label"])
        except Exception as e:
            errors += 1
            if errors <= 3:
                print(f"\n  Warning: skipped {row['file']} — {e}")

    out_dir = DATA_PROC / split
    out_dir.mkdir(parents=True, exist_ok=True)

    np.save(out_dir / "sequences.npy",  np.array(seqs,   dtype=np.float32))
    np.save(out_dir / "aggregates.npy", np.array(aggs,   dtype=np.float32))
    np.save(out_dir / "labels.npy",     np.array(labels, dtype=np.int64))

    print(f"[{split}] Saved {len(labels)} chunks → {out_dir}")
    print(f"  sequences.npy  : {np.array(seqs).shape}")
    print(f"  aggregates.npy : {np.array(aggs).shape}")
    if errors:
        print(f"  Skipped {errors} files")


if __name__ == "__main__":
    print("FraudShield — Feature Pre-computation")
    print("Using official ASVspoof 2019 LA protocols")
    print("train=train  |  dev=eval  |  eval=eval")
    print("Estimated time: 30-60 min")
    print("=" * 50)

    for split in ["train", "dev", "eval"]:
        process_split(split)

    print("\n" + "=" * 50)
    print("All splits done!")
    print("Next: python src/train.py")