"""
prepare_partialspoof.py
-----------------------
Extracts PartialSpoof v1.2 archives and organises the FAKE audio files into
    data/raw/spoof/      (121k+ partially-spoofed WAV files)

NOTE: PartialSpoof does NOT ship bonafide (real) audio — those come from
ASVspoof2019-LA which is a separate download. Instead, this script expects
you to supply real audio via LJSpeech (recommended) placed at:
    data/raw/bonafide/   (put LJSpeech wavs/ files here)

Download LJSpeech (~2.6 GB):
    https://data.keithito.com/data/speech/LJSpeech-1.1.tar.bz2
    Extract, then copy/move all .wav files from LJSpeech-1.1/wavs/ into data/raw/bonafide/

After this script completes + bonafide wavs are in place, run:
    venv\\Scripts\\python scripts\\precompute_from_folders.py --real data/raw/bonafide --fake data/raw/spoof
    venv\\Scripts\\python src\\train.py --finetune
    venv\\Scripts\\python scripts\\promote_checkpoint.py --name best_eer_v2.pt
"""

import os
import sys
import shutil
import tarfile
import argparse
from pathlib import Path

DATA_DIR    = Path(__file__).resolve().parent.parent / "data"
EXTRACT_DIR = DATA_DIR / "extracted"
OUT_REAL    = DATA_DIR / "raw" / "bonafide"
OUT_FAKE    = DATA_DIR / "raw" / "spoof"

ARCHIVES = {
    "train":     DATA_DIR / "database_train.tar.gz",
    "dev":       DATA_DIR / "database_dev.tar.gz",
    "eval":      DATA_DIR / "database_eval.tar.gz",
    "protocols": DATA_DIR / "database_protocols.tar.gz",
}

PROTOCOL_FILES = [
    "database/protocols/PartialSpoof_LA_cm_protocols/PartialSpoof.LA.cm.train.trl.txt",
    "database/protocols/PartialSpoof_LA_cm_protocols/PartialSpoof.LA.cm.dev.trl.txt",
    "database/protocols/PartialSpoof_LA_cm_protocols/PartialSpoof.LA.cm.eval.trl.txt",
]

# Map protocol split prefix → wav subfolder
SPLIT_DIRS = {
    "CON_T_": EXTRACT_DIR / "database" / "train" / "con_wav",
    "CON_D_": EXTRACT_DIR / "database" / "dev"   / "con_wav",
    "CON_E_": EXTRACT_DIR / "database" / "eval"  / "con_wav",
}


def extract_archive(name: str, path: Path, force: bool = False):
    marker = EXTRACT_DIR / f".{name}_extracted"
    if marker.exists() and not force:
        print(f"  [skip] {path.name} already extracted")
        return
    print(f"  Extracting {path.name} → {EXTRACT_DIR} ...", flush=True)
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "r:gz") as tf:
        tf.extractall(EXTRACT_DIR)
    marker.touch()
    print(f"  Done: {path.name}")


def read_labels() -> dict[str, str]:
    """Returns {file_stem: 'bonafide'|'spoof'} from all protocol files."""
    labels: dict[str, str] = {}
    for proto_rel in PROTOCOL_FILES:
        proto_path = EXTRACT_DIR / proto_rel
        if not proto_path.exists():
            print(f"  [warn] protocol file not found: {proto_path}")
            continue
        with open(proto_path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 5:
                    continue
                # format: speaker  file_stem  -  CON  label
                stem  = parts[1]   # e.g. CON_T_0000029
                label = parts[4]   # bonafide | spoof
                labels[stem] = label
    return labels


def link_or_copy(src: Path, dst: Path):
    """Try hardlink first (fast, no extra disk), fall back to copy."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        return
    try:
        os.link(src, dst)
    except (OSError, NotImplementedError):
        shutil.copy2(src, dst)


def organise_files(dry_run: bool = False) -> int:
    """
    Scan all con_wav folders and hard-link/copy every WAV into data/raw/spoof/.
    Bonafide (LA_T_*.flac) are NOT in the PartialSpoof archives — skip them.
    Returns number of fake files organised.
    """
    n_fake = 0
    for prefix, src_dir in SPLIT_DIRS.items():
        if not src_dir.exists():
            print(f"  [warn] folder not found: {src_dir}")
            continue
        for wav in src_dir.glob("*.wav"):
            dst = OUT_FAKE / wav.name
            n_fake += 1
            if not dry_run:
                link_or_copy(wav, dst)
    return n_fake


def main():
    parser = argparse.ArgumentParser(description="Prepare PartialSpoof dataset for training")
    parser.add_argument("--force-extract", action="store_true", help="Re-extract even if already done")
    parser.add_argument("--dry-run",       action="store_true", help="Parse and count only, no file ops")
    args = parser.parse_args()

    # ── 1. Check archives exist ──────────────────────────────────────────────
    missing = [n for n, p in ARCHIVES.items() if not p.exists()]
    if missing:
        print(f"ERROR: Missing archives in {DATA_DIR}: {missing}")
        sys.exit(1)

    # ── 2. Extract ────────────────────────────────────────────────────────────
    print("\n[1/2] Extracting archives ...")
    for name, path in ARCHIVES.items():
        extract_archive(name, path, force=args.force_extract)

    # ── 3. Organise fake files ────────────────────────────────────────────────
    print(f"\n[2/2] Organising fake files {'(dry-run)' if args.dry_run else ''} ...")
    OUT_FAKE.mkdir(parents=True, exist_ok=True)

    n_fake = organise_files(dry_run=args.dry_run)
    print(f"  spoof → {OUT_FAKE}  ({n_fake:,} files)")

    if args.dry_run:
        print("\n[dry-run] No files written. Remove --dry-run to proceed.")
        return

    # ── Done ─────────────────────────────────────────────────────────────────
    bonafide_count = sum(1 for _ in OUT_REAL.glob("*.wav")) if OUT_REAL.exists() else 0
    print(f"\n{'✅' if bonafide_count > 0 else '⚠️ '} Dataset status:")
    print(f"  Fake  : {n_fake:,} WAV files in {OUT_FAKE}")
    print(f"  Real  : {bonafide_count:,} WAV files in {OUT_REAL}")

    if bonafide_count == 0:
        print()
        print("⚠️  No real (bonafide) audio found!")
        print("   Download LJSpeech (~2.6 GB) from:")
        print("     https://data.keithito.com/data/speech/LJSpeech-1.1.tar.bz2")
        print(f"   Then extract and copy all .wav files into: {OUT_REAL}")
        print()
        print("   Once done, run:")
    else:
        print()
        print("Next steps:")

    print("─" * 60)
    print("1) Precompute MFCC features:")
    print("   venv\\Scripts\\python scripts\\precompute_from_folders.py \\")
    print(f"       --real {OUT_REAL} \\")
    print(f"       --fake {OUT_FAKE}")
    print()
    print("2) Fine-tune from existing best_eer.pt:")
    print("   venv\\Scripts\\python src\\train.py --finetune")
    print()
    print("3) Deploy as v2 (enables ensemble with original model):")
    print("   venv\\Scripts\\python scripts\\promote_checkpoint.py --name best_eer_v2.pt")
    print("─" * 60)


if __name__ == "__main__":
    main()
