# scripts/demo_correct.py
import torch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from features import extract_sequence, extract_aggregate, load_audio, chunk_audio
from model import DeepfakeVoiceDetector
from explainer import load_rf
from config import DEVICE, MODELS_DIR
import json

deep = DeepfakeVoiceDetector().to(DEVICE)
deep.load_state_dict(torch.load(MODELS_DIR / "best_eer.pt", map_location=DEVICE))
deep.eval()
rf = load_rf()

flac_dir = Path("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac")
proto    = open("data/raw/protocols/ASVspoof2019.LA.cm.train.trn.txt").readlines()

# Pick 3 bonafide and 3 spoof files
bonafide = [l.split()[1] for l in proto if "bonafide" in l][:3]
spoof    = [l.split()[1] for l in proto if "spoof" in l][:3]

THRESHOLD = 0.5

def predict_file(path, true_label):
    y   = load_audio(str(path))
    ch  = chunk_audio(y)
    with torch.no_grad():
        seq = torch.tensor(extract_sequence(ch[0])).unsqueeze(0).to(DEVICE)
        ds  = deep(seq).squeeze().item()
    rs      = rf.predict_proba([extract_aggregate(ch[0])])[0][1]
    fs      = 0.6 * ds + 0.4 * rs
    risk    = int(fs * 100)
    verdict = "FAKE" if fs >= THRESHOLD else "REAL"
    correct = "✓ CORRECT" if verdict == true_label else "✗ WRONG"

    tiers = [(86,"CRITICAL"),(61,"HIGH"),(31,"MEDIUM"),(0,"LOW")]
    tier  = next(t for thresh,t in tiers if risk >= thresh)

    print(f"  File    : {Path(path).name}")
    print(f"  Truth   : {true_label}")
    print(f"  Verdict : {verdict}  {correct}")
    print(f"  Score   : {risk}/100  [{tier}]")
    print(f"  Deep={ds:.4f}  RF={rs:.4f}  Final={fs:.4f}")
    print()

print("=" * 55)
print("FraudShield — Demo with ASVspoof Dataset Files")
print("=" * 55)

print("\n--- REAL (Bonafide) voices ---")
for fid in bonafide:
    predict_file(flac_dir / f"{fid}.flac", "REAL")

print("--- FAKE (Spoof) voices ---")
for fid in spoof:
    predict_file(flac_dir / f"{fid}.flac", "FAKE")