# scripts/diagnose.py
import torch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from features import extract_sequence, extract_aggregate, load_audio, chunk_audio
from model import DeepfakeVoiceDetector
from explainer import load_rf
from config import DEVICE, MODELS_DIR

deep = DeepfakeVoiceDetector().to(DEVICE)
deep.load_state_dict(torch.load(MODELS_DIR / "best_eer.pt", map_location=DEVICE))
deep.eval()
rf = load_rf()

flac_dir = Path("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac")
proto    = open("data/raw/protocols/ASVspoof2019.LA.cm.train.trn.txt").readlines()
bonafide = [l.split()[1] for l in proto if "bonafide" in l][:5]
spoof    = [l.split()[1] for l in proto if "spoof" in l][:5]

def score_file(path):
    y  = load_audio(str(path))
    ch = chunk_audio(y)
    with torch.no_grad():
        seq = torch.tensor(extract_sequence(ch[0])).unsqueeze(0).to(DEVICE)
        ds  = deep(seq).squeeze().item()
    rs = rf.predict_proba([extract_aggregate(ch[0])])[0][1]
    fs = 0.6 * ds + 0.4 * rs
    verdict = "FAKE" if fs >= 0.5 else "REAL"
    return ds, rs, fs, verdict

print("=== Known BONAFIDE files from training ===")
for fid in bonafide:
    ds, rs, fs, v = score_file(flac_dir / f"{fid}.flac")
    print(f"  {fid}: deep={ds:.4f}  rf={rs:.4f}  final={fs:.4f}  -> {v}")

print()
print("=== Known SPOOF files from training ===")
for fid in spoof:
    ds, rs, fs, v = score_file(flac_dir / f"{fid}.flac")
    print(f"  {fid}: deep={ds:.4f}  rf={rs:.4f}  final={fs:.4f}  -> {v}")

print()
print("=== Your recordings ===")
for f in ["outputs/real1_fixed.wav", "outputs/demo_fake.wav"]:
    if Path(f).exists():
        ds, rs, fs, v = score_file(f)
        print(f"  {f}: deep={ds:.4f}  rf={rs:.4f}  final={fs:.4f}  -> {v}")