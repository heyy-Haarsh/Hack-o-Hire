# scripts/debug_audio.py
import numpy as np
import torch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from config import DEVICE, MODELS_DIR, CLIP_SAMPLES, SAMPLE_RATE
from model import DeepfakeVoiceDetector
import librosa

deep = DeepfakeVoiceDetector().to(DEVICE)
deep.load_state_dict(torch.load(MODELS_DIR / "best_eer.pt", map_location=DEVICE))
deep.eval()

path = "outputs/real1_fixed.wav"

print("=== PATH 1: diagnose.py method ===")
from features import load_audio, chunk_audio, extract_sequence
y1     = load_audio(path)
chunks = chunk_audio(y1)
chunk1 = chunks[0]
print(f"Audio length   : {len(y1)}")
print(f"Num chunks     : {len(chunks)}")
print(f"Chunk max amp  : {np.max(np.abs(chunk1)):.4f}")
with torch.no_grad():
    seq1 = torch.tensor(extract_sequence(chunk1)).unsqueeze(0).to(DEVICE)
    s1   = deep(seq1).squeeze().item()
print(f"Deep score     : {s1:.4f}")

print()
print("=== PATH 2: evaluate.py predict() method ===")
from evaluate import predict, load_models
from explainer import load_rf
rf = load_rf()
result = predict(path, deep, rf, use_llm=False)
print(f"Deep score     : {result['deep_score']}")
print(f"Final score    : {result['final_score']}")
print(f"Verdict        : {result['verdict']}")

print()
print("=== RAW audio comparison ===")
y_raw, sr = librosa.load(path, sr=16000, mono=True)
print(f"Raw max amp    : {np.max(np.abs(y_raw)):.4f}")
print(f"Raw duration   : {len(y_raw)/sr:.2f}s")
print(f"After normalize: {np.max(np.abs(librosa.util.normalize(y_raw))):.4f}")