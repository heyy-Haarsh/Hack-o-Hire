# scripts/debug_chunks.py
import numpy as np
import torch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from config import DEVICE, MODELS_DIR
from model import DeepfakeVoiceDetector
from features import load_audio, chunk_audio, extract_sequence

deep = DeepfakeVoiceDetector().to(DEVICE)
deep.load_state_dict(torch.load(MODELS_DIR / "best_eer.pt", map_location=DEVICE))
deep.eval()

path   = "outputs/real1_fixed.wav"
y      = load_audio(path)
chunks = chunk_audio(y)

print(f"Total chunks: {len(chunks)}")
print()

for i, chunk in enumerate(chunks):
    energy = np.mean(chunk**2)
    with torch.no_grad():
        seq   = torch.tensor(extract_sequence(chunk)).unsqueeze(0).to(DEVICE)
        score = deep(seq).squeeze().item()
    print(f"Chunk {i+1}: energy={energy:.6f}  deep={score:.4f}  "
          f"speech={'YES' if energy > 0.001 else 'SILENCE/NOISE'}")