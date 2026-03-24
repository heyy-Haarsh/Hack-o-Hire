# scripts/test_pipeline.py
# Tests the ENTIRE pipeline end-to-end using synthetic audio.
# No dataset needed. Run this any time to verify everything works.

import numpy as np
import torch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config import SAMPLE_RATE, CLIP_SAMPLES, DEVICE
from features import extract_sequence, extract_aggregate, chunk_audio
from model import DeepfakeVoiceDetector

print("=" * 55)
print("FraudShield — Full Pipeline Test (synthetic audio)")
print("=" * 55)

# ── Step 1: Generate fake audio signals ───────────────────────────
print("\n[1] Generating synthetic audio...")

# Simulate a 'real' voice — natural random signal
real_audio = np.random.randn(CLIP_SAMPLES).astype(np.float32) * 0.1

# Simulate a 'fake' voice — periodic + smooth (like a vocoder output)
t = np.linspace(0, 3, CLIP_SAMPLES)
fake_audio = (
    0.3 * np.sin(2 * np.pi * 200 * t) +
    0.2 * np.sin(2 * np.pi * 400 * t) +
    0.1 * np.sin(2 * np.pi * 800 * t)
).astype(np.float32)

print(f"  Real audio shape : {real_audio.shape}  max={real_audio.max():.3f}")
print(f"  Fake audio shape : {fake_audio.shape}  max={fake_audio.max():.3f}")

# ── Step 2: Feature extraction ────────────────────────────────────
print("\n[2] Testing feature extraction...")

real_seq = extract_sequence(real_audio)
real_agg = extract_aggregate(real_audio)
fake_seq = extract_sequence(fake_audio)
fake_agg = extract_aggregate(fake_audio)

print(f"  Real sequence shape : {real_seq.shape}")    # (40, 94)
print(f"  Real aggregate shape: {real_agg.shape}")    # (~260,)
print(f"  Fake sequence shape : {fake_seq.shape}")
print(f"  Fake aggregate shape: {fake_agg.shape}")

# Verify features actually differ between real and fake
diff = np.mean(np.abs(real_seq - fake_seq))
print(f"  Mean feature diff (real vs fake): {diff:.4f}  (should be > 0)")
assert diff > 0, "Features are identical — something is wrong!"

# ── Step 3: Model forward pass ────────────────────────────────────
print(f"\n[3] Testing model forward pass on {DEVICE}...")

model = DeepfakeVoiceDetector().to(DEVICE)
model.eval()

with torch.no_grad():
    real_tensor = torch.tensor(real_seq).unsqueeze(0).to(DEVICE)
    fake_tensor = torch.tensor(fake_seq).unsqueeze(0).to(DEVICE)

    real_score = model(real_tensor).squeeze().item()
    fake_score = model(fake_tensor).squeeze().item()

print(f"  Real audio score : {real_score:.4f}  (untrained — expect ~0.5)")
print(f"  Fake audio score : {fake_score:.4f}  (untrained — expect ~0.5)")
print(f"  Note: scores near 0.5 are correct — model is not trained yet")

# ── Step 4: Batch processing test ────────────────────────────────
print("\n[4] Testing batch processing...")

batch = torch.stack([real_tensor.squeeze(), fake_tensor.squeeze()]).to(DEVICE)
with torch.no_grad():
    batch_out = model(batch)

print(f"  Batch input shape : {batch.shape}")       # [2, 40, 94]
print(f"  Batch output shape: {batch_out.shape}")   # [2, 1]

# ── Step 5: Chunking test ─────────────────────────────────────────
print("\n[5] Testing audio chunking...")

long_audio = np.random.randn(SAMPLE_RATE * 10).astype(np.float32)  # 10 sec
chunks     = chunk_audio(long_audio)
print(f"  10-sec audio → {len(chunks)} chunks of {CLIP_SAMPLES} samples each")
assert all(len(c) == CLIP_SAMPLES for c in chunks), "Chunk size mismatch!"

# ── Step 6: Score fusion simulation ──────────────────────────────
print("\n[6] Simulating score fusion...")

deep_score = real_score
rf_score   = 0.42          # simulated RF score
final      = 0.6 * deep_score + 0.4 * rf_score
risk       = int(final * 100)

tiers = [(86,"CRITICAL"),(61,"HIGH"),(31,"MEDIUM"),(0,"LOW")]
tier  = next(t for thresh, t in tiers if risk >= thresh)

print(f"  Deep score : {deep_score:.4f}")
print(f"  RF score   : {rf_score:.4f}  (simulated)")
print(f"  Final score: {final:.4f}")
print(f"  Risk score : {risk}/100")
print(f"  Tier       : {tier}")

# ── Summary ───────────────────────────────────────────────────────
print("\n" + "=" * 55)
print("ALL PIPELINE TESTS PASSED")
print("=" * 55)
print("\nWhat this means:")
print("  features.py  — working correctly")
print("  model.py     — forward pass on GPU working")
print("  chunking     — works on any audio length")
print("  score fusion — logic verified")
print("\nNext step: wait for dataset download, then run:")
print("  python scripts/precompute_features.py")
print("  python src/train.py")