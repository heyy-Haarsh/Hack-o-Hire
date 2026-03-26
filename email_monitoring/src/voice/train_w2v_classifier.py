"""
Train a wav2vec2-based binary classifier for voice deepfake detection.

Uses facebook/wav2vec2-base (pre-trained on 960h LibriSpeech) as a fixed
feature extractor.  Extracts mean+std pooled embeddings (1536-dim) and trains
a Logistic Regression.  Real samples are augmented with phone-quality,
noise, and bandwidth variations so the classifier learns "recording quality
does NOT mean fake".

Usage:
    python train_w2v_classifier.py [--n_real 600] [--n_fake 600]
"""
import os, sys, random, argparse, warnings, time, pickle
from pathlib import Path

import numpy as np
import torch
import librosa
from scipy import signal as scipy_signal

warnings.filterwarnings("ignore")

# ── paths ────────────────────────────────────────────────────────
ROOT       = Path(__file__).resolve().parent.parent.parent          # email_monitoring/
VOICE_ROOT = ROOT / "src" / "voice"
MODELS_DIR = ROOT / "models"
FS_ROOT    = ROOT.parent / "fraudshield-voice"
REAL_DIR   = FS_ROOT / "data" / "raw" / "bonafide"
FAKE_DIR   = FS_ROOT / "data" / "raw" / "spoof"
TEST_DIR   = ROOT / "extracted_attachments"

W2V_MODEL_PATH = MODELS_DIR / "w2v_classifier.pkl"

SR = 16000
CLIP_SEC = 3
CLIP_SAMPLES = SR * CLIP_SEC


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--n_real", type=int, default=600, help="base real samples")
    p.add_argument("--n_fake", type=int, default=600, help="fake samples")
    p.add_argument("--seed",   type=int, default=42)
    return p.parse_args()


def load_clip(path: str) -> np.ndarray:
    """Load audio, take middle clip, normalise."""
    y, _ = librosa.load(path, sr=SR, mono=True)
    if len(y) < SR:
        return None
    y = librosa.util.normalize(y)
    mid = len(y) // 2
    start = max(0, mid - CLIP_SAMPLES // 2)
    end   = start + CLIP_SAMPLES
    if end > len(y):
        end = len(y)
        start = max(0, end - CLIP_SAMPLES)
    clip = y[start:end]
    if len(clip) < CLIP_SAMPLES:
        clip = np.pad(clip, (0, CLIP_SAMPLES - len(clip)))
    return clip


# ── Augmentations for real samples ────────────────────────────────
def augment_phone(clip):
    """Simulate phone: low-pass at 3400Hz + resample through 8kHz."""
    # Low-pass Butterworth at 3400 Hz
    sos = scipy_signal.butter(5, 3400, btype='low', fs=SR, output='sos')
    y = scipy_signal.sosfilt(sos, clip)
    # Resample 16k→8k→16k to simulate narrowband codec
    y_8k = librosa.resample(y, orig_sr=SR, target_sr=8000)
    y_back = librosa.resample(y_8k, orig_sr=8000, target_sr=SR)
    if len(y_back) < len(clip):
        y_back = np.pad(y_back, (0, len(clip) - len(y_back)))
    return librosa.util.normalize(y_back[:len(clip)])

def augment_noise(clip, snr_db=15):
    """Add Gaussian noise at given SNR."""
    sig_power = np.mean(clip**2)
    noise_power = sig_power / (10 ** (snr_db / 10))
    noise = np.random.randn(len(clip)) * np.sqrt(noise_power)
    return librosa.util.normalize(clip + noise)

def augment_lowvol(clip, gain_db=-12):
    """Reduce volume to simulate quiet recordings."""
    gain = 10 ** (gain_db / 20)
    return clip * gain

def augment_bandpass(clip, low=300, high=3400):
    """Band-pass filter simulating phone bandwidth."""
    sos = scipy_signal.butter(4, [low, high], btype='band', fs=SR, output='sos')
    y = scipy_signal.sosfilt(sos, clip)
    return librosa.util.normalize(y)

def augment_silence_pad(clip, pad_ratio=0.5):
    """Pad with silence to simulate low-speech recordings like harvard.wav."""
    n_pad = int(len(clip) * pad_ratio)
    # insert silence in the middle
    mid = len(clip) // 2
    y = np.concatenate([clip[:mid], np.zeros(n_pad), clip[mid:]])
    # take center clip
    center = len(y) // 2
    start = max(0, center - CLIP_SAMPLES // 2)
    y = y[start:start + CLIP_SAMPLES]
    if len(y) < CLIP_SAMPLES:
        y = np.pad(y, (0, CLIP_SAMPLES - len(y)))
    return y


AUGMENTATIONS = [
    ("phone",    augment_phone),
    ("noise15",  lambda c: augment_noise(c, snr_db=15)),
    ("noise8",   lambda c: augment_noise(c, snr_db=8)),
    ("lowvol",   augment_lowvol),
    ("bandpass", augment_bandpass),
    ("silence",  augment_silence_pad),
]


@torch.no_grad()
def extract_w2v_embedding(model, extractor, clip: np.ndarray, device) -> np.ndarray:
    """Return 1536-dim mean+std pooled wav2vec2 embedding."""
    inputs = extractor(clip, sampling_rate=SR, return_tensors="pt", padding=True)
    outputs = model(inputs.input_values.to(device))
    h = outputs.last_hidden_state.squeeze(0)       # [T, 768]
    mean = h.mean(dim=0).cpu().numpy()              # [768]
    std  = h.std(dim=0).cpu().numpy()               # [768]
    return np.concatenate([mean, std])               # [1536]


def main():
    args = parse_args()
    random.seed(args.seed)
    np.random.seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[config] device={device}  n_real={args.n_real}  n_fake={args.n_fake}")

    # ── 1. Sample file lists ───────────────────────────────────────
    real_files = sorted(REAL_DIR.glob("*.wav"))
    fake_files = sorted(FAKE_DIR.glob("*.wav"))
    print(f"  Available: {len(real_files)} real, {len(fake_files)} fake")

    real_sample = random.sample(real_files, min(args.n_real, len(real_files)))
    fake_sample = random.sample(fake_files, min(args.n_fake, len(fake_files)))
    n_aug = len(AUGMENTATIONS)
    total_real_expected = len(real_sample) * (1 + n_aug)
    print(f"  Sampled:   {len(real_sample)} real (×{1+n_aug} with aug = ~{total_real_expected})")
    print(f"             {len(fake_sample)} fake")

    # ── 2. Load wav2vec2 ──────────────────────────────────────────
    print("Loading wav2vec2-base …")
    from transformers import Wav2Vec2Model, Wav2Vec2FeatureExtractor
    extractor = Wav2Vec2FeatureExtractor.from_pretrained("facebook/wav2vec2-base")
    w2v = Wav2Vec2Model.from_pretrained("facebook/wav2vec2-base").to(device).eval()
    print("  wav2vec2 ready ✅")

    # ── 3. Extract embeddings ─────────────────────────────────────
    X, Y = [], []
    t0 = time.time()

    # Real: original + augmented versions
    ok_real = 0
    for i, fp in enumerate(real_sample):
        clip = load_clip(str(fp))
        if clip is None:
            continue

        # Original
        emb = extract_w2v_embedding(w2v, extractor, clip, device)
        X.append(emb); Y.append(0); ok_real += 1

        # Augmented versions (all labeled REAL — augmentation != fakeness)
        for aug_name, aug_fn in AUGMENTATIONS:
            try:
                aug_clip = aug_fn(clip.copy())
                emb_aug = extract_w2v_embedding(w2v, extractor, aug_clip, device)
                X.append(emb_aug); Y.append(0); ok_real += 1
            except Exception:
                pass

        if (i + 1) % 100 == 0:
            print(f"    real: {i+1}/{len(real_sample)} files  ({time.time()-t0:.0f}s)")

    print(f"    real: done — {ok_real} embeddings (orig + augmented)")

    # Fake: original only (also apply some augmentations so model sees
    # fake audio in diverse conditions too — prevents learning "clean=fake")
    ok_fake = 0
    for i, fp in enumerate(fake_sample):
        clip = load_clip(str(fp))
        if clip is None:
            continue
        emb = extract_w2v_embedding(w2v, extractor, clip, device)
        X.append(emb); Y.append(1); ok_fake += 1

        # Apply 2 random augmentations to fake too (balanced)
        chosen = random.sample(AUGMENTATIONS, 2)
        for aug_name, aug_fn in chosen:
            try:
                aug_clip = aug_fn(clip.copy())
                emb_aug = extract_w2v_embedding(w2v, extractor, aug_clip, device)
                X.append(emb_aug); Y.append(1); ok_fake += 1
            except Exception:
                pass

        if (i + 1) % 100 == 0:
            print(f"    fake: {i+1}/{len(fake_sample)} files  ({time.time()-t0:.0f}s)")

    print(f"    fake: done — {ok_fake} embeddings (orig + some augmented)")

    X = np.array(X)
    Y = np.array(Y)
    n_real = np.sum(Y == 0)
    n_fake = np.sum(Y == 1)
    print(f"  Total: {X.shape[0]} × {X.shape[1]}  (real={n_real}, fake={n_fake})  ({time.time()-t0:.0f}s)")

    # ── 4. Train classifier ───────────────────────────────────────
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score

    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)

    clf = LogisticRegression(max_iter=2000, C=0.5, solver="lbfgs",
                              class_weight="balanced")
    scores = cross_val_score(clf, Xs, Y, cv=5, scoring="accuracy")
    print(f"\n  5-fold CV accuracy: {scores.mean():.4f} ± {scores.std():.4f}")

    clf.fit(Xs, Y)
    train_acc = clf.score(Xs, Y)
    print(f"  Train accuracy:     {train_acc:.4f}")

    # ── 5. Save classifier ────────────────────────────────────────
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {"scaler": scaler, "clf": clf}
    with open(W2V_MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)
    print(f"\n  Saved → {W2V_MODEL_PATH}")

    # ── 6. Test on known files ────────────────────────────────────
    test_files = [
        ("FAKE", TEST_DIR / "demo_fake.wav"),
        ("FAKE", TEST_DIR / "demo_fake_gtts.mp3"),
        ("REAL", TEST_DIR / "demo_real.wav"),
        ("REAL", TEST_DIR / "demo_real.flac"),
        ("REAL", TEST_DIR / "harvard.wav"),
        ("REAL", TEST_DIR / "call_recording_01.wav"),
        ("REAL", TEST_DIR / "call_recording_02.wav"),
    ]

    print(f"\n{'Label':<6} {'File':<30} {'P(fake)':>8} {'Pred':<6} {'OK?'}")
    print("-" * 60)

    for label, fp in test_files:
        if not fp.exists():
            continue
        clip = load_clip(str(fp))
        if clip is None:
            print(f"{label:<6} {fp.name:<30} SKIPPED (too short)")
            continue
        emb = extract_w2v_embedding(w2v, extractor, clip, device)
        emb_s = scaler.transform(emb.reshape(1, -1))
        prob = clf.predict_proba(emb_s)[0, 1]
        pred = "FAKE" if prob > 0.5 else "REAL"
        ok = "✅" if pred == label else "❌"
        print(f"{label:<6} {fp.name:<30} {prob:>8.4f} {pred:<6} {ok}")

    print("\nDone.")


if __name__ == "__main__":
    main()
