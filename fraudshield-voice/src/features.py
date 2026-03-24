# src/features.py
import librosa
import numpy as np
import audiomentations as A
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import SAMPLE_RATE, CLIP_SAMPLES, N_MFCC, N_FFT, HOP_LENGTH

# ── Augmentation pipeline (training time only) ─────────────────────
AUGMENT = A.Compose([
    A.AddGaussianNoise(min_amplitude=0.001, max_amplitude=0.025, p=0.7),
    A.Mp3Compression(min_bitrate=8, max_bitrate=64, p=0.7),
    A.PitchShift(min_semitones=-3, max_semitones=3, p=0.4),
    A.TimeStretch(min_rate=0.85, max_rate=1.15, p=0.4),
    A.LowPassFilter(min_cutoff_freq=1000, max_cutoff_freq=4000, p=0.5),
    A.Gain(min_gain_db=-6, max_gain_db=6, p=0.5),
])

# src/features.py — replace load_audio() with this

def load_audio(path: str) -> np.ndarray:
    """
    Load ANY audio format → 16kHz mono numpy array.
    Supports: wav, mp3, flac, ogg, m4a, aac, wma, mp4, webm
    Auto-converts unsupported formats via pydub fallback.
    """
    path = str(path)
    ext  = Path(path).suffix.lower()

    # Formats librosa handles natively
    NATIVE = {".wav", ".flac", ".ogg", ".mp3"}

    try:
        if ext in NATIVE:
            y, sr = librosa.load(path, sr=SAMPLE_RATE, mono=True)
        else:
            # Convert via pydub → temp WAV → librosa
            y = _convert_via_pydub(path)
            sr = SAMPLE_RATE

        y = librosa.util.normalize(y)
        y, _ = librosa.effects.trim(y, top_db=20)
        return y

    except Exception:
        # Final fallback — try pydub regardless of extension
        try:
            y = _convert_via_pydub(path)
            y = librosa.util.normalize(y)
            y, _ = librosa.effects.trim(y, top_db=20)
            return y
        except Exception as e:
            raise ValueError(f"Could not load audio file '{path}': {e}")


def _convert_via_pydub(path: str) -> np.ndarray:
    """Convert any format to numpy array via pydub."""
    try:
        from pydub import AudioSegment
        import tempfile, os

        ext = Path(path).suffix.lower().strip(".")
        if not ext:
            ext = "mp3"

        audio = AudioSegment.from_file(path, format=ext)
        audio = audio.set_frame_rate(SAMPLE_RATE).set_channels(1)

        # Export to temp WAV and load
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
            audio.export(tmp.name, format="wav")
            tmp_path = tmp.name

        try:
            y, _ = librosa.load(tmp_path, sr=SAMPLE_RATE, mono=True)
        finally:
            os.unlink(tmp_path)

        return y

    except ImportError:
        raise ImportError(
            "pydub not installed. Run: pip install pydub\n"
            "Also install ffmpeg: https://ffmpeg.org/download.html"
        )

def chunk_audio(y: np.ndarray) -> list:
    """Split audio into fixed CLIP_SAMPLES chunks. Pad last chunk if short."""
    chunks = []
    for i in range(0, max(len(y), CLIP_SAMPLES), CLIP_SAMPLES):
        c = y[i:i + CLIP_SAMPLES]
        if len(c) < CLIP_SAMPLES:
            c = np.pad(c, (0, CLIP_SAMPLES - len(c)))
        chunks.append(c)
    return chunks

def extract_sequence(y: np.ndarray, augment: bool = False) -> np.ndarray:
    """
    Returns MFCC matrix shape [N_MFCC, T] — input to CNN+LSTM.
    T ≈ 94 frames for a 3-second clip at hop_length=512, sr=16000.
    """
    if augment:
        y = AUGMENT(samples=y, sample_rate=SAMPLE_RATE)
    mfcc = librosa.feature.mfcc(
        y=y, sr=SAMPLE_RATE,
        n_mfcc=N_MFCC,
        n_fft=N_FFT,
        hop_length=HOP_LENGTH
    )
    return mfcc.astype(np.float32)

def extract_aggregate(y: np.ndarray, augment: bool = False) -> np.ndarray:
    """
    Returns ~260-dim flat feature vector — input to Random Forest.
    Combines MFCC + deltas + spectral features, each with mean + std.
    """
    if augment:
        y = AUGMENT(samples=y, sample_rate=SAMPLE_RATE)

    mfcc      = librosa.feature.mfcc(y=y, sr=SAMPLE_RATE, n_mfcc=N_MFCC,
                                      n_fft=N_FFT, hop_length=HOP_LENGTH)
    delta1    = librosa.feature.delta(mfcc)
    delta2    = librosa.feature.delta(mfcc, order=2)
    contrast  = librosa.feature.spectral_contrast(y=y, sr=SAMPLE_RATE)
    centroid  = librosa.feature.spectral_centroid(y=y, sr=SAMPLE_RATE)
    rolloff   = librosa.feature.spectral_rolloff(y=y, sr=SAMPLE_RATE)
    zcr       = librosa.feature.zero_crossing_rate(y)

    feats = np.concatenate([
        mfcc.mean(axis=1),    mfcc.std(axis=1),
        delta1.mean(axis=1),  delta1.std(axis=1),
        delta2.mean(axis=1),  delta2.std(axis=1),
        contrast.mean(axis=1),contrast.std(axis=1),
        [centroid.mean(),     centroid.std()],
        [rolloff.mean(),      rolloff.std()],
        [zcr.mean(),          zcr.std()],
    ])
    return feats.astype(np.float32)


# ── Quick test — run this file directly to verify ──────────────────
if __name__ == "__main__":
    import numpy as np
    print("Testing feature extraction on synthetic audio...")
    dummy_audio = np.random.randn(CLIP_SAMPLES).astype(np.float32)
    seq = extract_sequence(dummy_audio)
    agg = extract_aggregate(dummy_audio)
    print(f"  extract_sequence shape : {seq.shape}")   # expect (40, 94)
    print(f"  extract_aggregate shape: {agg.shape}")   # expect (~260,)
    print("  features.py OK!")