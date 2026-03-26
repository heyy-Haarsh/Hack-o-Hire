# src/voice/evaluate.py
"""
Voice deepfake evaluation pipeline — dual-model ensemble.

Two independent classifiers must BOTH agree the audio is fake before issuing
a FAKE verdict (AND-logic).  This drastically reduces false positives because
each model has different blind spots:

  Model A  — MFCC CNN+BiLSTM (best_eer.pt, trained on ASVspoof2019-LA)
             Strong at detecting known TTS/vocoder artifacts in spectral domain.
             Weakness: false positives on phone / low-bandwidth recordings.

  Model B  — wav2vec2-base MLP classifier (w2v_classifier.pkl)
             Uses multi-layer (phonetic + semantic) self-supervised speech
             features pre-trained on 960 h of diverse speech, trained with
             phone-augmented real data from 40+ speakers.
             Weakness: some phone recordings with heavy codec processing.

Final score = A × B  (product enforces AND — if either model says REAL the
score drops to near zero).
"""
import os
import numpy as np
import time
import sys
import pickle
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import DEVICE, MODELS_DIR, SAMPLE_RATE
from features import load_audio, chunk_audio, extract_sequence, extract_aggregate
from model import DeepfakeVoiceDetector

# ── Configuration ──────────────────────────────────────────────────
THRESHOLD = 0.55   # Binary decision boundary — slightly above 0.5 to reduce false positives

# Set to True AFTER v2 MFCC model is retrained with diverse real speakers
_V2_READY = False

# ── Risk tiers ────────────────────────────────────────────────────
TIERS = [
    (88, "CRITICAL 🚨", "BLOCK — trigger incident response immediately"),
    (70, "HIGH 🔴",     "BLOCK — escalate to security team now"),
    (50, "MEDIUM 🟡",   "FLAG  — route to human reviewer within 1 hour"),
    (0,  "LOW 🟢",      "ALLOW — voice appears authentic"),
]

# ── Cached models ─────────────────────────────────────────────────
_model_v1         = None
_model_v2         = None
_model_loaded     = False
_load_attempted   = False
_model            = None   # back-compat alias

_w2v_model        = None   # Wav2Vec2Model
_w2v_extractor    = None   # Wav2Vec2FeatureExtractor
_w2v_clf          = None   # sklearn MLPClassifier
_w2v_scaler       = None   # sklearn StandardScaler
_w2v_layers       = [6, 7, 8, 12]  # default multi-layer indices
_w2v_loaded       = False
_w2v_load_attempted = False

SR = SAMPLE_RATE
CLIP_SAMPLES = SR * 3     # 3-second clip for wav2vec2


def get_tier(score: int):
    for threshold, tier, action in TIERS:
        if score >= threshold:
            return tier, action
    return "LOW 🟢", "ALLOW — voice appears authentic"


def _load_single(path, label: str):
    """Load one DeepfakeVoiceDetector checkpoint. Returns model or None."""
    import torch
    if not path.exists():
        return None
    try:
        m = DeepfakeVoiceDetector().to(DEVICE)
        state = torch.load(str(path), map_location=DEVICE, weights_only=False)
        if isinstance(state, dict):
            if "model_state_dict" in state:
                state = state["model_state_dict"]
            elif "state_dict" in state:
                state = state["state_dict"]
            elif "model" in state:
                state = state["model"]
        m.load_state_dict(state, strict=True)
        m.eval()
        print(f"  ✅ {label} loaded → {path.name}")
        return m
    except Exception as e:
        print(f"  ❌ {label} load error: {e}")
        return None


def _load_model():
    """Load MFCC model(s) once and cache globally."""
    global _model_v1, _model_v2, _model, _model_loaded, _load_attempted
    if _load_attempted:
        return _model_loaded

    _load_attempted = True
    _model_v1 = _load_single(MODELS_DIR / "best_eer.pt", "Model v1 (best_eer)")

    if _V2_READY:
        _model_v2 = _load_single(MODELS_DIR / "best_eer_v2.pt", "Model v2 (best_eer_v2)")
        if _model_v1 and _model_v2:
            print("  🔀 MFCC ensemble: v1 (no CMN) + v2 (CMN)")
    else:
        _model_v2 = None

    _model_loaded = _model_v1 is not None
    _model = _model_v1
    return _model_loaded


def _load_w2v():
    """Load wav2vec2 model + sklearn classifier once and cache globally."""
    global _w2v_model, _w2v_extractor, _w2v_clf, _w2v_scaler, _w2v_layers
    global _w2v_loaded, _w2v_load_attempted

    if _w2v_load_attempted:
        return _w2v_loaded
    _w2v_load_attempted = True

    pkl_path = MODELS_DIR / "w2v_classifier.pkl"
    if not pkl_path.exists():
        print("  ⚠️  wav2vec2 classifier not found — skipping Model B")
        return False

    try:
        import torch
        from transformers import Wav2Vec2Model, Wav2Vec2FeatureExtractor

        with open(pkl_path, "rb") as f:
            bundle = pickle.load(f)
        _w2v_scaler = bundle["scaler"]
        _w2v_clf    = bundle["clf"]
        _w2v_layers = bundle.get("layers", [6, 7, 8, 12])

        _w2v_extractor = Wav2Vec2FeatureExtractor.from_pretrained(
            "facebook/wav2vec2-base"
        )
        _w2v_model = Wav2Vec2Model.from_pretrained(
            "facebook/wav2vec2-base"
        ).to(DEVICE).eval()

        _w2v_loaded = True
        print(f"  ✅ wav2vec2 classifier loaded → {pkl_path.name}  (layers={_w2v_layers})")
        return True
    except Exception as e:
        print(f"  ⚠️  wav2vec2 load error (non-fatal): {e}")
        return False


def _w2v_predict(y: np.ndarray) -> float:
    """
    Run wav2vec2 multi-layer classifier on raw audio waveform.

    Extracts up to 5 clips spread across the audio, computes multi-layer
    features (mean+std from phonetic and semantic layers), predicts P(fake)
    for each clip, and returns the MINIMUM probability (conservative: any
    clip scoring REAL pulls the whole audio toward REAL).
    """
    import torch
    import librosa as _librosa

    y_norm = _librosa.util.normalize(y)
    total  = len(y_norm)

    # Determine clip offsets — up to 5 clips evenly spaced
    n_clips = min(5, max(1, total // CLIP_SAMPLES))
    if n_clips == 1:
        offsets = [max(0, total // 2 - CLIP_SAMPLES // 2)]
    else:
        step = (total - CLIP_SAMPLES) / (n_clips - 1)
        offsets = [int(i * step) for i in range(n_clips)]

    probs = []
    with torch.no_grad():
        for off in offsets:
            clip = y_norm[off : off + CLIP_SAMPLES]
            if len(clip) < CLIP_SAMPLES:
                clip = np.pad(clip, (0, CLIP_SAMPLES - len(clip)))

            inp = _w2v_extractor(
                clip, sampling_rate=SR, return_tensors="pt", padding=True
            )
            out = _w2v_model(
                inp.input_values.to(DEVICE), output_hidden_states=True
            )

            # Multi-layer feature extraction (mean+std per layer)
            feats = []
            for li in _w2v_layers:
                h = out.hidden_states[li].squeeze(0)          # [T, 768]
                feats.append(h.mean(dim=0).cpu().numpy())      # mean
                feats.append(h.std(dim=0).cpu().numpy())       # std
            emb = np.concatenate(feats).reshape(1, -1)

            emb_s = _w2v_scaler.transform(emb)
            prob  = float(_w2v_clf.predict_proba(emb_s)[0, 1])
            probs.append(prob)

    # Use minimum — conservative: if any clip looks real, lean toward real
    return float(min(probs))


def _get_spectral_indicators(y: np.ndarray) -> list:
    """Generate rule-based secondary indicators from raw audio."""
    try:
        import librosa
        indicators = []

        spec_centroid = float(librosa.feature.spectral_centroid(y=y, sr=SAMPLE_RATE).mean())
        zcr           = float(librosa.feature.zero_crossing_rate(y).mean())
        mfcc_data     = librosa.feature.mfcc(y=y, sr=SAMPLE_RATE, n_mfcc=13)
        mfcc_var      = float(mfcc_data.std())

        if spec_centroid > 4500:
            indicators.append(f"High spectral centroid ({spec_centroid:.0f} Hz) — synthetic voice fingerprint")
        if zcr < 0.02:
            indicators.append(f"Low zero-crossing rate ({zcr:.4f}) — atypical for natural speech dynamics")
        if mfcc_var < 6.0:
            indicators.append(f"Low MFCC variance ({mfcc_var:.2f}) — unnaturally uniform voice texture")

        return indicators
    except Exception:
        return []


def analyze_audio_file(audio_path: str) -> dict:
    """
    Full voice deepfake analysis pipeline.

    Args:
        audio_path: absolute path to audio file saved by attachment extractor

    Returns dict with:
        verdict        : "FAKE 🤖" | "REAL ✅" | "UNKNOWN"
        risk_score     : int 0-100
        tier           : "CRITICAL 🚨" | "HIGH 🔴" | "MEDIUM 🟡" | "LOW 🟢"
        action         : recommended action string
        deep_score     : float (raw model output 0-1)
        confidence_pct : str  (e.g. "83.4%")
        indicators     : list of str  (secondary signals)
        chunks_analyzed: int
        processing_ms  : int
        error          : str | None
    """
    t0 = time.time()

    result = {
        "verdict":         "UNKNOWN",
        "risk_score":      0,
        "tier":            "LOW 🟢",
        "action":          "Analysis pending",
        "deep_score":      0.0,
        "confidence_pct":  "0.0%",
        "vote_fraction":   0.0,
        "indicators":      [],
        "chunks_analyzed": 0,
        "speech_chunks":   0,
        "processing_ms":   0,
        "error":           None,
        "model_used":      "best_eer.pt (MFCC CNN+BiLSTM)",
    }

    if not os.path.exists(audio_path):
        result["error"] = f"File not found: {audio_path}"
        return result

    try:
        # ── Load & chunk ────────────────────────────────────────────
        print(f"\n  🎙️  Analyzing voice: {os.path.basename(audio_path)}")
        y      = load_audio(audio_path)
        chunks = chunk_audio(y)
        result["chunks_analyzed"] = len(chunks)

        # ── Spectral indicators ─────────────────────────────────────
        result["indicators"] = _get_spectral_indicators(y)

        # ── Model A: MFCC CNN+BiLSTM ───────────────────────────────
        model_ok = _load_model()
        score_a  = None                       # P(fake) from Model A

        if model_ok:
            import torch

            energies         = [float(np.mean(c**2)) for c in chunks]
            max_energy       = max(energies) if energies else 1.0
            energy_threshold = max(0.001, max_energy * 0.20)

            speech_count = 0
            scores_v1, scores_v2 = [], []

            with torch.no_grad():
                for chunk, energy in zip(chunks, energies):
                    if energy < energy_threshold:
                        continue
                    speech_count += 1

                    if _model_v1 is not None:
                        seq = torch.tensor(extract_sequence(chunk, cmn=False)).unsqueeze(0).to(DEVICE)
                        scores_v1.append(_model_v1(seq).squeeze().item())

                    if _model_v2 is not None:
                        seq = torch.tensor(extract_sequence(chunk, cmn=True)).unsqueeze(0).to(DEVICE)
                        scores_v2.append(_model_v2(seq).squeeze().item())

            if scores_v1 and scores_v2:
                a_scores = [max(a, b) for a, b in zip(scores_v1, scores_v2)]
            elif scores_v1:
                a_scores = scores_v1
            else:
                a_scores = scores_v2 or [0.0]

            result["speech_chunks"] = speech_count
            score_a = float(np.median(a_scores)) if a_scores else 0.0
            vote_a  = (sum(s > 0.50 for s in a_scores) / len(a_scores)) if a_scores else 0.0

        # ── Model B: wav2vec2 classifier ────────────────────────────
        w2v_ok  = _load_w2v()
        score_b = None                        # P(fake) from Model B

        if w2v_ok:
            score_b = _w2v_predict(y)

        # ── Combine: AND-logic ensemble ─────────────────────────────
        if score_a is not None and score_b is not None:
            # Product enforces AND: both must be high for FAKE
            deep_score = score_a * score_b
            vote_fraction = vote_a * (1.0 if score_b > 0.50 else 0.0)
            model_tag = "Ensemble (MFCC × wav2vec2)"
            print(f"    Model A (MFCC): {score_a:.3f}  |  Model B (w2v): {score_b:.3f}")
        elif score_a is not None:
            deep_score    = score_a
            vote_fraction = vote_a
            model_tag     = "MFCC CNN+BiLSTM only"
        elif score_b is not None:
            deep_score    = score_b
            vote_fraction = 1.0 if score_b > 0.50 else 0.0
            model_tag     = "wav2vec2 classifier only"
        else:
            deep_score    = 0.0
            vote_fraction = 0.0
            model_tag     = "Spectral rule-based (model fallback)"

        deep_score = round(float(deep_score), 4)

        result["deep_score"]      = deep_score
        result["confidence_pct"]  = f"{deep_score*100:.1f}%"
        result["risk_score"]      = int(deep_score * 100)
        result["vote_fraction"]   = round(vote_fraction, 3)
        result["verdict"]         = "FAKE 🤖" if deep_score >= THRESHOLD else "REAL ✅"
        result["tier"], result["action"] = get_tier(result["risk_score"])
        result["model_used"]      = model_tag

        print(f"  🎯 Verdict: {result['verdict']}  Score: {deep_score:.3f}"
              f"  Tier: {result['tier']}")

    except ImportError as e:
        result["error"] = f"Missing package: {e}. Run: pip install librosa pydub torch transformers"
    except Exception as e:
        result["error"] = f"Voice analysis failed: {str(e)}"
        print(f"  ❌ Error: {e}")

    result["processing_ms"] = round((time.time() - t0) * 1000)
    return result


class VoiceDeepfakeDetector:
    """Wrapper class for the voice deepfake analysis pipeline."""
    def predict(self, audio_path: str) -> dict:
        return analyze_audio_file(audio_path)
