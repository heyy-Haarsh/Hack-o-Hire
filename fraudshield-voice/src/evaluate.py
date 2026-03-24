# src/evaluate.py
import torch
import numpy as np
import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import DEVICE, MODELS_DIR
from features import load_audio, chunk_audio, extract_sequence, extract_aggregate
from model import DeepfakeVoiceDetector
from explainer import get_shap_top5, load_rf

# ── Calibrator ─────────────────────────────────────────────────────
from calibration import ScoreCalibrator
_calibrator = ScoreCalibrator()
_calibrator.load()

# ── Constants ──────────────────────────────────────────────────────
THRESHOLD  = 0.50
MIN_ENERGY = 0.015   # skip silent/low-energy noise chunks

# ── Risk tier mapping ──────────────────────────────────────────────
TIERS = [
    (86, "CRITICAL", "BLOCK — trigger incident response immediately"),
    (61, "HIGH",     "BLOCK — escalate to security team now"),
    (31, "MEDIUM",   "FLAG  — route to human reviewer within 1 hour"),
    (0,  "LOW",      "ALLOW — log and continue monitoring"),
]


def get_tier(score: int):
    for threshold, tier, action in TIERS:
        if score >= threshold:
            return tier, action
    return "LOW", "ALLOW — log and continue monitoring"


def load_models():
    print("Loading models...")
    deep = DeepfakeVoiceDetector().to(DEVICE)
    deep.load_state_dict(
        torch.load(MODELS_DIR / "best_eer.pt", map_location=DEVICE)
    )
    deep.eval()
    rf = load_rf()
    print("  Models loaded and ready.")
    return deep, rf


def predict(audio_path: str, deep_model, rf_model,
            use_llm: bool = True) -> dict:
    t0 = time.time()

    # 1 — Load and chunk audio
    y      = load_audio(audio_path)
    chunks = chunk_audio(y)

    # 2 — Score only speech chunks (skip silence)
    deep_scores, rf_scores, speech_chunks = [], [], []

    # Use relative threshold — top 50% energy chunks only
    energies = [float(np.mean(c**2)) for c in chunks]
    max_energy = max(energies)
    # Threshold = 20% of max energy in this file
    energy_threshold = max(0.001, max_energy * 0.20)

    with torch.no_grad():
        for chunk, energy in zip(chunks, energies):
            if energy < energy_threshold:
                continue

            speech_chunks.append(chunk)

            seq = torch.tensor(
                extract_sequence(chunk)
            ).unsqueeze(0).to(DEVICE)
            deep_scores.append(deep_model(seq).squeeze().item())

            agg = extract_aggregate(chunk)
            rf_scores.append(rf_model.predict_proba([agg])[0][1])

    # Fallback if all chunks filtered
    if not deep_scores:
        deep_scores   = [0.0]
        rf_scores     = [0.0]
    speech_chunks = chunks[:1]

    # 3 — Fuse scores (deep model weighted higher for real-world audio)
    deep_score = float(np.mean(deep_scores))
    rf_score   = float(np.mean(rf_scores))
    raw_final  = 0.85 * deep_score + 0.15 * rf_score

    # 4 — Apply calibration
    if _calibrator.is_fitted:
        final      = _calibrator.calibrate(raw_final)
        calibrated = True
    else:
        final      = raw_final
        calibrated = False

    risk = int(final * 100)
    tier, action = get_tier(risk)

    # 5 — SHAP from highest energy speech chunk
    best_chunk = max(speech_chunks, key=lambda c: float(np.mean(c ** 2)))
    last_agg   = extract_aggregate(best_chunk)
    top5       = get_shap_top5(rf_model, last_agg)
    indicators = [
        f"{desc}  (impact: {val:+.3f})"
        for desc, val in top5
    ]

    # 6 — LLM explanation
    explanation = ""
    if use_llm:
        try:
            import ollama
            prompt = f"""You are a voice fraud analyst at Barclays bank.
An audio clip was analyzed by our deepfake detection system.

Risk score : {risk}/100
Tier       : {tier}
Top signals: {'; '.join([d for d, v in top5[:3]])}

Write exactly 2 sentences for a non-technical bank security reviewer.
Be specific about what the audio signals mean. No jargon."""
            response = ollama.chat(
                model="llama3",
                messages=[{"role": "user", "content": prompt}]
            )
            explanation = response["message"]["content"].strip()
        except Exception as e:
            explanation = f"LLM unavailable ({e}) — see top_indicators."

    processing_ms = round((time.time() - t0) * 1000)

    return {
        "verdict":            "FAKE" if final >= THRESHOLD else "REAL",
        "risk_score":          risk,
        "tier":                tier,
        "action":              action,
        "deep_score":          round(deep_score, 4),
        "rf_score":            round(rf_score,   4),
        "raw_score":           round(raw_final,  4),
        "final_score":         round(final,      4),
        "calibrated":          calibrated,
        "top_indicators":      indicators,
        "explanation":         explanation,
        "chunks_analyzed":     len(chunks),
        "speech_chunks_used":  len(speech_chunks),
        "processing_ms":       processing_ms,
        "audio_file":          str(audio_path),
    }


if __name__ == "__main__":
    import json
    if len(sys.argv) < 2:
        print("Usage: python src/evaluate.py <audio_file.wav>")
        sys.exit(1)

    deep, rf = load_models()
    result   = predict(sys.argv[1], deep, rf, use_llm=False)
    print(json.dumps(result, indent=2))