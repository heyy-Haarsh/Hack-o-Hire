# scripts/generate_demo_audio.py
# Generates real-sounding fake voice samples for the hackathon demo.
# Run this once — produces demo_real.wav and demo_fake.wav

import numpy as np
import soundfile as sf
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from config import SAMPLE_RATE, OUTPUTS_DIR

OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Option A: Bark TTS (best quality, needs ~5GB GPU RAM) ─────────
def generate_with_bark():
    print("Generating fake voice with Bark TTS...")
    print("(First run downloads ~5GB model weights — be patient)")
    from bark import generate_audio, SAMPLE_RATE as BARK_SR
    from bark.preload_models import preload_models
    import librosa

    preload_models()

    scripts = [
        "Hello, this is your Barclays bank calling. We have detected suspicious activity on your account.",
        "Please verify your identity by confirming your card number and PIN immediately.",
        "Your account will be suspended in 24 hours unless you call us back urgently.",
    ]

    for i, text in enumerate(scripts):
        print(f"  Generating clip {i+1}/{len(scripts)}...")
        audio = generate_audio(text)

        # Resample to 16kHz if needed
        if BARK_SR != SAMPLE_RATE:
            audio = librosa.resample(audio, orig_sr=BARK_SR, target_sr=SAMPLE_RATE)

        out_path = OUTPUTS_DIR / f"demo_fake_{i+1}.wav"
        sf.write(str(out_path), audio, SAMPLE_RATE)
        print(f"  Saved → {out_path}")

    print("Fake audio generation complete!")


# ── Option B: gTTS (lightweight fallback, no GPU needed) ──────────
def generate_with_gtts():
    print("Generating fake voice with gTTS (lightweight)...")
    try:
        from gtts import gTTS
        import librosa

        scripts = [
            "Hello, this is your Barclays bank calling about suspicious activity.",
            "Please verify your identity immediately to avoid account suspension.",
            "Your transaction of five thousand pounds has been flagged for review.",
        ]

        for i, text in enumerate(scripts):
            tmp = OUTPUTS_DIR / f"_tmp_{i}.mp3"
            gTTS(text=text, lang="en", tld="co.uk").save(str(tmp))

            # Convert to 16kHz wav
            y, sr = librosa.load(str(tmp), sr=SAMPLE_RATE)
            out   = OUTPUTS_DIR / f"demo_fake_{i+1}.wav"
            import soundfile as sf
            sf.write(str(out), y, SAMPLE_RATE)
            tmp.unlink()
            print(f"  Saved → {out}")

        print("gTTS generation complete!")

    except ImportError:
        print("gTTS not installed. Run: pip install gtts")


# ── Real voice placeholder ─────────────────────────────────────────
def generate_real_placeholder():
    """
    Creates a synthetic 'real-like' audio as placeholder.
    Replace demo_real.wav with an actual recording of your own voice
    for the best demo impact.
    """
    print("\nCreating real audio placeholder...")
    print("TIP: Replace this with an actual recording of your voice")
    print("     for maximum demo impact!")

    duration = 3
    t        = np.linspace(0, duration, SAMPLE_RATE * duration)
    # Simulate natural speech-like signal with multiple harmonics + noise
    audio = (
        0.3 * np.sin(2 * np.pi * 150 * t) * np.exp(-0.5 * t) +
        0.2 * np.sin(2 * np.pi * 300 * t) * np.exp(-0.3 * t) +
        0.1 * np.random.randn(len(t))
    ).astype(np.float32)

    out = OUTPUTS_DIR / "demo_real_placeholder.wav"
    sf.write(str(out), audio, SAMPLE_RATE)
    print(f"  Saved → {out}")
    print("  Record your actual voice and save as: outputs/demo_real.wav")


if __name__ == "__main__":
    print("=" * 55)
    print("FraudShield — Demo Audio Generator")
    print("=" * 55)

    # Try Bark first, fall back to gTTS
    try:
        import bark
        generate_with_bark()
    except ImportError:
        print("Bark not installed, using gTTS fallback...")
        try:
            import gtts
        except ImportError:
            import subprocess
            subprocess.run(["pip", "install", "gtts"], check=True)
        generate_with_gtts()

    generate_real_placeholder()

    print("\n" + "=" * 55)
    print("Demo audio ready in outputs/ folder")
    print("These files are what you'll play live for judges")
    print("=" * 55)