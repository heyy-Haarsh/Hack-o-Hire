# scripts/realtime_test.py
# Live microphone test with visual feedback
# Speak into mic — watch scores update every 3 seconds

import sys
import time
import numpy as np
import threading
import queue
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from evaluate import load_models, predict
from features import load_audio, chunk_audio, extract_sequence, extract_aggregate
from config import SAMPLE_RATE, CLIP_SAMPLES, DEVICE
import torch

# ── Color codes for terminal ───────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

TIER_COLORS = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   BLUE,
    "LOW":      GREEN,
}

def score_chunk(chunk, deep_model, rf_model):
    """Score using the same pipeline as evaluate.py predict()"""
    import librosa
    import tempfile, os, soundfile as sf
    from evaluate import predict

    # Save chunk to temp file and run through full predict pipeline
    # This ensures identical processing to the API
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        sf.write(tmp.name, chunk, SAMPLE_RATE)
        tmp_path = tmp.name

    try:
        result = predict(tmp_path, deep_model, rf_model, use_llm=False)
        return {
            "verdict": result["verdict"],
            "risk":    result["risk_score"],
            "tier":    result["tier"],
            "action":  result["action"],
            "deep":    result["deep_score"],
            "rf":      result["rf_score"],
            "final":   result["final_score"],
            "energy":  float(np.mean(chunk**2)),
        }
    except Exception as e:
        print(f"  Scoring error: {e}")
        return None
    finally:
        os.unlink(tmp_path)

        
def print_result(result, window_num):
    """Print color-coded result."""
    if result is None:
        print(f"  Window {window_num}: [SILENCE — skipped]")
        return

    color   = TIER_COLORS.get(result["tier"], RESET)
    verdict = result["verdict"]
    risk    = result["risk"]
    tier    = result["tier"]

    bar_len = risk // 5
    bar     = "█" * bar_len + "░" * (20 - bar_len)

    print(f"\n  Window {window_num}")
    print(f"  {color}{BOLD}[{verdict}]{RESET} "
          f"Score: {color}{risk}/100{RESET} "
          f"Tier: {color}{tier}{RESET}")
    print(f"  [{bar}] {risk}%")
    print(f"  Deep={result['deep']}  RF={result['rf']}  "
          f"Energy={result['energy']}")
    print(f"  Action: {color}{result['action']}{RESET}")


def run_microphone_test(duration_seconds=30):
    """Run live microphone test for specified duration."""
    try:
        import sounddevice as sd
    except ImportError:
        print("Installing sounddevice...")
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install",
                        "sounddevice"], check=True)
        import sounddevice as sd

    print("=" * 55)
    print("FraudShield — Live Microphone Test")
    print("=" * 55)
    print("Loading models...")

    deep, rf = load_models()

    print(f"\nListening for {duration_seconds} seconds...")
    print("Speak into your microphone.")
    print("Every 3 seconds will be scored.\n")
    print("Score guide:")
    print(f"  {GREEN}0-30   LOW      = Real voice{RESET}")
    print(f"  {BLUE}31-60  MEDIUM   = Uncertain{RESET}")
    print(f"  {YELLOW}61-85  HIGH     = Likely fake{RESET}")
    print(f"  {RED}86-100 CRITICAL = Definitely fake{RESET}")
    print("\nListening...\n")

    audio_buffer = []
    audio_queue  = queue.Queue()
    window_count = [0]

    def audio_callback(indata, frames, time_info, status):
        audio_queue.put(indata[:, 0].copy())

    def process_audio():
        buffer = np.array([], dtype=np.float32)
        while True:
            try:
                chunk = audio_queue.get(timeout=1.0)
                buffer = np.concatenate([buffer, chunk])

                if len(buffer) >= CLIP_SAMPLES:
                    audio_chunk = buffer[:CLIP_SAMPLES].copy()
                    buffer      = buffer[CLIP_SAMPLES:]
                    window_count[0] += 1

                    result = score_chunk(audio_chunk, deep, rf)
                    print_result(result, window_count[0])

            except queue.Empty:
                continue
            except Exception as e:
                print(f"  Error: {e}")

    # Start processing thread
    proc_thread = threading.Thread(target=process_audio, daemon=True)
    proc_thread.start()

    # Record audio
    with sd.InputStream(
        samplerate=SAMPLE_RATE,
        channels=1,
        dtype="float32",
        blocksize=int(SAMPLE_RATE * 0.5),
        callback=audio_callback
    ):
        time.sleep(duration_seconds)

    print(f"\n\nTest complete — {window_count[0]} windows analyzed")
    print("=" * 55)


def run_file_streaming_test(file_path):
    """
    Simulate real-time analysis on a file.
    Processes 3-second windows with a delay between each
    to simulate live streaming.
    """
    import librosa

    print("=" * 55)
    print("FraudShield — File Streaming Test")
    print(f"File: {file_path}")
    print("=" * 55)
    print("Loading models...")

    deep, rf = load_models()

    print(f"\nSimulating real-time analysis...")
    print("Processing 3-second windows with 0.5s delay\n")

    y, sr = librosa.load(file_path, sr=SAMPLE_RATE, mono=True)
    total_duration = len(y) / sr
    chunks = [
        y[i:i + CLIP_SAMPLES]
        for i in range(0, len(y), CLIP_SAMPLES)
    ]

    print(f"File duration  : {total_duration:.1f}s")
    print(f"Total windows  : {len(chunks)}")
    print(f"Window size    : 3 seconds each\n")

    for i, chunk in enumerate(chunks):
        if len(chunk) < CLIP_SAMPLES:
            chunk = np.pad(chunk, (0, CLIP_SAMPLES - len(chunk)))

        t_start = i * 3
        t_end   = min(t_start + 3, total_duration)
        print(f"--- Window {i+1} [{t_start:.0f}s → {t_end:.0f}s] ---")

        result = score_chunk(chunk, deep, rf)
        print_result(result, i + 1)

        time.sleep(0.5)   # simulate real-time delay

    print("\n\nStreaming test complete.")
    print("=" * 55)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # File mode
        run_file_streaming_test(sys.argv[1])
    else:
        # Live microphone mode — 30 seconds
        run_microphone_test(duration_seconds=30)