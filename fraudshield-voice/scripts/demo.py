# scripts/demo.py
import sys, json
from pathlib import Path

# Clear module cache BEFORE importing — ensures fresh evaluate.py is loaded
for mod in list(sys.modules.keys()):
    if 'evaluate' in mod or 'calibration' in mod:
        del sys.modules[mod]

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from evaluate import load_models, predict


def run_demo(audio_path: str, label: str, deep, rf):
    print(f"\n{'='*55}")
    print(f"Testing: {label}")
    print(f"File   : {audio_path}")
    print(f"{'='*55}")

    result = predict(audio_path, deep, rf, use_llm=False)

    print(f"  Verdict     : {result['verdict']}")
    print(f"  Risk score  : {result['risk_score']}/100")
    print(f"  Tier        : {result['tier']}")
    print(f"  Action      : {result['action']}")
    print(f"  Deep score  : {result['deep_score']}")
    print(f"  RF score    : {result['rf_score']}")
    print(f"  Calibrated  : {result.get('calibrated', False)}")
    print(f"  Speech chunks used: {result.get('speech_chunks_used', '?')}")
    print(f"\n  Top indicators:")
    for ind in result['top_indicators']:
        print(f"    - {ind}")
    print(f"\n  Processed in: {result['processing_ms']}ms")
    return result


if __name__ == "__main__":
    print("FraudShield — Live Demo")
    print("Loading models...")
    deep, rf = load_models()

    files = sys.argv[1:] if len(sys.argv) > 1 else []

    if not files:
        print("\nUsage: python scripts/demo.py <file1.wav> <file2.wav>")
        sys.exit(0)

    for f in files:
        label = "REAL voice" if "real" in f.lower() else "FAKE voice"
        run_demo(f, label, deep, rf)