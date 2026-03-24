# scripts/batch_test.py
# Tests the system on multiple files at once and gives a summary report

import sys
import json
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from evaluate import load_models, predict

# ── Test cases — add/remove files as needed ────────────────────────
TEST_CASES = [
    # (file_path, expected_verdict, description)

    # Known REAL files from ASVspoof
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1138215.flac", "REAL", "ASVspoof bonafide 1"),
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1271820.flac", "REAL", "ASVspoof bonafide 2"),
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1272637.flac", "REAL", "ASVspoof bonafide 3"),
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1276960.flac", "REAL", "ASVspoof bonafide 4"),
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1341447.flac", "REAL", "ASVspoof bonafide 5"),

    # Your real voice recording
    ("outputs/demo_real.flac", "REAL", "Your real voice"),

    # Known FAKE files from ASVspoof
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1004644.flac", "FAKE", "ASVspoof spoof A01"),
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1056709.flac", "FAKE", "ASVspoof spoof A02"),
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1195221.flac", "FAKE", "ASVspoof spoof A03"),
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1265032.flac", "FAKE", "ASVspoof spoof A04"),
    ("data/raw/ASVspoof2019_LA/LA/LA/ASVspoof2019_LA_train/flac/LA_T_1287124.flac", "FAKE", "ASVspoof spoof A05"),

    # Generated fake audio
    ("outputs/demo_fake.wav", "FAKE", "gTTS generated fake"),
]

def run_batch_test():
    print("=" * 65)
    print("FraudShield — Batch Test Suite")
    print("=" * 65)
    print("Loading models...")
    deep, rf = load_models()
    print()

    results   = []
    correct   = 0
    total     = 0
    not_found = 0

    for file_path, expected, description in TEST_CASES:
        if not Path(file_path).exists():
            print(f"  SKIP  {description:<30} (file not found)")
            not_found += 1
            continue

        try:
            t0     = time.time()
            result = predict(file_path, deep, rf, use_llm=False)
            ms     = round((time.time() - t0) * 1000)

            verdict   = result["verdict"]
            score     = result["risk_score"]
            tier      = result["tier"]
            is_correct = verdict == expected

            if is_correct:
                correct += 1
                status = "PASS"
            else:
                status = "FAIL"

            total += 1

            # Color coding
            tier_icons = {
                "LOW":      "GREEN",
                "MEDIUM":   "AMBER",
                "HIGH":     "ORANGE",
                "CRITICAL": "RED"
            }

            print(f"  [{status}] {description:<30} "
                  f"Expected={expected:<4} "
                  f"Got={verdict:<4} "
                  f"Score={score:>3}/100 "
                  f"[{tier:<8}] "
                  f"{ms}ms")

            results.append({
                "file":        file_path,
                "description": description,
                "expected":    expected,
                "got":         verdict,
                "score":       score,
                "tier":        tier,
                "correct":     is_correct,
                "ms":          ms,
            })

        except Exception as e:
            print(f"  [ERROR] {description:<30} {str(e)[:50]}")
            total += 1

    # Summary
    print()
    print("=" * 65)
    accuracy = round(correct / total * 100, 1) if total > 0 else 0
    print(f"Results: {correct}/{total} correct  ({accuracy}% accuracy)")
    print(f"Skipped: {not_found} files not found")

    # Breakdown
    real_tests  = [r for r in results if r["expected"] == "REAL"]
    fake_tests  = [r for r in results if r["expected"] == "FAKE"]
    real_correct = sum(1 for r in real_tests  if r["correct"])
    fake_correct = sum(1 for r in fake_tests  if r["correct"])

    print(f"Real voice accuracy: {real_correct}/{len(real_tests)}")
    print(f"Fake voice accuracy: {fake_correct}/{len(fake_tests)}")

    avg_real_score = sum(r["score"] for r in real_tests)  / max(len(real_tests), 1)
    avg_fake_score = sum(r["score"] for r in fake_tests)  / max(len(fake_tests), 1)
    avg_ms         = sum(r["ms"] for r in results) / max(len(results), 1)

    print(f"Avg real score : {avg_real_score:.1f}/100  (lower = better)")
    print(f"Avg fake score : {avg_fake_score:.1f}/100  (higher = better)")
    print(f"Avg latency    : {avg_ms:.0f}ms per file")
    print("=" * 65)

    # Save report
    report_path = Path("outputs/batch_test_report.json")
    with open(report_path, "w") as f:
        json.dump({
            "accuracy":        accuracy,
            "correct":         correct,
            "total":           total,
            "real_accuracy":   f"{real_correct}/{len(real_tests)}",
            "fake_accuracy":   f"{fake_correct}/{len(fake_tests)}",
            "avg_real_score":  round(avg_real_score, 1),
            "avg_fake_score":  round(avg_fake_score, 1),
            "avg_latency_ms":  round(avg_ms),
            "results":         results,
        }, f, indent=2)
    print(f"Report saved → {report_path}")

    return accuracy


if __name__ == "__main__":
    run_batch_test()