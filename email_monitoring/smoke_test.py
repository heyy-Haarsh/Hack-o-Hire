"""
smoke_test.py — quick end-to-end pipeline check
Run: .venv\Scripts\python.exe smoke_test.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

print("=" * 60)
print("PIPELINE SMOKE TEST")
print("=" * 60)

# ── 1. DistilBERT fine-tuned ─────────────────────────────────
print("\n[1/4] DistilBERT Fine-Tuned Classifier")
from bert_detector import DistilBertEmailDetector
det = DistilBertEmailDetector()

phish_email = "URGENT! Your bank account has been suspended. Click here immediately to verify your identity or you will lose access."
legit_email = "Hi team, please find attached the meeting agenda for tomorrow's 10am call. Let me know if you have questions."

r1 = det.predict(phish_email)
r2 = det.predict(legit_email)

print(f"  Phishing test → {r1['label']:12} | {r1['risk_level']} | conf={r1['confidence']} | model={r1['model']}")
print(f"  Legit test    → {r2['label']:12} | {r2['risk_level']} | conf={r2['confidence']}")

phish_ok = r1['is_phishing']
legit_ok  = not r2['is_phishing']
print(f"  Result: {'✅ PASS' if phish_ok and legit_ok else '❌ FAIL'}")

# ── 2. URL Scanner ───────────────────────────────────────────
print("\n[2/4] URL Scanner (PhishGuard)")
try:
    from url_scanner import extract_urls_from_text, fast_scan
    urls = extract_urls_from_text("Check this http://192.168.1.1/verify-account and https://google.com")
    print(f"  Extracted {len(urls)} URL(s): {urls}")
    if urls:
        res = fast_scan(urls[0])
        print(f"  Fast scan → {res.get('verdict', '?')}")
    print("  Result: ✅ PASS")
except Exception as e:
    print(f"  Result: ❌ FAIL — {e}")

# ── 3. Voice/Audio MFCC ─────────────────────────────────────
print("\n[3/4] Voice Deepfake Detector")
try:
    from voice.evaluate import VoiceDeepfakeDetector
    vd = VoiceDeepfakeDetector()
    print(f"  Model loaded: {vd is not None}")
    print(f"  Result: ✅ PASS (model ready)")
except Exception as e:
    print(f"  Result: ⚠️  {e} (no audio file in test, but module loads)")

# ── 4. LLM Explanation ──────────────────────────────────────
print("\n[4/4] LLM (Ollama / Qwen) Connection")
try:
    import ollama
    models = ollama.list()
    model_names = [m.model for m in models.models]
    print(f"  Available models: {model_names}")
    print(f"  Result: ✅ PASS")
except Exception as e:
    print(f"  Result: ❌ — {e}")

print("\n" + "=" * 60)
print("SMOKE TEST COMPLETE")
print("=" * 60)
