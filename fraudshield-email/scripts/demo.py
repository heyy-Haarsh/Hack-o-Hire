# scripts/demo.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from evaluate import load_models, predict_email

SAMPLES = [
    (
        "Hi team, the Q3 report is attached. Please review by Friday.",
        "Q3 Report",
        "john.smith@barclays.com",
        "LEGITIMATE",
        "Normal work email"
    ),
    (
        "URGENT: Your Barclays account has been suspended. Click here to verify your card details immediately: http://barclays-secure.xyz or face legal action.",
        "URGENT: Account Suspended",
        "security@barclays-secure.xyz",
        "PHISHING",
        "Classic phishing"
    ),
    (
        "Dear valued customer, As part of our ongoing security review, we require you to verify your account credentials. Please provide your card number, PIN, and date of birth within 24 hours to avoid permanent suspension.",
        "Important Security Notice",
        "noreply@barclays-uk.com",
        "PHISHING",
        "AI-generated phishing"
    ),
    (
        "Meeting rescheduled to 2pm tomorrow. Conference room B. Dial-in details attached.",
        "Meeting Update",
        "sarah.jones@company.com",
        "LEGITIMATE",
        "Normal calendar email"
    ),
    (
        "Aapka Barclays account band ho sakta hai. Abhi apna OTP aur card details share karo warna account permanently band ho jayega.",
        "Urgent: Account Alert",
        "alerts@barclays-in.tk",
        "PHISHING",
        "Hindi phishing"
    ),
]


def run_demo():
    print("=" * 65)
    print("FraudShield Email — Live Demo")
    print("=" * 65)
    print("Loading models...")
    tokenizer, model = load_models()
    print()

    correct = 0

    for text, subject, sender, expected, desc in SAMPLES:
        result  = predict_email(text, subject, sender,
                                tokenizer, model, use_llm=False)
        verdict = result["verdict"]
        score   = result["risk_score"]
        tier    = result["tier"]
        action  = result["outlook_action"]
        ai_prob = result["ai_generated_probability"]
        ok      = "PASS" if verdict == expected else "FAIL"

        if verdict == expected:
            correct += 1

        print(f"[{ok}] {desc}")
        print(f"  Expected  : {expected}")
        print(f"  Verdict   : {verdict}")
        print(f"  Score     : {score}/100  [{tier}]")
        print(f"  Outlook   : {action}")
        print(f"  AI-written: {ai_prob:.0%}")
        if result["top_indicators"]:
            print(f"  Top signal: {result['top_indicators'][0]}")
        print()

    print("=" * 65)
    accuracy = round(correct / len(SAMPLES) * 100)
    print(f"Result: {correct}/{len(SAMPLES)} correct ({accuracy}%)")
    print("=" * 65)

    if correct == len(SAMPLES):
        print("\nAll tests passed — system ready for hackathon demo")
    else:
        failed = len(SAMPLES) - correct
        print(f"\n{failed} test(s) failed — check above for details")


if __name__ == "__main__":
    run_demo()