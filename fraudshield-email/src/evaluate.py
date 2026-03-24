# src/evaluate.py
import re
import torch
import time
import sys
import requests
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import DEVICE, MODELS_DIR, TIERS
from feature_extractor import extract_features
from ai_text_detector import detect_ai_text

THRESHOLD = 0.50

OUTLOOK_ACTIONS = {
    "CRITICAL": "QUARANTINE",
    "HIGH":     "JUNK",
    "MEDIUM":   "FLAG",
    "LOW":      "ALLOW",
}


def get_tier(score: int):
    for threshold, tier, _ in TIERS:
        if score >= threshold:
            return tier, OUTLOOK_ACTIONS.get(tier, "ALLOW")
    return "LOW", "ALLOW"


def load_models():
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    print("Loading email phishing models...")
    saved_path = MODELS_DIR / "phishing_classifier"
    tokenizer  = AutoTokenizer.from_pretrained(str(saved_path))
    model      = AutoModelForSequenceClassification.from_pretrained(
        str(saved_path)
    ).to(DEVICE)
    model.eval()
    print("  Models loaded.")
    return tokenizer, model


def analyze_headers(
    sender:      str,
    receiver:    str,
    reply_to:    str,
    subject:     str,
    spf_pass:    bool,
    dkim_pass:   bool,
    attachments: list
) -> tuple:
    """
    Analyze email headers for phishing signals.
    Returns (header_score 0-100, header_flags list).
    """
    score = 0
    flags = []

    sender_domain   = sender.split("@")[-1].lower()   if "@" in sender   else ""
    reply_to_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
    receiver_domain = receiver.split("@")[-1].lower() if "@" in receiver else ""

    # Reply-To mismatch — #1 phishing indicator in headers
    if reply_to and reply_to_domain and reply_to_domain != sender_domain:
        score += 30
        flags.append(
            f"Reply-To mismatch — sender: {sender_domain}, "
            f"replies go to: {reply_to_domain}"
        )

    # SPF failure — sender not authorized to send from this domain
    if spf_pass is False:
        score += 25
        flags.append("SPF authentication FAILED — sender domain not authorized")

    # DKIM failure — email signature invalid
    if dkim_pass is False:
        score += 20
        flags.append("DKIM signature FAILED — email may be forged")

    # Suspicious sender domain patterns
    suspicious_patterns = [
        (r"@.+\.(xyz|tk|ml|ga|cf|top|click|loan|work)$",
         "Sender uses suspicious TLD"),
        (r"barclays.+\.(net|xyz|org|info|biz)",
         "Barclays impersonation in sender domain"),
        (r"(security|verify|alert|support)\d*@(?!barclays\.com)",
         "Fake security/verify sender address"),
    ]
    for pattern, msg in suspicious_patterns:
        if re.search(pattern, sender.lower()):
            score += 20
            flags.append(msg + f": {sender}")
            break

    # Subject line urgency/threat patterns
    subject_patterns = [
        r"urgent", r"immediate(ly)?", r"action required",
        r"verify", r"suspend", r"block", r"unusual activity",
        r"security alert", r"account (locked|suspended|terminated)",
        r"(limited|expir)", r"final (notice|warning)",
    ]
    subject_hits = sum(
        1 for p in subject_patterns
        if re.search(p, subject.lower())
    )
    if subject_hits:
        score += min(20, subject_hits * 8)
        flags.append(
            f"Urgent/threatening subject line "
            f"({subject_hits} patterns): '{subject[:50]}'"
        )

    # Risky attachments
    if attachments:
        risky_exts = [
            ".exe", ".bat", ".vbs", ".js", ".zip", ".rar",
            ".docm", ".xlsm", ".pptm", ".iso", ".lnk", ".ps1"
        ]
        risky = [
            a for a in attachments
            if any(a.lower().endswith(ext) for ext in risky_exts)
        ]
        if risky:
            score += 30
            flags.append(f"Risky attachment(s) detected: {risky}")

    # External sender targeting Barclays employee
    barclays_domains = ["barclays.com", "barclays.co.uk", "barclaysus.com"]
    is_external = (
        sender_domain not in barclays_domains and
        any(d in receiver_domain for d in barclays_domains)
    )
    if is_external and score > 20:
        flags.append(
            f"External sender targeting Barclays employee: {sender}"
        )

    return min(100, score), flags

def guard_check(text: str) -> dict:
    try:
        r = requests.post(
            "http://localhost:8005/guard/check",
            json={"prompt": text[:2000], "context": "email"},
            timeout=2
        )
        return r.json()
    except:
        return {"block": False, "injection_score": 0, "verdict": "CLEAN"}


def predict_email(
    email_text:   str,
    subject:      str  = "",
    sender:       str  = "",
    receiver:     str  = "",
    cc:           str  = "",
    reply_to:     str  = "",
    spf_pass:     bool = None,
    dkim_pass:    bool = None,
    attachments:  list = None,
    tokenizer          = None,
    model              = None,
    use_llm:      bool = False
) -> dict:
    guard = guard_check(email_text)
    if guard.get("block"):
        return {
            "verdict":          "INJECTION_ATTEMPT",
            "risk_score":       100,
            "tier":             "CRITICAL",
            "outlook_action":   "QUARANTINE",
            "top_indicators":   [f"Prompt injection detected: {guard.get('human_summary')}"],
            "injection_score":  guard.get("injection_score", 0),
            "processing_ms":    guard.get("processing_ms", 0),
        }
    t0 = time.time()
    full_text = f"Subject: {subject}\n\n{email_text}".strip()

    # ── Layer 1: RoBERTa classification ───────────────────────────
    inputs = tokenizer(
        full_text,
        truncation=True,
        max_length=512,
        padding="max_length",
        return_tensors="pt"
    ).to(DEVICE)

    with torch.no_grad():
        logits       = model(**inputs).logits
        probs        = torch.softmax(logits, dim=-1)
        roberta_prob = float(probs[0][1].item())

    # ── Layer 2: Rule-based features ───────────────────────   ───────
    features   = extract_features(email_text, subject, sender)
    rule_score = min(100, (
        features["urgency_count"]          * 15 +
        features["credential_count"]       * 25 +
        features["threat_count"]           * 20 +
        features["impersonation_count"]    * 15 +
        features["suspicious_url_count"]   * 10 +
        features["domain_spoofed"]         * 15 +
        features["known_phishing_domain"]  * 50
    )) / 100.0

    # ── Layer 3: AI-text detection ────────────────────────────────
    ai_result = detect_ai_text(email_text)
    ai_prob   = ai_result["ai_generated_probability"]

    # ── Layer 4: Header analysis ──────────────────────────────────
    header_score, header_flags = analyze_headers(
        sender, receiver, reply_to, subject,
        spf_pass, dkim_pass, attachments or []
    )
    header_score_norm = header_score / 100.0

    # ── Score fusion — all 4 layers ───────────────────────────────
    hindi_boost = 0.10 if features.get("has_hindi_patterns") else 0.0
    final = min(1.0, (
        0.45 * roberta_prob      +
        0.20 * rule_score        +
        0.15 * ai_prob           +
        0.20 * header_score_norm +
        hindi_boost * rule_score
    ))
    risk = int(final * 100)
    tier, outlook_action = get_tier(risk)

    # ── Human-readable indicators ─────────────────────────────────
    indicators = []
    if features["urgency_count"]:
        indicators.append(
            f"Urgency language ({features['urgency_count']} patterns)")
    if features["credential_count"]:
        indicators.append(
            f"Credential request ({features['credential_count']} patterns)")
    if features["domain_spoofed"]:
        indicators.append("Sender domain spoofing detected")
    if features["threat_count"]:
        indicators.append("Threat language detected")
    if features["has_hindi_patterns"]:
        indicators.append("Hindi/regional phishing patterns detected")
    if features.get("known_phishing_domain"):
        indicators.append("Domain found in phishing blocklist (778k domains)")
    if ai_prob > 0.6:
        indicators.append(
            f"AI-generated text detected ({ai_prob:.0%} probability)")
    if roberta_prob > 0.7:
        indicators.append(
            f"RoBERTa: {roberta_prob:.0%} phishing confidence")

    all_indicators = indicators + header_flags

    # ── LLM explanation ───────────────────────────────────────────
    explanation = ""
    if use_llm:
        try:
            import ollama
            prompt = f"""You are a phishing analyst at Barclays bank.
Email risk score: {risk}/100. Tier: {tier}.
Top signals: {'; '.join(all_indicators[:3]) if all_indicators else 'None'}.
AI-generated probability: {ai_prob:.0%}.
Write exactly 2 sentences for a non-technical security reviewer."""
            r = ollama.chat(
                model="llama3",
                messages=[{"role": "user", "content": prompt}]
            )
            explanation = r["message"]["content"].strip()
        except Exception as e:
            explanation = f"LLM unavailable: {e}"

    # ── Verdict with special cases ────────────────────────────────
    verdict = "PHISHING" if (
        final >= THRESHOLD or
        (features.get("has_hindi_patterns") and final >= 0.30) or
        (features.get("known_phishing_domain")  and final >= 0.20) or
        (header_score >= 50 and roberta_prob > 0.3)
    ) else "LEGITIMATE"

    return {
        "verdict":                   verdict,
        "risk_score":                risk,
        "tier":                      tier,
        "outlook_action":            outlook_action,
        "roberta_phishing_prob":     round(roberta_prob, 4),
        "rule_based_score":          round(rule_score * 100, 1),
        "header_risk_score":         header_score,
        "ai_generated_probability":  round(ai_prob, 4),
        "top_indicators":            all_indicators,
        "header_flags":              header_flags,
        "explanation":               explanation,
        "email_features":            features,
        "processing_ms":             round((time.time() - t0) * 1000),
    }


if __name__ == "__main__":
    import json
    tokenizer, model = load_models()
    sample = (
        "URGENT: Your Barclays account has been suspended. "
        "Verify your card details at http://barclays-secure.xyz "
        "or face legal action within 24 hours."
    )
    result = predict_email(
        sample,
        subject="Account Suspended",
        sender="security@barclays-secure.xyz",
        reply_to="collect@fraudster.ru",
        spf_pass=False,
        tokenizer=tokenizer,
        model=model
    )
    print(json.dumps(
        {k: v for k, v in result.items() if k != "email_features"},
        indent=2
    ))