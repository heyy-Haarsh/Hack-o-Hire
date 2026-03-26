import fitz  # PyMuPDF — replaces unused PyPDF2 import
import importlib.util
import os
import re
import sys
import time
import ollama
from pathlib import Path
from lib.attachments import extract_attachments
from llm import return_ans
import fraudshield_scorer
import n8n_client

# Absolute path for extracted_attachments — always relative to src/
_SRC_DIR = Path(__file__).parent
EXTRACTED_DIR = str(_SRC_DIR.parent / "extracted_attachments")

# ── Credential Scanner integration ────────────────────────────────────────────
_CS_DIR  = _SRC_DIR.parent.parent / "Credential_Scanner-main"
_cs_mod  = None  # lazy-loaded

def _get_credential_scanner():
    """Lazy-load Credential_Scanner full_scan via importlib (avoids module name conflicts)."""
    global _cs_mod
    if _cs_mod is not None:
        return _cs_mod
    try:
        _cs_path = _CS_DIR / "main.py"
        spec = importlib.util.spec_from_file_location("_cred_scanner_main", str(_cs_path))
        mod  = importlib.util.module_from_spec(spec)
        # Add CS dir to sys.path for its internal imports
        _cs_str = str(_CS_DIR)
        _saved  = sys.path[:]
        if _cs_str not in sys.path:
            sys.path.insert(0, _cs_str)
        spec.loader.exec_module(mod)
        sys.path = _saved
        _cs_mod = mod
        return mod
    except Exception as exc:
        print(f"[CredentialScanner] Load failed: {exc}")
        return None


def _run_credential_scan(text: str, filename: str = "email") -> dict:
    """Run the full 4-layer credential scan (regex + entropy + NER). Returns structured findings."""
    mod = _get_credential_scanner()
    if mod is None:
        return {"total_findings": 0, "findings": [], "risk_score": 0,
                "risk_label": "UNKNOWN", "human_summary": "Scanner unavailable"}
    try:
        return mod.full_scan(text, "email", filename)
    except Exception as exc:
        print(f"[CredentialScanner] Scan error: {exc}")
        return {"total_findings": 0, "findings": [], "risk_score": 0,
                "risk_label": "LOW", "human_summary": str(exc)}

# ─────────────────────────────────────────
# 1. EXTRACT TEXT FROM ATTACHMENTS
# ─────────────────────────────────────────

# Attachment extraction is now handled by src/lib/attachments.py to ensure 
# consistent and permanent storage in the 'extracted_attachments' folder.


# ─────────────────────────────────────────
# 2. RULE-BASED FRAUD DETECTION
# ─────────────────────────────────────────

# Keywords commonly found in fraudulent/phishing emails
FRAUD_KEYWORDS = [
    # Urgency
    "urgent", "immediate action", "act now", "limited time",
    "your account will be suspended", "verify your account",
    "confirm your identity", "click here immediately",

    # Money / Financial scams
    "you have won", "congratulations you won", "claim your prize",
    "wire transfer", "western union", "money gram",
    "send money", "transfer funds", "bitcoin",
    "nigerian prince", "inheritance", "lottery winner",

    # Credential phishing
    "enter your password", "update your payment",
    "your card has been charged", "unusual activity detected",
    "login to verify", "reset your credentials",
    "bank account details", "social security number",
    "account number", "sort code", "cvv", "pin", "routing number",
    "online banking", "username", "password", "security code",
    "set up your account", "business account",

    # Too good to be true
    "free gift", "100% free", "no cost", "risk free",
    "guaranteed income", "make money fast", "work from home",
    "earn $", "earn dollars",
]

# Suspicious link patterns
SUSPICIOUS_LINK_PATTERNS = [
    r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address links
    r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly',             # URL shorteners
    r'paypa1|g00gle|arnazon|micros0ft',                   # Typosquatting
    r'barclays|hsbc|lloyds|natwest|santander|chase'        # Major bank names in links (potentially phishing)
]

def rule_based_fraud_check(text, sender=""):
    """
    Fast rule-based fraud detection using keywords and patterns.
    Returns: { is_suspicious, score, reasons }
    """
    text_lower = text.lower()
    reasons = []
    score = 0

    # Check fraud keywords
    for keyword in FRAUD_KEYWORDS:
        if keyword in text_lower:
            reasons.append(f"Suspicious keyword: '{keyword}'")
            score += 10

    # Check suspicious link patterns
    for pattern in SUSPICIOUS_LINK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            reasons.append(f"Suspicious link pattern detected")
            score += 20

    # Check sender domain mismatches (e.g. paypal email from gmail)
    trusted_brands = ["paypal", "amazon", "google", "microsoft", "apple", "bank"]
    if sender:
        sender_lower = sender.lower()
        for brand in trusted_brands:
            if brand in text_lower and brand not in sender_lower:
                reasons.append(f"Brand '{brand}' mentioned but sender domain doesn't match")
                score += 25

    # Check for excessive urgency indicators
    urgency_count = sum(1 for word in ["urgent", "immediately", "asap", "right now", "expires"] 
                       if word in text_lower)
    if urgency_count >= 2:
        reasons.append(f"Multiple urgency indicators ({urgency_count} found)")
        score += 15

    return {
        "is_suspicious": score >= 30,
        "score": min(score, 100),  # cap at 100
        "reasons": reasons
    }


# ─────────────────────────────────────────
# 2.5 METADATA EXTRACTION (Links & Credentials)
# ─────────────────────────────────────────

def extract_metadata(text):
    """
    Extracts all URLs and identifiable credentials/identifiers from text.
    Returns: { urls: [], credentials: [] }
    """
    # ── URL Extraction ─────────────────────
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    raw_urls = re.findall(url_pattern, text)
    urls = []
    for u in set(raw_urls):
        is_suspicious = any(re.search(p, u, re.IGNORECASE) for p in SUSPICIOUS_LINK_PATTERNS)
        urls.append({
            "url": u,
            "type": "SUSPICIOUS" if is_suspicious else "NORMAL",
            "is_ip": bool(re.search(r'\d{1,3}\.\d{1,3}', u))
        })

    # ── Credential Extraction ──────────────
    credentials = []
    
    # Email addresses
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
    for email in set(emails):
        credentials.append({"type": "EMAIL", "value": email})

    # Potential API Keys / Secret Tokens (generic 32-40 char hex/alphanum)
    keys = re.findall(r'\b[A-Za-z0-9]{32,44}\b', text)
    for key in set(keys):
        # Filter for keys that seem like a mix of letters and numbers (avoiding common words)
        if any(c.isdigit() for c in key) and any(c.isalpha() for c in key):
            credentials.append({"type": "POTENTIAL_KEY", "value": key})

    # Potential Card Numbers (basic 16-digit check)
    cards = re.findall(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', text)
    for card in set(cards):
        credentials.append({"type": "CREDIT_CARD_FORMAT", "value": card})

    # Financial Identifiers
    sort_codes = re.findall(r'\b\d{2}-\d{2}-\d{2}\b', text)
    for sc in set(sort_codes):
        credentials.append({"type": "SORT_CODE", "value": sc})

    cvvs = re.findall(r'\bCVV:?\s?(\d{3,4})\b', text, re.IGNORECASE)
    for cvv in set(cvvs):
        credentials.append({"type": "CVV", "value": cvv})

    pins = re.findall(r'\bPIN:?\s?(\d{4,6})\b', text, re.IGNORECASE)
    for pin in set(pins):
        credentials.append({"type": "PIN", "value": pin})

    # Credentials in text
    usernames = re.findall(r'\bUsername:?\s?(\S+)\b', text, re.IGNORECASE)
    for u in set(usernames):
        credentials.append({"type": "EXTRACTED_USERNAME", "value": u})

    passwords = re.findall(r'\bPassword:?\s?(\S+)\b', text, re.IGNORECASE)
    for p in set(passwords):
        credentials.append({"type": "EXTRACTED_PASSWORD", "value": p})

    return {
        "urls": urls,
        "credentials": credentials
    }


# ─────────────────────────────────────────
# 3. LLM-BASED FRAUD DETECTION (Ollama)
# ─────────────────────────────────────────

def llm_fraud_detection(email_text, attachment_texts=[]):
    """
    Uses local Ollama LLM to deeply analyze email for fraud.
    Returns: { is_fraud, confidence, explanation, red_flags }
    """
    # Combine email + attachment content
    full_content = email_text
    if attachment_texts:
        full_content += "\n\n--- ATTACHMENT CONTENT ---\n"
        full_content += "\n\n".join(attachment_texts)

    prompt = f"""You are a cybersecurity expert specializing in email fraud detection.
Analyze the following email and its attachments for signs of fraud, phishing, or scam.

EMAIL CONTENT:
{full_content[:3000]}  

Respond in this exact format:
VERDICT: (FRAUD, SUSPICIOUS, or LEGITIMATE)
CONFIDENCE: (HIGH, MEDIUM, or LOW)
RED FLAGS: 
(List specific red flags starting with a dash, or "None")
EXPLANATION: [Provide a brief, human-like summary of why this email was flagged or safe]
"""

    try:
        response = ollama.chat(
            model='qwen3:8b',
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Be concise and accurate."},
                {"role": "user", "content": prompt}
            ]
        )
        result_text = response['message']['content']

        # Parse the response
        verdict = "UNKNOWN"
        confidence = "LOW"
        red_flags = []
        explanation = ""

        explanation_lines = []
        in_explanation = False
        for line in result_text.split('\n'):
            if line.startswith("VERDICT:"):
                verdict = line.replace("VERDICT:", "").strip()
                in_explanation = False
            elif line.startswith("CONFIDENCE:"):
                confidence = line.replace("CONFIDENCE:", "").strip()
                in_explanation = False
            elif line.startswith("RED FLAGS:"):
                in_explanation = False
            elif line.startswith("EXPLANATION:"):
                first = line.replace("EXPLANATION:", "").strip()
                if first:
                    explanation_lines.append(first)
                in_explanation = True
            elif in_explanation and line.strip():
                explanation_lines.append(line.strip())
            elif line.strip().startswith("- "):
                red_flags.append(line.strip()[2:])
        explanation = " ".join(explanation_lines)

        return {
            "is_fraud": verdict in ["FRAUD", "SUSPICIOUS"],
            "verdict": verdict,
            "confidence": confidence,
            "red_flags": red_flags,
            "explanation": explanation,
            "raw_response": result_text
        }

    except Exception as e:
        return {
            "is_fraud": False,
            "verdict": "ERROR",
            "confidence": "LOW",
            "red_flags": [],
            "explanation": f"LLM analysis failed: {str(e)}",
            "raw_response": ""
        }


# ─────────────────────────────────────────
# 4. GenAI CONTENT DETECTION
# ─────────────────────────────────────────

# Patterns commonly found in AI-generated text
AI_PATTERNS = [
    r'\bcertainly\b', r'\bof course\b', r'\babsolutely\b',
    r'\bi hope this (email|message|finds you)\b',
    r'\bplease do not hesitate to\b',
    r'\bshould you (have|need|require) any\b',
    r'\bfeel free to (reach out|contact)\b',
    r'\bin conclusion\b.*\bin summary\b',
    r'\bit is (important|worth noting|crucial) (to note|that)\b',
]

def detect_ai_generated(text):
    """
    Detects if email content was likely written by AI.
    Uses pattern matching + LLM verification.
    Returns: { is_ai_generated, confidence_score, indicators }
    """
    text_lower = text.lower()
    indicators = []
    score = 0

    # Check AI writing patterns
    for pattern in AI_PATTERNS:
        if re.search(pattern, text_lower):
            indicators.append(f"AI phrase pattern: '{pattern}'")
            score += 15

    # Check for unusually perfect grammar (very long sentences, no typos)
    sentences = text.split('.')
    avg_sentence_length = sum(len(s.split()) for s in sentences) / max(len(sentences), 1)
    if avg_sentence_length > 25:
        indicators.append("Unusually long, complex sentences")
        score += 10

    # Check for overly formal structure
    formal_openers = ["i am writing to", "i would like to", "please be informed", "kindly note"]
    for opener in formal_openers:
        if opener in text_lower:
            indicators.append(f"Overly formal opener: '{opener}'")
            score += 10

    # Use LLM for deeper check if rule-based score is borderline
    llm_result = None
    if score >= 20 or len(text) > 500:
        try:
            prompt = f"""Is the following text likely written by an AI or a human?
Look for signs like: overly formal tone, perfect grammar, generic phrasing, lack of personal touch.

TEXT:
{text[:1500]}

Respond in this exact format:
VERDICT: [AI-GENERATED / HUMAN-WRITTEN / UNCERTAIN]
CONFIDENCE: [HIGH / MEDIUM / LOW]
REASON: [one sentence explanation]"""

            response = ollama.chat(
                model='qwen3:8b',
                messages=[{"role": "user", "content": prompt}]
            )
            llm_result = response['message']['content']

            if "AI-GENERATED" in llm_result.upper():
                score += 30
                indicators.append("LLM analysis suggests AI-generated content")

        except Exception as e:
            indicators.append(f"LLM check skipped: {str(e)}")

    return {
        "is_ai_generated": score >= 40,
        "confidence_score": min(score, 100),
        "indicators": indicators,
        "llm_verdict": llm_result
    }


# ─────────────────────────────────────────
# 5. MASTER ANALYSIS FUNCTION
# ─────────────────────────────────────────

def analyze_email(email_message, sender="", subject="", body=""):
    """
    Full 7-layer analysis pipeline:
    1. Extract attachments (+ voice deepfake scan)
    2. Rule-based fraud check
    3. Metadata extraction (URLs, credentials)
    4. LLM deep analysis (Ollama qwen3:8b)
    5. AI-generated content detection
    6. ML score fusion (RoBERTa → DistilBERT → heuristic fallback chain)
    7. n8n incident webhook (HIGH/CRITICAL only)

    Returns complete analysis report.
    """
    print(f"\n{'='*50}")
    print(f"Analyzing email: {subject}")
    print(f"{'='*50}")

    # Step 1: Extract attachments
    print("\n[1/6] Extracting attachments...")
    # Using unified extractor to ensure permanent storage
    attachments = extract_attachments(email_message)
    attachment_texts = [a['text'] for a in attachments]
    print(f"  Found {len(attachments)} attachment(s)")

    # Combine all text for analysis
    full_text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    if attachment_texts:
        full_text += "\n\nATTACHMENTS:\n" + "\n".join(attachment_texts)

    # Step 2: Rule-based fraud check (fast)
    print("\n[2/6] Running rule-based fraud check...")
    rule_result = rule_based_fraud_check(full_text, sender)
    print(f"  Suspicious: {rule_result['is_suspicious']} (score: {rule_result['score']})")

    # Step 2.5: Metadata extraction (URLs & Credentials)
    print("\n[2.5/6] Extracting metadata (URLs & Credentials)...")
    metadata_result = extract_metadata(full_text)
    print(f"  Found {len(metadata_result['urls'])} URL(s) and {len(metadata_result['credentials'])} credential(s)")

    # Step 3: LLM fraud detection (deep)
    print("\n[3/6] Running LLM fraud detection...")
    llm_result = llm_fraud_detection(full_text, attachment_texts)
    print(f"  Verdict: {llm_result['verdict']} ({llm_result['confidence']} confidence)")

    # Step 4: AI-generated content detection
    # Append voice analysis summary to body for LLM context
    voice_context = ""
    for att in attachments:
        va = att.get('voice_analysis')
        if va:
            voice_context += f" [VOICE SCAN: {att['filename']} - Verdict: {va.get('verdict')}, Score: {va.get('risk_score')}/100]"

    body += voice_context

    print("\n[4/6] Checking for AI-generated content...")
    ai_result = detect_ai_generated(body)
    print(f"  AI-Generated: {ai_result['is_ai_generated']} (score: {ai_result['confidence_score']})")

    # Step 5: ML score fusion (fraudshield-email 4-layer pipeline)
    print("\n[5/6] Running ML score fusion (RoBERTa → DistilBERT → heuristic)...")
    reply_to         = (email_message.get('Reply-To', '') or '') if hasattr(email_message, 'get') else ''
    receiver         = (email_message.get('To', '')       or '') if hasattr(email_message, 'get') else ''
    attachment_names = [a.get('filename', '') for a in attachments]
    fused = fraudshield_scorer.score_email(
        email_text       = body,
        subject          = subject,
        sender           = sender,
        receiver         = receiver,
        reply_to         = reply_to,
        attachment_names = attachment_names,
    )
    print(f"  ML fused score: {fused['risk_score']}/100 | Scorer: {fused['scorer_used']}")

    # Step 5b: Credential scanner (regex + entropy + NER)
    print("\n[5b/6] Running credential scanner...")
    credential_scan = _run_credential_scan(full_text, subject or "email")
    cred_count = credential_scan.get("total_findings", 0)
    print(f"  Found {cred_count} credential(s) | Risk: {credential_scan.get('risk_label','LOW')}")

    # Final risk calculation — voice deepfake detection
    voice_fake_detected = any(
        (a.get('voice_analysis') or {}).get('verdict') == "FAKE 🤖"
        for a in attachments
    )
    voice_risk_score = 0
    for att in attachments:
        va = att.get('voice_analysis')
        if va and va.get('verdict') == "FAKE 🤖":
            voice_risk_score = max(voice_risk_score, va.get('risk_score', 80))

    # Step 5c: Merge ALL signals into one unified score
    unified = fraudshield_scorer.combine_all_scores(
        ml_fused         = fused,
        rule_result      = rule_result,
        llm_result       = llm_result,
        voice_risk_score = voice_risk_score,
    )
    print(f"  Unified score: {unified['final_score']}/100 [{unified['tier']}] — {unified['confidence_label']}")

    overall_risk, risk_score_numeric = _calculate_risk(
        rule_result, llm_result, ai_result, attachments,
        fused_score=unified['final_score'],
        voice_risk_score=voice_risk_score,
    )

    # Unify fraud flag — any layer finding fraud counts
    is_fraud = (
        rule_result['is_suspicious'] or
        llm_result['is_fraud']       or
        voice_fake_detected          or
        unified['verdict'] == 'PHISHING'
    )
    if "HIGH RISK" in overall_risk or "CRITICAL" in overall_risk:
        is_fraud = True

    # Step 6: n8n incident webhook
    prediction_id = f"FS-{int(time.time() * 1000)}"
    llm_summary   = llm_result.get('explanation', '') or llm_result.get('verdict', '')
    n8n_indicators = (unified.get('top_indicators') or [])
    print(f"\n[6/6] Triggering n8n incident (score={risk_score_numeric}, tier={unified['tier']})...")
    n8n_incident = n8n_client.trigger_incident(
        risk_score        = risk_score_numeric,
        verdict           = unified['verdict'],
        tier              = unified['tier'],
        outlook_action    = unified['outlook_action'],
        top_indicators    = n8n_indicators[:6],
        sender            = sender,
        subject           = subject,
        llm_summary       = unified.get('explanation', llm_summary),
        ai_prob           = fused.get('ai_prob', 0.0),
        voice_deepfake    = voice_fake_detected,
        prediction_id     = prediction_id,
    )
    if n8n_incident['triggered']:
        print(f"  ✅ Incident {n8n_incident['incident_id']} — {n8n_incident['message']}")
    else:
        print(f"  ℹ  n8n not triggered: {n8n_incident['message']}")

    report = {
        "email": {
            "sender":  sender,
            "subject": subject,
        },
        "attachments": {
            "count": len(attachments),
            # Include full attachment metadata (filename, extension, voice_analysis, save_path)
            "files": attachments
        },
        "extracted_data": metadata_result,
        "fraud_analysis": {
            "is_fraud":             is_fraud,
            "rule_based":           rule_result,
            "llm_based":            llm_result,
            "voice_deepfake_found": voice_fake_detected,
        },
        "ai_detection":        ai_result,
        "overall_risk":        overall_risk,
        "risk_score_numeric":  risk_score_numeric,
        "fused_score_details": fused,
        "unified_score":       unified,
        "credential_scan":     credential_scan,
        "n8n_incident":        n8n_incident,
        "prediction_id":       prediction_id,
    }

    # Construct a routing query string for the RAG/LLM
    routing_query = f"""
    SUBJECT: {report['email']['subject']}
    SENDER: {report['email']['sender']}
    FRAUD STATUS: {report['fraud_analysis']['is_fraud']}
    VOICE DEEPFAKE: {report['fraud_analysis'].get('voice_deepfake_found', False)}
    RISK LEVEL: {report['overall_risk']}
    EMAIL BODY: {body[:1000]}
    """

    report["routing"] = return_ans(routing_query)

    _print_report(report)
    return report


def _calculate_risk(rule_result, llm_result, ai_result, attachments=None,
                    fused_score=None, voice_risk_score=0):
    """
    Calculate overall risk level fusing all pipeline signals.

    Priority:
      1. fused_score (ML score fusion from fraudshield_scorer) — most reliable
      2. LLM + rule-based composite (fallback when ML is unavailable)

    Voice deepfake is weighted proportionally: voice_risk_score × 0.20 (max +20 pts).

    Returns: (label_string, numeric_score_0_100)
    """
    if attachments is None:
        attachments = []

    # ── Voice deepfake proportional boost ─────────────────────────────────────
    voice_boost = min(20, round(voice_risk_score * 0.20))

    # ── Use ML fused score as primary signal ─────────────────────────────────
    if fused_score is not None:
        # Blend fused ML score with voice boost
        score = min(100, int(fused_score + voice_boost))
    else:
        # Legacy fallback: rule + LLM + AI signals
        score = 0
        if rule_result['is_suspicious']:
            score += int(rule_result['score'] * 0.4)
        if llm_result['is_fraud']:
            score += 40
        if llm_result['confidence'] == 'HIGH' and llm_result['is_fraud']:
            score += 20
        if ai_result['is_ai_generated']:
            score += 10
        score = min(100, score + voice_boost)

    # Mirror fraudshield-email risk tiers exactly
    if score >= 70:
        return "CRITICAL RISK 🚨", score
    elif score >= 61:
        return "HIGH RISK 🔴", score
    elif score >= 31:
        return "MEDIUM RISK 🟡", score
    else:
        return "LOW RISK 🟢", score



def _print_report(report):
    """Print a clean summary report."""
    print(f"\n{'='*50}")
    print("📊 ANALYSIS REPORT")
    print(f"{'='*50}")
    print(f"📧 Subject    : {report['email']['subject']}")
    print(f"👤 From       : {report['email']['sender']}")
    print(f"📎 Attachments: {report['attachments']['count']}")
    print(f"🚨 Fraud      : {report['fraud_analysis']['is_fraud']}")
    print(f"🤖 AI Written : {report['ai_detection']['is_ai_generated']}")
    print(f"⚠️  Risk Level : {report['overall_risk']}")

    # ML score fusion summary
    fsd = report.get('fused_score_details', {})
    if fsd:
        print(f"\n🧠 ML Score Fusion ({fsd.get('scorer_used','?')}):")
        print(f"   • Final score  : {fsd.get('risk_score')}/100  [{fsd.get('tier')}]")
        print(f"   • Verdict      : {fsd.get('verdict')}")
        if fsd.get('roberta_prob') is not None:
            print(f"   • RoBERTa prob : {fsd['roberta_prob']:.2%}")
        print(f"   • Rule score   : {fsd.get('rule_score', 0):.0f}/100")
        print(f"   • AI-text prob : {fsd.get('ai_prob', 0):.2%}")
        print(f"   • Header score : {fsd.get('header_score', 0)}/100")

    # n8n incident
    n8n = report.get('n8n_incident', {})
    if n8n.get('triggered'):
        print(f"\n🔔 n8n Incident : {n8n.get('incident_id')} — {n8n.get('message')}")
        if n8n.get('approve_url'):
            print(f"   ✅ Approve : {n8n['approve_url']}")
            print(f"   ❌ Reject  : {n8n['reject_url']}")

    if report['extracted_data']['urls']:
        print(f"\n🔗 URLs Found ({len(report['extracted_data']['urls'])}):")
        for u in report['extracted_data']['urls']:
            print(f"   • [{u['type']}] {u['url']}")

    if report['extracted_data']['credentials']:
        print(f"\n🔐 Credentials Found ({len(report['extracted_data']['credentials'])}):")
        for c in report['extracted_data']['credentials']:
            print(f"   • [{c['type']}] {c['value']}")

    if report['fraud_analysis']['rule_based']['reasons']:
        print("\n🔍 Fraud Indicators:")
        for r in report['fraud_analysis']['rule_based']['reasons']:
            print(f"   • {r}")

    if report['fraud_analysis']['llm_based']['red_flags']:
        print("\n🤖 LLM Red Flags:")
        for f in report['fraud_analysis']['llm_based']['red_flags']:
            print(f"   • {f}")

    if report['ai_detection']['indicators']:
        print("\n✍️  AI Writing Indicators:")
        for i in report['ai_detection']['indicators']:
            print(f"   • {i}")

    print(f"{'='*50}\n")


# ─────────────────────────────────────────
# EXAMPLE USAGE
# ─────────────────────────────────────────
if __name__ == "__main__":
    # Test with a fake suspicious email (no real email needed)
    import email
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    # Create a fake test email
    msg = MIMEMultipart()
    msg['From'] = 'support@paypa1.com'
    msg['Subject'] = 'URGENT: Verify your account immediately'
    msg.attach(MIMEText("""
    Dear Customer,
    
    Your PayPal account has been suspended due to unusual activity detected.
    You must verify your account immediately or it will be permanently closed.
    
    Click here to verify: http://192.168.1.1/paypal/verify
    
    Enter your password and bank account details to restore access.
    Act now - this offer expires in 24 hours.
    
    Regards,
    PayPal Security Team
    """))

    # Run analysis
    result = analyze_email(
        email_message=msg,
        sender='support@paypa1.com',
        subject='URGENT: Verify your account immediately',
        body=msg.get_payload()[0].get_payload()
    )