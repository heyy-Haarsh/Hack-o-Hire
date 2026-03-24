# src/transcript_analyzer.py
# Combines voice deepfake detection with speech-to-text
# + phishing language detection on the transcript

import re
import json
import numpy as np
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))

# ── Phishing language patterns ─────────────────────────────────────
URGENCY_PATTERNS = [
    r"urgent(ly)?", r"immediately", r"right now",
    r"within \d+ (hours?|minutes?)", r"account.{0,20}suspend",
    r"suspend.{0,20}account", r"blocked", r"frozen",
    r"verify.{0,20}(now|immediately|urgent)",
]

CREDENTIAL_PATTERNS = [
    r"(card|account).{0,20}number",
    r"(pin|password|passcode)",
    r"cvv", r"sort code", r"security.{0,20}(number|code|question)",
    r"date of birth", r"mother.{0,10}maiden",
    r"one.{0,5}time.{0,5}(password|code|pin)",
    r"otp",
]

IMPERSONATION_PATTERNS = [
    r"(this is|calling from).{0,30}(barclays|bank|fraud)",
    r"(fraud|security|risk).{0,10}(team|department|unit)",
    r"(official|genuine|legitimate).{0,20}(call|contact)",
    r"do not.{0,20}(hang up|end the call|disconnect)",
    r"stay on the line",
]

THREAT_PATTERNS = [
    r"(legal|police|authorities).{0,20}(action|involve|contact)",
    r"arrest", r"lawsuit", r"criminal",
    r"(fine|penalty).{0,20}(£|\$|\d+)",
]

HINDI_URGENCY = [
    r"turant", r"abhi", r"jaldi",
    r"(khata|account).{0,20}band",
    r"(verify|check).{0,20}karo",
]

HINDI_CREDENTIAL = [
    r"(card|atm).{0,20}(number|nombor|nambar)",
    r"(pin|password).{0,20}(batao|dijiye|share)",
    r"otp.{0,20}(batao|share|dijiye|bhejo)",
]

def analyze_transcript(text: str) -> dict:
    """
    Analyze call transcript for phishing/social engineering patterns.
    Returns risk indicators and scores.
    """
    text_lower = text.lower()
    urgency     = check_patterns(URGENCY_PATTERNS + HINDI_URGENCY)
    credentials = check_patterns(CREDENTIAL_PATTERNS + HINDI_CREDENTIAL)
    
    # Check each pattern category
    def check_patterns(patterns: list) -> list:
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, text_lower)
            if found:
                matches.append(pattern.split("(")[0].strip(".{?,?}"))
        return matches

    urgency     = check_patterns(URGENCY_PATTERNS)
    credentials = check_patterns(CREDENTIAL_PATTERNS)
    impersonation = check_patterns(IMPERSONATION_PATTERNS)
    threats     = check_patterns(THREAT_PATTERNS)

    # Score calculation
    text_score = min(100, (
        len(urgency)       * 15 +
        len(credentials)   * 25 +
        len(impersonation) * 20 +
        len(threats)       * 30
    ))

    indicators = []
    if urgency:
        indicators.append(f"Urgency language detected: {urgency[:2]}")
    if credentials:
        indicators.append(f"Credential request detected: {credentials[:2]}")
    if impersonation:
        indicators.append(f"Bank impersonation patterns: {impersonation[:2]}")
    if threats:
        indicators.append(f"Threat language detected: {threats[:2]}")

    return {
        "text_risk_score": text_score,
        "urgency_count":      len(urgency),
        "credential_requests": len(credentials),
        "impersonation_signs": len(impersonation),
        "threat_language":     len(threats),
        "text_indicators":     indicators,
        "transcript_length":   len(text.split()),
    }


def transcribe_audio(audio_path: str) -> str:
    """
    Transcribe audio to text using Whisper (local, offline).
    Falls back to empty string if Whisper not available.
    """
    try:
        import whisper
        print(f"  Transcribing {Path(audio_path).name}...")
        model = whisper.load_model("tiny")   # tiny = fast, 39M params
        result = model.transcribe(
            audio_path,
            language=None,       # auto-detect language
            task="transcribe",
            fp16=False
        )
        return result["text"].strip()
    except ImportError:
        return ""
    except Exception as e:
        print(f"  Transcription failed: {e}")
        return ""


def combined_analysis(
    audio_path:   str,
    voice_result: dict,
    transcript:   str = None
) -> dict:
    """
    Combine voice deepfake score + transcript phishing score
    into a single fused risk assessment.
    """
    # Get transcript if not provided
    if transcript is None:
        transcript = transcribe_audio(audio_path)

    # Analyze transcript
    text_analysis = analyze_transcript(transcript)

    # Fuse voice + text scores
    voice_score = voice_result.get("risk_score", 0)
    text_score  = text_analysis["text_risk_score"]

    # Weighted fusion — voice is primary signal
    fused_score = int(0.65 * voice_score + 0.35 * text_score)
    fused_score = min(100, fused_score)

    tiers = [
        (86, "CRITICAL", "BLOCK — trigger incident response"),
        (61, "HIGH",     "BLOCK — escalate to fraud team"),
        (31, "MEDIUM",   "FLAG — human review required"),
        (0,  "LOW",      "ALLOW — log and monitor"),
    ]
    tier, action = next(
        (t, a) for thresh, t, a in tiers if fused_score >= thresh
    )

    return {
        **voice_result,
        "transcript":          transcript,
        "text_risk_score":     text_score,
        "fused_risk_score":    fused_score,
        "fused_tier":          tier,
        "fused_action":        action,
        "text_indicators":     text_analysis["text_indicators"],
        "urgency_detected":    text_analysis["urgency_count"] > 0,
        "credential_request":  text_analysis["credential_requests"] > 0,
        "impersonation_detected": text_analysis["impersonation_signs"] > 0,
        "language_detected":   "auto",
    }