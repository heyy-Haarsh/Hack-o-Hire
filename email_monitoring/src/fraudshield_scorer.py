"""
fraudshield_scorer.py
─────────────────────────────────────────────────────────────────────────────
Production-grade email phishing scorer for email_monitoring.

Implements a 4-layer score fusion pipeline mirroring fraudshield-email:
  Layer 1: RoBERTa phishing classifier     × 0.45 weight
  Layer 2: Rule-based feature extraction   × 0.20 weight
  Layer 3: AI-generated text detection     × 0.15 weight
  Layer 4: Header analysis                 × 0.20 weight

Fallback chain (automatic, zero configuration needed):
  RoBERTa (full fusion) → DistilBERT (simplified) → Heuristic-only

Returns a standardised dict compatible with the email_monitoring pipeline.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Optional

# ── Path resolution ────────────────────────────────────────────────────────────
_SRC_DIR       = Path(__file__).parent                                       # email_monitoring/src/
_FS_EMAIL_SRC  = _SRC_DIR.parent.parent / "fraudshield-email" / "src"       # fraudshield-email/src/
_FS_MODEL_DIR  = (_SRC_DIR.parent.parent / "fraudshield-email"
                  / "models" / "saved" / "phishing_classifier")              # RoBERTa model

# ── Risk tiers — mirror fraudshield-email/src/config.py exactly ───────────────
_TIERS = [
    (70, "CRITICAL", "QUARANTINE"),
    (61, "HIGH",     "JUNK"),
    (31, "MEDIUM",   "FLAG"),
    (0,  "LOW",      "ALLOW"),
]

# ── Lazy-loaded RoBERTa model ─────────────────────────────────────────────────
_tokenizer  = None
_model      = None
_load_error = ""
_loaded     = False


def _ensure_fs_path() -> None:
    """Inject fraudshield-email/src into sys.path once."""
    fs = str(_FS_EMAIL_SRC)
    if fs not in sys.path:
        sys.path.insert(0, fs)


def _try_load_roberta() -> None:
    """Lazy-load the fine-tuned RoBERTa phishing model (thread-safe read)."""
    global _tokenizer, _model, _load_error, _loaded
    if _loaded:
        return
    _loaded = True

    if not (_FS_MODEL_DIR / "config.json").exists():
        _load_error = f"RoBERTa model not found at {_FS_MODEL_DIR}"
        print(f"[FraudShieldScorer] ⚠  {_load_error} — falling back to DistilBERT")
        return

    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        _dev = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"[FraudShieldScorer] Loading RoBERTa on {_dev.upper()}…")
        _tokenizer = AutoTokenizer.from_pretrained(str(_FS_MODEL_DIR))
        _model = (AutoModelForSequenceClassification
                  .from_pretrained(str(_FS_MODEL_DIR))
                  .to(_dev))
        _model.eval()
        print("[FraudShieldScorer] ✅ RoBERTa ready.")
    except Exception as exc:
        _load_error = str(exc)
        print(f"[FraudShieldScorer] ✗ RoBERTa load failed: {exc}")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_tier(score: int):
    for threshold, tier, action in _TIERS:
        if score >= threshold:
            return tier, action
    return "LOW", "ALLOW"


def _roberta_prob(email_text: str, subject: str) -> float:
    import torch
    device = next(_model.parameters()).device
    full   = f"Subject: {subject}\n\n{email_text}"
    inputs = _tokenizer(
        full, truncation=True, max_length=512,
        padding="max_length", return_tensors="pt"
    ).to(device)
    with torch.no_grad():
        logits = _model(**inputs).logits
        probs  = torch.softmax(logits, dim=-1)
    return float(probs[0][1].item())


def _heuristic_prob(text: str) -> float:
    """Simple keyword heuristic as last-resort fallback (0–1)."""
    patterns = [
        r"urgent", r"verify your account", r"click here", r"account suspended",
        r"confirm your password", r"bitcoin", r"wire transfer", r"western union",
        r"you have won", r"nigerian prince", r"limited time offer",
        r"social security", r"suspicious activity", r"credential",
    ]
    hits = sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))
    if hits >= 4: return 0.90
    if hits >= 3: return 0.75
    if hits >= 2: return 0.55
    if hits >= 1: return 0.35
    return 0.10


def _rule_score_fallback(text: str, subject: str, sender: str) -> tuple[float, list]:
    """Lightweight rule scoring when fraudshield-email feature_extractor is unavailable."""
    indicators = []
    score = 0.0
    t = text.lower()

    urgency = sum(1 for p in [r"urgent", r"act now", r"immediately", r"limited time",
                               r"expires", r"last warning", r"account.{0,15}suspend"]
                  if re.search(p, t))
    if urgency:
        score += urgency * 0.15
        indicators.append(f"Urgency language ({urgency} patterns)")

    creds = sum(1 for p in [r"password", r"pin", r"cvv", r"social security",
                             r"card.{0,10}(number|detail)", r"confirm.{0,10}(credential|account)"]
                if re.search(p, t))
    if creds:
        score += creds * 0.20
        indicators.append(f"Credential request ({creds} patterns)")

    threats = sum(1 for p in [r"legal action", r"arrest", r"lawsuit", r"fine", r"penalty"]
                  if re.search(p, t))
    if threats:
        score += threats * 0.15
        indicators.append("Threat language detected")

    return min(1.0, score), indicators


def _ai_prob_fallback(text: str) -> float:
    """Pattern-based AI-text probability fallback."""
    ai_patterns = [
        r"\bcertainly\b", r"\bof course\b", r"\bplease do not hesitate\b",
        r"\bshould you (have|need|require)\b", r"\bfeel free to (reach|contact)\b",
        r"\bi hope this (email|message|finds)\b", r"\babsolutely\b",
    ]
    hits = sum(1 for p in ai_patterns if re.search(p, text, re.IGNORECASE))
    return min(0.9, hits * 0.15)


# ── Public API ────────────────────────────────────────────────────────────────

def score_email(
    email_text:       str,
    subject:          str           = "",
    sender:           str           = "",
    receiver:         str           = "",
    reply_to:         str           = "",
    spf_pass:         Optional[bool] = None,
    dkim_pass:        Optional[bool] = None,
    attachment_names: list          = None,
) -> dict:
    """
    Score an email for phishing using a 4-layer score fusion pipeline.

    Parameters
    ----------
    email_text       : Body text of the email
    subject          : Email subject line
    sender           : Sender address (From header)
    receiver         : Recipient address (To header)
    reply_to         : Reply-To header value
    spf_pass         : SPF authentication result (True/False/None)
    dkim_pass        : DKIM signature result (True/False/None)
    attachment_names : List of attachment filenames

    Returns
    -------
    dict with keys:
        risk_score      int    0–100
        verdict         str    PHISHING | LEGITIMATE
        tier            str    CRITICAL | HIGH | MEDIUM | LOW
        outlook_action  str    QUARANTINE | JUNK | FLAG | ALLOW
        roberta_prob    float  None if not available
        rule_score      float  0–100
        ai_prob         float  0–1
        header_score    int    0–100
        header_flags    list
        top_indicators  list
        scorer_used     str    roberta-fused | distilbert | heuristic
        processing_ms   int
    """
    t0 = time.time()
    _try_load_roberta()
    _ensure_fs_path()

    roberta_prob = None
    rule_score   = 0.0
    ai_prob      = 0.0
    header_score = 0
    header_norm  = 0.0
    header_flags = []
    indicators   = []
    features     = {}
    scorer_used  = "heuristic"

    # ── Layer 2: Rule-based features ─────────────────────────────────────────
    try:
        from feature_extractor import extract_features
        features   = extract_features(email_text, subject, sender)
        rule_score = min(100, (
            features.get("urgency_count",       0) * 15 +
            features.get("credential_count",    0) * 25 +
            features.get("threat_count",        0) * 20 +
            features.get("impersonation_count", 0) * 15 +
            features.get("suspicious_url_count",0) * 10 +
            features.get("domain_spoofed",      0) * 15 +
            features.get("known_phishing_domain",0) * 50
        )) / 100.0

        if features.get("urgency_count"):
            indicators.append(f"Urgency language ({features['urgency_count']} patterns)")
        if features.get("credential_count"):
            indicators.append(f"Credential request ({features['credential_count']} patterns)")
        if features.get("domain_spoofed"):
            indicators.append("Sender domain spoofing detected")
        if features.get("threat_count"):
            indicators.append("Threat language detected")
        if features.get("known_phishing_domain"):
            indicators.append("Domain in phishing blocklist (778 k domains)")
        if features.get("has_hindi_patterns"):
            indicators.append("Hindi/regional phishing patterns detected")
    except Exception as exc:
        rule_score, _ind = _rule_score_fallback(email_text, subject, sender)
        indicators.extend(_ind)
        print(f"[FraudShieldScorer] feature_extractor fallback: {exc}")

    # ── Layer 3: AI-text detection ────────────────────────────────────────────
    try:
        from ai_text_detector import detect_ai_text
        ai_result = detect_ai_text(email_text[:1500])
        ai_prob   = ai_result.get("ai_generated_probability", 0.0)
        if ai_prob > 0.6:
            indicators.append(f"AI-generated text detected ({ai_prob:.0%} probability)")
    except Exception:
        ai_prob = _ai_prob_fallback(email_text)

    # ── Layer 4: Header analysis ──────────────────────────────────────────────
    try:
        from evaluate import analyze_headers
        header_score, header_flags = analyze_headers(
            sender, receiver, reply_to, subject,
            spf_pass, dkim_pass, attachment_names or []
        )
        indicators.extend(header_flags)
    except Exception as exc:
        # Manual header checks if fraudshield-email evaluate.py unavailable
        if reply_to and sender:
            sd = sender.split("@")[-1].lower()   if "@" in sender   else ""
            rd = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
            if sd and rd and sd != rd:
                header_score = 30
                hf = f"Reply-To mismatch — sender: {sd}, replies go to: {rd}"
                header_flags.append(hf)
                indicators.append(hf)
        if spf_pass is False:
            header_score = max(header_score, 25)
            indicators.append("SPF authentication FAILED")
        if dkim_pass is False:
            header_score = max(header_score, 20)
            indicators.append("DKIM signature FAILED")
        print(f"[FraudShieldScorer] header analysis fallback: {exc}")

    header_norm  = header_score / 100.0
    hindi_boost  = 0.10 if features.get("has_hindi_patterns") else 0.0

    # ── Layer 1: RoBERTa + full score fusion ──────────────────────────────────
    if _model is not None and _tokenizer is not None:
        try:
            roberta_prob = _roberta_prob(email_text, subject)
            scorer_used  = "roberta-fused"
            final = min(1.0, (
                0.45 * roberta_prob +
                0.20 * rule_score   +
                0.15 * ai_prob      +
                0.20 * header_norm  +
                hindi_boost * rule_score
            ))
            if roberta_prob > 0.7:
                indicators.append(f"RoBERTa: {roberta_prob:.0%} phishing confidence")
        except Exception as exc:
            print(f"[FraudShieldScorer] RoBERTa inference error: {exc}")
            # Skip RoBERTa weight, redistribute to other layers
            final = min(1.0, 0.40 * rule_score + 0.20 * ai_prob + 0.40 * header_norm)
            scorer_used = "distilbert"

    # ── Fallback: DistilBERT ──────────────────────────────────────────────────
    if scorer_used != "roberta-fused":
        try:
            db_src = str(_SRC_DIR)
            if db_src not in sys.path:
                sys.path.insert(0, db_src)
            from bert_detector import DistilBertEmailDetector
            db        = DistilBertEmailDetector()
            db_result = db.predict(f"{subject}\n\n{email_text[:1500]}")
            # Parse percentage string e.g. "87.23%"
            raw_pct   = db_result["probabilities"].get("phishing", "0%")
            db_prob   = float(str(raw_pct).replace("%", "")) / 100.0
            scorer_used = "distilbert"
            final = min(1.0, (
                0.55 * db_prob    +
                0.25 * rule_score +
                0.10 * ai_prob    +
                0.10 * header_norm
            ))
        except Exception as exc:
            print(f"[FraudShieldScorer] DistilBERT fallback error: {exc}")
            scorer_used = "heuristic"
            h_prob = _heuristic_prob(email_text)
            final  = min(1.0, 0.60 * h_prob + 0.25 * rule_score + 0.10 * ai_prob + 0.05 * header_norm)

    risk = int(round(final * 100))
    tier, outlook_action = _get_tier(risk)

    # Verdict logic — mirrors fraudshield-email/src/evaluate.py
    verdict = "PHISHING" if (
        final >= 0.50 or
        (features.get("has_hindi_patterns")   and final >= 0.30) or
        (features.get("known_phishing_domain") and final >= 0.20) or
        (header_score >= 50 and (roberta_prob or 0) > 0.30)
    ) else "LEGITIMATE"

    return {
        "risk_score":     risk,
        "verdict":        verdict,
        "tier":           tier,
        "outlook_action": outlook_action,
        "roberta_prob":   round(roberta_prob, 4) if roberta_prob is not None else None,
        "rule_score":     round(rule_score * 100, 1),
        "ai_prob":        round(ai_prob, 4),
        "header_score":   header_score,
        "header_flags":   header_flags,
        "top_indicators": indicators[:8],
        "scorer_used":    scorer_used,
        "processing_ms":  round((time.time() - t0) * 1000),
    }


# ── Unified score: merge ML + LLM + rule signals ──────────────────────────────

def combine_all_scores(
    ml_fused:        dict,
    rule_result:     dict,
    llm_result:      dict,
    voice_risk_score: int = 0,
) -> dict:
    """
    Merge all four pipeline signals into a single, human-readable phishing score.

    Weights (research-backed blend):
      ML fused (RoBERTa/DistilBERT) : 45 %
      LLM analysis (Ollama qwen3)   : 30 %
      Rule-based heuristics          : 15 %
      Voice deepfake signal          : 10 %

    Returns a unified dict with:
        final_score      int    0–100
        verdict          str    PHISHING | LEGITIMATE
        tier             str    CRITICAL | HIGH | MEDIUM | LOW
        outlook_action   str    QUARANTINE | JUNK | FLAG | ALLOW
        confidence_label str    "High confidence" | "Moderate confidence" | etc.
        explanation      str    Plain-English analyst explanation
        all_signals      dict   Breakdown of each layer's contribution
        top_indicators   list   Merged, deduplicated indicators
    """
    # ── Extract individual scores (0–1) ─────────────────────────────────────
    ml_prob   = ml_fused.get("risk_score", 0) / 100.0

    rule_raw  = rule_result.get("score", 0)
    rule_prob = min(1.0, rule_raw / 100.0)

    llm_map = {
        ("FRAUD",      "HIGH"):    0.95,
        ("FRAUD",      "MEDIUM"):  0.80,
        ("FRAUD",      "LOW"):     0.65,
        ("SUSPICIOUS", "HIGH"):    0.60,
        ("SUSPICIOUS", "MEDIUM"):  0.45,
        ("SUSPICIOUS", "LOW"):     0.35,
        ("LEGITIMATE", "HIGH"):    0.05,
        ("LEGITIMATE", "MEDIUM"):  0.10,
        ("LEGITIMATE", "LOW"):     0.15,
    }
    llm_verdict    = str(llm_result.get("verdict",    "UNKNOWN")).upper()
    llm_confidence = str(llm_result.get("confidence", "LOW")).upper()
    llm_prob = llm_map.get(
        (llm_verdict, llm_confidence),
        0.50 if llm_verdict == "UNKNOWN" else 0.20
    )

    voice_prob = min(1.0, voice_risk_score / 100.0)

    # ── Weighted fusion ──────────────────────────────────────────────────────
    final_prob = (
        0.45 * ml_prob   +
        0.30 * llm_prob  +
        0.15 * rule_prob +
        0.10 * voice_prob
    )
    final_score = int(round(min(100, final_prob * 100)))
    tier, outlook_action = _get_tier(final_score)

    # ── Verdict ─────────────────────────────────────────────────────────────
    verdict = "PHISHING" if (
        final_score >= 50 or
        (llm_verdict == "FRAUD" and llm_confidence in ("HIGH", "MEDIUM")) or
        (ml_fused.get("verdict") == "PHISHING" and llm_verdict != "LEGITIMATE")
    ) else "LEGITIMATE"

    # ── Confidence label ────────────────────────────────────────────────────
    signals_agree = sum([
        ml_prob   > 0.5,
        llm_prob  > 0.5,
        rule_prob > 0.4,
    ])
    if signals_agree == 3:
        confidence_label = "High confidence — all detectors agree"
    elif signals_agree == 2:
        confidence_label = "Moderate confidence — majority of detectors agree"
    elif signals_agree == 1:
        confidence_label = "Low confidence — signals mixed, manual review advised"
    else:
        confidence_label = "Very low confidence — likely legitimate"

    # ── Plain-English explanation ────────────────────────────────────────────
    parts = []
    if ml_prob > 0.6:
        roberta = ml_fused.get("roberta_prob")
        if roberta:
            parts.append(f"The AI phishing classifier is {roberta:.0%} confident this is a phishing attempt.")
        else:
            parts.append(f"The ML model assigned a {ml_fused.get('risk_score',0)}/100 phishing score.")
    if llm_verdict == "FRAUD":
        llm_expl = llm_result.get("explanation", "")
        parts.append(f"The language model flagged this as fraud ({llm_confidence.lower()} confidence)" +
                     (f": {llm_expl[:120]}..." if len(llm_expl) > 120 else (f": {llm_expl}" if llm_expl else ".")))
    if rule_prob > 0.3:
        reasons = rule_result.get("reasons", [])
        if reasons:
            parts.append(f"Rule-based analysis found {len(reasons)} red flag(s): {'; '.join(reasons[:3])}.")
    if voice_risk_score > 50:
        parts.append(f"Voice deepfake detection scored {voice_risk_score}/100 — AI-generated audio suspected.")
    if not parts:
        parts.append("All detection layers returned low-risk signals — email appears legitimate.")

    explanation = " ".join(parts)

    # ── Merge indicators from all layers ────────────────────────────────────
    all_ind = list(ml_fused.get("top_indicators", []))
    all_ind += [r for r in rule_result.get("reasons", []) if r not in all_ind]
    all_ind += [f for f in llm_result.get("red_flags", []) if f not in all_ind]

    return {
        "final_score":     final_score,
        "verdict":         verdict,
        "tier":            tier,
        "outlook_action":  outlook_action,
        "confidence_label": confidence_label,
        "explanation":     explanation,
        "top_indicators":  all_ind[:10],
        "all_signals": {
            "ml_score":    round(ml_prob   * 100, 1),
            "llm_score":   round(llm_prob  * 100, 1),
            "rule_score":  round(rule_prob * 100, 1),
            "voice_score": voice_risk_score,
            "scorer_used": ml_fused.get("scorer_used", "heuristic"),
        },
    }
