import re
import math
from patterns import redact, hash_value

ENTROPY_THRESHOLD = 4.2
MIN_LENGTH        = 20
TOKEN_RE          = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return round(
        -sum((c / length) * math.log2(c / length)
             for c in freq.values()), 3
    )


def run_entropy_scan(text: str) -> list:
    findings = []
    seen = set()
    for token in TOKEN_RE.findall(text):
        if len(token) < MIN_LENGTH:
            continue
        score = shannon_entropy(token)
        if score < ENTROPY_THRESHOLD:
            continue
        h = hash_value(token)
        if h in seen:
            continue
        seen.add(h)
        pos     = text.find(token)
        s       = max(0, pos - 60)
        e       = min(len(text), pos + len(token) + 60)
        snippet = text[s:e].replace(token, redact(token))
        risk    = ("Critical" if score >= 5.5
                   else "High" if score >= 5.0
                   else "Medium")
        conf    = (0.85 if score >= 5.5
                   else 0.75 if score >= 5.0
                   else 0.60)
        findings.append({
            "layer":           "entropy",
            "credential_type": "high_entropy_token",
            "description":     f"High-entropy string (score {score}) — likely a secret",
            "risk_tier":       risk,
            "category":        "unknown_secret",
            "redacted_value":  redact(token),
            "value_hash":      h,
            "context_snippet": snippet.strip(),
            "char_position":   pos,
            "confidence":      conf,
            "entropy_score":   score,
        })
    return findings