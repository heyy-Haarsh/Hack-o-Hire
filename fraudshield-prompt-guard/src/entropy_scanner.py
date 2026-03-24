# fraudshield-prompt-guard/src/entropy_scanner.py
# Layer 3 — Entropy and perplexity based obfuscation detection
# High entropy = possible base64/encoded injection
# Very low perplexity = templated/scripted injection attempt

import re
import math

TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{15,}")
MIN_LENGTH = 15
ENTROPY_THRESHOLD = 4.0   # above this = likely encoded
PERPLEXITY_LOW    = 15.0  # below this = too templated (injection script)


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


def run_entropy_scan(text: str) -> dict:
    """
    Detect obfuscated injections via entropy analysis.
    High entropy tokens suggest base64/encoded payloads.
    """
    findings      = []
    max_entropy   = 0.0
    seen          = set()

    for token in TOKEN_RE.findall(text):
        if len(token) < MIN_LENGTH or token in seen:
            continue
        seen.add(token)
        score = shannon_entropy(token)
        if score >= ENTROPY_THRESHOLD:
            max_entropy = max(max_entropy, score)
            findings.append({
                "token_preview": token[:8] + "...",
                "entropy":       score,
                "length":        len(token),
                "risk":          "HIGH" if score >= 5.0 else "MEDIUM",
            })

    # Score based on highest entropy found
    if max_entropy >= 5.5:
        injection_score = 80
    elif max_entropy >= 5.0:
        injection_score = 60
    elif max_entropy >= 4.5:
        injection_score = 40
    elif max_entropy >= 4.0:
        injection_score = 20
    else:
        injection_score = 0

    return {
        "layer":              "entropy",
        "injection_score":    injection_score,
        "max_entropy":        max_entropy,
        "high_entropy_count": len(findings),
        "findings":           findings[:5],  # top 5 only
    }
