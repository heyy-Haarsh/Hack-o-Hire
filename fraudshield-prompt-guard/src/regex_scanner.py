# src/regex_scanner.py
# Layer 1 — Fast regex + keyword detection
# Runs first, zero ML overhead, catches known patterns immediately

import re
import json
import os
import unicodedata

PATTERNS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "injection_patterns.json")

with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
    PATTERNS = json.load(f)

SEVERITY_MAP = {
    "instruction_override":    ("HIGH",     75),
    "role_override":           ("HIGH",     85),
    "system_prompt_extraction":("CRITICAL", 95),
    "authority_impersonation": ("HIGH",     80),
    "output_manipulation":     ("CRITICAL", 90),
    "jailbreak_templates":     ("MEDIUM",   55),
    "continuation_attacks":    ("MEDIUM",   45),
}

UNICODE_HOMOGLYPHS = {
    "\u0430": "a", "\u0435": "e", "\u0456": "i", "\u043e": "o",
    "\u0440": "r", "\u0441": "s", "\u0445": "x", "\u0441": "c",
    "\u00e0": "a", "\u00e8": "e", "\u00ec": "i", "\u00f2": "o",
    "\u00f9": "u", "\u00e7": "c", "\u00f1": "n",
}


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    result = []
    for ch in normalized:
        result.append(UNICODE_HOMOGLYPHS.get(ch, ch))
    cleaned = "".join(result)
    cleaned = re.sub(r"[\u200b\u200c\u200d\ufeff\u00ad]", "", cleaned)
    return cleaned


def decode_obfuscation(text: str) -> str:
    import base64
    decoded_parts = []
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for match in b64_pattern.finditer(text):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            if len(decoded) > 10 and decoded.isprintable():
                decoded_parts.append(decoded)
        except Exception:
            pass
    if decoded_parts:
        return text + " " + " ".join(decoded_parts)
    return text


def run_regex_scan(text: str) -> dict:
    normalized  = normalize_text(text)
    deobfuscated = decode_obfuscation(normalized)
    lower       = deobfuscated.lower()

    matches     = []
    max_score   = 0
    max_severity = "CLEAN"

    for category, phrases in PATTERNS.items():
        severity, score = SEVERITY_MAP.get(category, ("LOW", 20))
        for phrase in phrases:
            if phrase.lower() in lower:
                matches.append({
                    "category": category,
                    "phrase":   phrase,
                    "severity": severity,
                    "score":    score,
                })
                if score > max_score:
                    max_score    = score
                    max_severity = severity

    was_obfuscated = (deobfuscated != normalized)

    return {
        "layer":           "regex",
        "injection_score": max_score,
        "severity":        max_severity if matches else "CLEAN",
        "matches":         matches,
        "match_count":     len(matches),
        "was_obfuscated":  was_obfuscated,
        "normalized_text": normalized if was_obfuscated else None,
    }
