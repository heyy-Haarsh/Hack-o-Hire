# src/yara_scanner.py
# Layer 1b — YARA rule matching
# Complements regex with structured rule sets

import yara
import os

RULES_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "injection.yar")

_rules = None

def load_rules():
    global _rules
    if _rules is None:
        try:
            _rules = yara.compile(filepath=RULES_FILE)
            print("[yara] Rules loaded from", RULES_FILE)
        except Exception as e:
            print(f"[yara] WARNING: Could not load rules: {e}")
            _rules = None
    return _rules


SEVERITY_SCORE = {
    "CRITICAL": 90,
    "HIGH":     75,
    "MEDIUM":   50,
    "LOW":      25,
}


def run_yara_scan(text: str) -> dict:
    rules = load_rules()
    if rules is None:
        return {
            "layer":           "yara",
            "injection_score": 0,
            "severity":        "CLEAN",
            "matches":         [],
            "error":           "YARA rules not loaded"
        }

    try:
        matches = rules.match(data=text.encode("utf-8", errors="ignore"))
    except Exception as e:
        return {
            "layer":           "yara",
            "injection_score": 0,
            "severity":        "CLEAN",
            "matches":         [],
            "error":           str(e)
        }

    if not matches:
        return {
            "layer":           "yara",
            "injection_score": 0,
            "severity":        "CLEAN",
            "matches":         [],
        }

    results    = []
    max_score  = 0
    max_sev    = "CLEAN"

    for match in matches:
        severity = match.meta.get("severity", "MEDIUM")
        category = match.meta.get("category", "unknown")
        score    = SEVERITY_SCORE.get(severity, 50)

        results.append({
            "rule":     match.rule,
            "severity": severity,
            "category": category,
            "score":    score,
        })

        if score > max_score:
            max_score = score
            max_sev   = severity

    return {
        "layer":           "yara",
        "injection_score": max_score,
        "severity":        max_sev,
        "matches":         results,
        "match_count":     len(results),
    }
