import re
import hashlib
import json
import os

PATTERNS_FILE = os.path.join(os.path.dirname(__file__), "patterns.json")


def load_patterns() -> dict:
    if not os.path.exists(PATTERNS_FILE):
        print(f"WARNING: patterns.json not found")
        return {}
    try:
        with open(PATTERNS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"Loaded {len(data)} patterns from patterns.json")
        return data
    except json.JSONDecodeError as e:
        print(f"ERROR: patterns.json invalid: {e}")
        return {}


CREDENTIAL_PATTERNS = load_patterns()


def redact(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 12)


def hash_value(value: str) -> str:
    return hashlib.sha256(value.strip().encode()).hexdigest()


def run_regex_scan(text: str) -> list:
    findings = []
    seen = set()
    for name, cfg in CREDENTIAL_PATTERNS.items():
        try:
            for match in re.finditer(cfg["regex"], text):
                raw = match.group(0)
                if len(raw.strip()) < 4:
                    continue
                h = hash_value(raw)
                if h in seen:
                    continue
                seen.add(h)
                s = max(0, match.start() - 60)
                e = min(len(text), match.end() + 60)
                snippet = text[s:e].replace(raw, redact(raw))
                findings.append({
                    "layer":           "regex",
                    "credential_type": name,
                    "description":     cfg["desc"],
                    "risk_tier":       cfg["risk"],
                    "category":        cfg.get("category", "general"),
                    "redacted_value":  redact(raw),
                    "value_hash":      h,
                    "context_snippet": snippet.strip(),
                    "char_position":   match.start(),
                    "confidence":      0.90,
                })
        except re.error as e:
            print(f"Bad regex '{name}': {e}")
            continue
    return findings


def reload_patterns():
    global CREDENTIAL_PATTERNS
    CREDENTIAL_PATTERNS = load_patterns()
    return len(CREDENTIAL_PATTERNS)