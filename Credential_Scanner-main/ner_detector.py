import re
import nltk
from nltk import word_tokenize, pos_tag, ne_chunk
from nltk.tree import Tree
from patterns import redact, hash_value

# Expanded keyword list — now catches names in welcome/regards sections
CRED_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "token", "key",
    "pin", "otp", "cvv", "account number", "card number",
    "sort code", "iban", "api key", "auth", "credential",
    "login", "passphrase", "access key",
    "welcome", "dear", "confidential", "username",
    "system access", "details", "induction", "regards",
    "access details", "please find", "as discussed",
    "please keep", "do not share","verification","code","initiated",
"re-verification", "suspended", "blocked", "closure",
"confirm", "validate", "verify",
]

SENSITIVE_PATTERNS = [
    r"(?i)(your|my|the)\s+(password|pin|otp|token)\s+(is|was|:)\s+\S+",
    r"(?i)(please|kindly)\s+(use|enter)\s+(otp|pin|password)\s*[:]\s*\d+",
    r"(?i)credentials?\s*[:=]\s*\S+",
    r"(?i)login\s+(details?|info)\s*[:]\s*\S+",
    r"(?i)(maiden|mother.?s)\s+name\s+(is|was|:)\s+\S+",
    r"(?i)date\s+of\s+birth\s*(is|was|:)\s*[\d\/\-]+",
    r"(?i)passport\s+(number|no)?\s*(is|:)\s*[A-Z0-9]+",
    r"(?i)sort\s+code\s*(is|:)\s*[\d\-]+",
    r"(?i)account\s+(number|no)\s*(is|:)\s*[\d]+",
]


def get_entities(text: str) -> list:
    entities = []
    try:
        tokens  = word_tokenize(text)
        tagged  = pos_tag(tokens)
        chunked = ne_chunk(tagged)
        for subtree in chunked:
            if isinstance(subtree, Tree):
                label       = subtree.label()
                entity_text = " ".join(w for w, t in subtree.leaves())
                entities.append((entity_text, label))
    except Exception:
        pass
    return entities


def run_ner_scan(text: str) -> list:
    findings = []
    seen     = set()
    offset   = 0

    # Split into paragraphs and scan each one
    for para in text.split("\n"):
        if not para.strip():
            offset += len(para) + 1
            continue

        para_lower = para.lower()

        # Check if paragraph contains any credential keyword
        has_keyword = any(kw in para_lower for kw in CRED_KEYWORDS)

        if has_keyword:
            for raw, label in get_entities(para[:5000]):
                raw = raw.strip()
                if len(raw) < 3:
                    continue
                h = hash_value(raw)
                if h in seen:
                    continue
                seen.add(h)

                # Assign risk based on entity type
                if label == "PERSON":
                    risk = "Low"
                    desc = f"Person name near credential context (PII exposure)"
                elif label == "ORGANIZATION":
                    risk = "Low"
                    desc = f"Organisation name in credential context"
                elif label == "GPE":
                    risk = "Low"
                    desc = f"Location in credential context"
                else:
                    risk = "Low"
                    desc = f"Named entity ({label}) in credential context"

                findings.append({
                    "layer":           "ner",
                    "credential_type": f"ner_{label.lower()}",
                    "description":     desc,
                    "risk_tier":       risk,
                    "category":        "named_entity",
                    "redacted_value":  redact(raw) if len(raw) > 4 else "****",
                    "value_hash":      h,
                    "context_snippet": para[:200],
                    "char_position":   offset,
                    "confidence":      0.65,
                })

        offset += len(para) + 1

    # Sensitive sentence pattern matching
    for pattern in SENSITIVE_PATTERNS:
        for match in re.finditer(pattern, text):
            raw = match.group(0)
            h   = hash_value(raw)
            if h in seen:
                continue
            seen.add(h)
            s = max(0, match.start() - 40)
            e = min(len(text), match.end() + 40)
            findings.append({
                "layer":           "ner",
                "credential_type": "sensitive_sentence",
                "description":     "Sentence strongly suggests credential exposure",
                "risk_tier":       "High",
                "category":        "credential",
                "redacted_value":  redact(raw),
                "value_hash":      h,
                "context_snippet": text[s:e],
                "char_position":   match.start(),
                "confidence":      0.80,
            })

    return findings