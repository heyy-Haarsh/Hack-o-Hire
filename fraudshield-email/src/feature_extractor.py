# src/feature_extractor.py
import re
import sys
from pathlib import Path
import tldextract
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import warnings
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

sys.path.insert(0, str(Path(__file__).parent))
from domain_blocklist import is_known_phishing_domain

# ── Phishing language patterns ─────────────────────────────────────
URGENCY_PATTERNS = [
    r"urgent(ly)?", r"immediately", r"right now", r"act now",
    r"account.{0,20}(suspend|block|close|terminat)",
    r"within \d+ (hours?|minutes?|days?)",
    r"verify.{0,20}(now|immediately|today)",
    r"limited time", r"expires? (today|soon)",
    r"last (chance|warning|notice)",
]

CREDENTIAL_PATTERNS = [
    r"(enter|provide|confirm|update).{0,20}(password|pin|credentials)",
    r"card.{0,20}(number|details|information)",
    r"(social security|ssn|national insurance)",
    r"(cvv|cvc|security code)",
    r"(one.?time.?password|otp)",
    r"(username|user id).{0,20}(enter|provide|update)",
    r"(bank|account).{0,20}(details|information|number)",
]

THREAT_PATTERNS = [
    r"(legal|police|authorities).{0,30}(action|contact|involve)",
    r"(fine|penalty|charge).{0,20}(£|\$|\d+)",
    r"\barrest\b", r"lawsuit", r"criminal charges",
    r"account.{0,20}(deleted|terminated|permanently)",
]

IMPERSONATION_PATTERNS = [
    r"\b(barclays|lloyds|hsbc|natwest|santander)\b",
    r"(amazon|paypal|apple|microsoft|google).{0,20}(security|account|verify)",
    r"(hmrc|irs|tax).{0,20}(refund|payment|outstanding)",
    r"(your bank|your account|dear customer|dear valued)",
    r"micros0ft|arnazon|paypa1|app1e", 
]

HINDI_URGENCY = [
    r"turant", r"abhi verify", r"jaldi karo",
    r"(account|khata).{0,20}band", r"24 ghante",
]

HINDI_CREDENTIAL = [
    r"(card|atm).{0,20}(number|nambar|detail)",
    r"(pin|password).{0,20}(batao|dijiye|share)",
    r"otp.{0,20}(share|batao|bhejo|dijiye)",
]


def extract_urls(text: str) -> list:
    return re.findall(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", text)


def check_url_suspicious(url: str) -> dict:
    try:
        extracted = tldextract.extract(url)
        return {
            "uses_ip":        bool(re.match(r"\d+\.\d+\.\d+\.\d+",
                                            extracted.domain)),
            "is_shortened":   extracted.domain in [
                                "bit", "tinyurl", "t", "goo",
                                "ow", "rb", "is", "tiny"],
            "has_at_sign":    "@" in url,
            "subdomain_deep": (len(extracted.subdomain.split(".")) > 2
                               if extracted.subdomain else False),
            "suspicious_tld": extracted.suffix in [
                                "xyz", "top", "click", "work",
                                "loan", "tk", "ml", "ga", "cf"],
            "registered_domain": extracted.top_domain_under_public_suffix,
        }
    except Exception:
        return {
            "uses_ip": False, "is_shortened": False,
            "has_at_sign": False, "subdomain_deep": False,
            "suspicious_tld": False, "registered_domain": ""
        }


def count_pattern(text: str, patterns: list) -> int:
    text_lower = text.lower()
    return sum(1 for p in patterns if re.search(p, text_lower))


def extract_features(email_text: str,
                     subject: str = "",
                     sender:  str = "") -> dict:
    """
    Extract 28+ interpretable features from a raw email.
    Returns dict of feature_name → numeric value.
    """
    full_text  = f"{subject} {email_text}"
    text_lower = full_text.lower()
    words      = full_text.split()

    # URL analysis
    urls       = extract_urls(full_text)
    url_checks = [check_url_suspicious(u) for u in urls[:10]]

    # Blocklist check — known phishing domains
    blocklist_hits = sum(
        1 for uc in url_checks
        if uc.get("registered_domain") and
        is_known_phishing_domain(uc["registered_domain"])
    )

    # Text statistics
    caps_ratio = (sum(1 for c in full_text if c.isupper()) /
                  max(len(full_text), 1))

    # Sender domain analysis
    sender_domain   = sender.split("@")[-1].lower() if "@" in sender else ""
    trusted_domains = [
        "barclays.com", "lloyds.com", "hsbc.co.uk",
        "amazon.co.uk", "gov.uk", "hmrc.gov.uk"
    ]
    domain_spoofed = any(
        brand in text_lower and brand not in sender_domain
        for brand in ["barclays", "amazon", "paypal",
                      "apple", "hmrc", "lloyds"]
    )

    return {
        # Pattern counts
        "urgency_count":          count_pattern(full_text, URGENCY_PATTERNS),
        "credential_count":       count_pattern(full_text, CREDENTIAL_PATTERNS),
        "threat_count":           count_pattern(full_text, THREAT_PATTERNS),
        "impersonation_count":    count_pattern(full_text, IMPERSONATION_PATTERNS),
        "hindi_urgency_count":    count_pattern(full_text, HINDI_URGENCY),
        "hindi_credential_count": count_pattern(full_text, HINDI_CREDENTIAL),

        # URL features
        "url_count":              len(urls),
        "suspicious_url_count":   sum(
            any(v for k, v in u.items() if k != "registered_domain")
            for u in url_checks
        ),
        "ip_url_count":           sum(u["uses_ip"] for u in url_checks),
        "shortened_url_count":    sum(u["is_shortened"] for u in url_checks),
        "suspicious_tld_count":   sum(u["suspicious_tld"] for u in url_checks),

        # Blocklist
        "known_phishing_domain":  1 if blocklist_hits > 0 else 0,
        "blocklist_hit_count":    blocklist_hits,

        # Text statistics
        "caps_ratio":             round(caps_ratio, 4),
        "exclamation_count":      full_text.count("!"),
        "question_count":         full_text.count("?"),
        "word_count":             len(words),
        "html_present":           1 if (
            "<html" in text_lower or "<body" in text_lower
        ) else 0,

        # Sender features
        "domain_spoofed":         1 if domain_spoofed else 0,
        "sender_is_trusted":      1 if sender_domain in trusted_domains else 0,

        # Derived binary signals
        "has_credential_request": 1 if count_pattern(
            full_text, CREDENTIAL_PATTERNS) > 0 else 0,
        "has_urgency":            1 if count_pattern(
            full_text, URGENCY_PATTERNS) > 0 else 0,
        "has_threats":            1 if count_pattern(
            full_text, THREAT_PATTERNS) > 0 else 0,
        "has_impersonation":      1 if count_pattern(
            full_text, IMPERSONATION_PATTERNS) > 0 else 0,
        "has_hindi_patterns":     1 if count_pattern(
            full_text, HINDI_URGENCY + HINDI_CREDENTIAL) > 0 else 0,
    }


if __name__ == "__main__":
    samples = [
        ("Hi team, Q3 report attached. Review by Friday.",
         "", "john@barclays.com"),
        ("URGENT: Your Barclays account suspended. Verify card details at "
         "http://barclays-secure.xyz or face legal action.",
         "Account Suspended", "security@barclays-secure.xyz"),
        ("Aapka account band ho jayega. Abhi apna OTP share karo.",
         "Urgent Notice", "info@fake-bank.tk"),
    ]
    for text, subject, sender in samples:
        feats = extract_features(text, subject, sender)
        score = min(100,
            feats["urgency_count"]          * 15 +
            feats["credential_count"]       * 25 +
            feats["threat_count"]           * 20 +
            feats["impersonation_count"]    * 15 +
            feats["domain_spoofed"]         * 15 +
            feats["known_phishing_domain"]  * 50
        )
        print(f"\nText   : {text[:60]}...")
        print(f"Score  : {score}/100")
        print(f"urgency={feats['urgency_count']}  "
              f"credential={feats['credential_count']}  "
              f"threat={feats['threat_count']}  "
              f"blocklist={feats['known_phishing_domain']}  "
              f"hindi={feats['has_hindi_patterns']}")