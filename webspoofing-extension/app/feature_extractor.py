"""
feature_extractor.py – Converts a raw URL string into a fixed-length
numerical feature vector, entirely offline.

Libraries used: urllib, tldextract, re, hashlib — no network calls.
"""
from __future__ import annotations

import hashlib
import math
import re
import socket
import dataclasses
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

import tldextract

from app.logger import logger


# ── Suspicious signals ─────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = {
    "login", "secure", "verify", "update", "confirm", "account",
    "banking", "paypal", "signin", "password", "credential", "wallet",
    "ebay", "amazon", "support", "service", "free", "bonus", "prize",
    "alert", "suspended", "urgent", "invoice", "webscr",
}

# High-risk TLDs often used for free/low-cost phishing domains
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".info", ".biz", ".ru", ".cn", ".pw",
}

# Common paths and structures used in phishing kits
PHISHING_PATH_PATTERNS = {
    "wp-content", "well-known", "index.php", "login.php", "signin.php",
    "verification", "validate", "secure-login", "account-update",
}

_IP_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


# ── Feature dataclass ──────────────────────────────────────────────────────────

@dataclass
class URLFeatures:
    url_length: int = 0
    num_dots: int = 0
    num_hyphens: int = 0
    num_at: int = 0
    num_slashes: int = 0
    num_query_params: int = 0
    has_https: int = 0
    has_ip: int = 0
    has_at_symbol: int = 0
    suspicious_keywords: int = 0
    num_subdomains: int = 0
    tld_suspicious: int = 0
    domain_length: int = 0
    path_length: int = 0
    has_port: int = 0
    port_number: int = 0
    double_slash_redirect: int = 0
    prefix_suffix: int = 0
    digit_ratio: float = 0.0
    entropy: float = 0.0
    
    # --- New Advanced Features ---
    num_digits_domain: int = 0
    num_digits_path: int = 0
    num_special_chars: int = 0  # _, ~, ,, ;, etc.
    is_shortened: int = 0      # bit.ly, etc.
    brand_mimicry: int = 0      # looks like 'g00gle' or 'paypa1'
    tld_rarity: int = 0         # ranking of how 'rare/cheap' the TLD is
    num_phishing_path_patterns: int = 0 # matches for things like /wp-content/login.php

    def to_list(self) -> list[float]:
        return [
            float(self.url_length), float(self.num_dots), float(self.num_hyphens),
            float(self.num_at), float(self.num_slashes), float(self.num_query_params),
            float(self.has_https), float(self.has_ip), float(self.has_at_symbol),
            float(self.suspicious_keywords), float(self.num_subdomains),
            float(self.tld_suspicious), float(self.domain_length),
            float(self.path_length), float(self.has_port), float(self.port_number),
            float(self.double_slash_redirect), float(self.prefix_suffix),
            float(self.digit_ratio), float(self.entropy),
            # New ones
            float(self.num_digits_domain), float(self.num_digits_path),
            float(self.num_special_chars), float(self.is_shortened),
            float(self.brand_mimicry), float(self.tld_rarity),
            float(self.num_phishing_path_patterns)
        ]

    def to_dict(self) -> dict[str, float]:
        return {k: float(v) for k, v in self.__dict__.items() if not k.startswith('_')}

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "url_length", "num_dots", "num_hyphens", "num_at", "num_slashes",
            "num_query_params", "has_https", "has_ip", "has_at_symbol",
            "suspicious_keywords", "num_subdomains", "tld_suspicious",
            "domain_length", "path_length", "has_port", "port_number",
            "double_slash_redirect", "prefix_suffix", "digit_ratio", "entropy",
            "num_digits_domain", "num_digits_path", "num_special_chars",
            "is_shortened", "brand_mimicry", "tld_rarity", "num_phishing_path_patterns"
        ]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_ip_address(hostname: str) -> bool:
    try:
        socket.inet_aton(hostname)
        return True
    except OSError:
        return bool(_IP_PATTERN.match(hostname))


def _count_suspicious_keywords(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


# ── Main extractor ─────────────────────────────────────────────────────────────

class FeatureExtractor:
    """Offline URL feature extractor – no network calls."""

    def extract(self, url: str) -> URLFeatures:
        """
        Extract features from a URL string.

        Parameters
        ----------
        url : str
            The URL to analyse (must start with http:// or https://).

        Returns
        -------
        URLFeatures
            Dataclass with all numerical features populated.
        """
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            return self._extract_safe(url)
        except Exception as exc:
            import traceback
            logger.error(f"Feature extraction failed for {url!r}: {exc}")
            logger.debug(traceback.format_exc())
            # Re-raise or return empty? 
            # In data_ingestion we catch it, but we need to know WHY it fails.
            raise exc

    def _extract_safe(self, url: str) -> URLFeatures:
        parsed = urlparse(url)
        ext = tldextract.extract(url)

        hostname = parsed.hostname or ""
        path = parsed.path or ""
        full_domain = parsed.netloc or ""

        features = URLFeatures()

        # Basic length metrics
        features.url_length = len(url)
        features.num_dots = url.count(".")
        features.num_hyphens = url.count("-")
        features.num_at = url.count("@")
        features.num_slashes = url.count("/")
        features.path_length = len(path)
        features.domain_length = len(ext.domain)

        # Query params
        features.num_query_params = len(parse_qs(parsed.query))

        # Protocol
        features.has_https = int(parsed.scheme == "https")

        # IP-based host
        features.has_ip = int(_is_ip_address(hostname))

        # @ in URL (credential harvesting trick)
        features.has_at_symbol = int("@" in url)

        # Suspicious keywords
        features.suspicious_keywords = _count_suspicious_keywords(url)

        # Subdomains
        subdomain_parts = [p for p in ext.subdomain.split(".") if p]
        features.num_subdomains = len(subdomain_parts)

        # TLD check
        tld = f".{ext.suffix}" if ext.suffix else ""
        features.tld_suspicious = int(tld.lower() in SUSPICIOUS_TLDS)

        # Port
        if parsed.port is not None:
            features.has_port = 1
            features.port_number = int(str(parsed.port))
        else:
            features.has_port = 0
            features.port_number = 0

        # Double-slash redirect (e.g. http://legit.com//evil.com)
        features.double_slash_redirect = int("//" in path)

        # Prefix-suffix in domain (e.g. paypal-secure.com)
        # Refinement: avoid false positives for simple names like 'moms-bakery'.
        # Phishing often uses multiple hyphens (e.g. apple-support-verify.com) 
        # or combines a hyphen with a suspicious keyword (e.g. paypal-login.com).
        domain_parts = ext.domain.split("-")
        has_suspicious_part = any(p in SUSPICIOUS_KEYWORDS for p in domain_parts)
        features.prefix_suffix = int(ext.domain.count("-") >= 2 or (("-" in ext.domain) and has_suspicious_part))

        # Digit ratio in full URL
        digits = sum(1 for c in url if c.isdigit())
        features.digit_ratio = digits / len(url) if url else 0.0

        # --- NEW ADVANCED FEATURES EXTRACTION ---
        # 1. Digits in domain vs path
        features.num_digits_domain = sum(1 for c in ext.domain if c.isdigit())
        features.num_digits_path = sum(1 for c in path if c.isdigit())

        # 2. Special characters
        special_chars = set("_~,;!$")
        features.num_special_chars = sum(1 for c in url if c in special_chars)

        # 3. URL Shorteners
        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "bit.do"}
        features.is_shortened = int(f"{ext.domain}.{ext.suffix}" in shorteners)

        # 4. Brand Mimicry (Typosquatting)
        # Check if the domain name looks like a top brand but isn't
        top_brands = ["google", "apple", "facebook", "microsoft", "amazon", "paypal", "netflix", "ebay", "chase", "barclays"]
        brand_mimicry_detected = 0
        domain_lower = ext.domain.lower()
        if domain_lower not in top_brands:
            for brand in top_brands:
                # If domain contains the brand name but isn't the brand domain (e.g. 'paypal-secure')
                # or if it's 1-2 characters different (e.g. 'paypa1')
                if brand in domain_lower:
                    brand_mimicry_detected = 1
                    break
                # Simple distance check for similar length
                if abs(len(domain_lower) - len(brand)) <= 1:
                    diff_chars = sum(1 for a, b in zip(domain_lower, brand) if a != b)
                    if diff_chars <= 1:
                        brand_mimicry_detected = 1
                        break
        features.brand_mimicry = brand_mimicry_detected

        # 5. TLD Rarity Score (Binary for now, can be weighted)
        features.tld_rarity = int(tld.lower() in SUSPICIOUS_TLDS)

        # 6. Phishing Path Patterns
        path_lower = path.lower()
        features.num_phishing_path_patterns = sum(1 for pat in PHISHING_PATH_PATTERNS if pat in path_lower)

        # Shannon entropy on the full URL
        features.entropy = _shannon_entropy(url)

        return features


# Singleton for import convenience
extractor = FeatureExtractor()
