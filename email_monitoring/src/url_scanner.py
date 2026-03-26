"""
url_scanner.py — PhishGuard Full-Pipeline URL Scanner
======================================================
Complete 6-check analysis pipeline matching flask_api.py's run_full_analysis().

Pipeline:
  Step 1: XGBoost ML classification  (phishguard.predictor)
  Step 2: SSL/TLS certificate check  (phishguard.ssl_checker)
  Step 3: WHOIS domain age           (phishguard.whois_checker)
  Step 4: HTTP cookie inspection     (requests + phishguard.cookie_detector)
  Step 5: URL encoding analysis      (offline, instant)
  Step 6: HTML content analysis      (phishguard.html_analyzer)

Output format matches flask_api.py so the same rendering logic works for both
the web dashboard and the email-monitoring Streamlit UI.
"""
from __future__ import annotations

import hashlib
import time
import ssl
import socket
import urllib.parse
import warnings
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

warnings.filterwarnings("ignore")

# ── Lazy-load PhishGuard modules (avoids circular imports at load time) ────────
_predictor = None

def _get_predictor():
    global _predictor
    if _predictor is None:
        from phishguard.predictor import Predictor
        _predictor = Predictor()
    return _predictor


# ── URL normalisation helpers ──────────────────────────────────────────────────

def _normalise(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        return "https://" + url
    return url

def _domain(url: str) -> str:
    return urlparse(_normalise(url)).netloc.split(":")[0]

def _tld(url: str) -> str:
    parts = _domain(url).rsplit(".", 2)
    return "." + parts[-1] if parts else ""


# ── Offline metric extraction ──────────────────────────────────────────────────

def _url_format_analysis(url: str) -> dict:
    """
    Comprehensive URL format analysis — 15 metrics, all offline.
    Inspired by: IEEE Transactions on Information Forensics 2021.
    """
    parsed   = urlparse(url)
    netloc   = parsed.netloc
    path     = parsed.path
    query    = parsed.query
    fragment = parsed.fragment

    # Readability score: human-typed URLs are short, lowercase, recognisable
    words_in_path = re.findall(r'[a-zA-Z]{4,}', path)
    has_brand_words = any(w.lower() in (
        "login","secure","verify","account","update","confirm","bank",
        "paypal","amazon","apple","google","microsoft","netflix","barclays"
    ) for w in words_in_path)

    return {
        "scheme":              parsed.scheme,
        "domain":              netloc,
        "path":                path or "/",
        "query_string":        query,
        "fragment":            fragment,
        "path_depth":          len([p for p in path.split("/") if p]),
        "query_param_count":   len(urllib.parse.parse_qs(query)),
        "has_fragment":        bool(fragment),
        "has_brand_keywords":  has_brand_words,
        "path_word_count":     len(words_in_path),
        "readability_score":   min(10, len(words_in_path) * 2),    # 0–10, higher = more readable
        "uses_https":          parsed.scheme == "https",
        "has_port":            ":" in netloc and netloc.split(":")[-1].isdigit(),
        "is_ip_address":       bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", netloc.split(":")[0])),
        "url_length":          len(url),
    }


def _compute_fingerprint(url: str) -> str:
    """
    Structural fingerprint: hash of the normalised URL skeleton
    (scheme + domain pattern + path template), to match known phishing campaigns.
    e.g. paypa1.net/login → same fingerprint as paypa1.net/verify
    """
    parsed = urlparse(url)
    # Replace variable parts: digits, random strings, UUIDs
    domain_clean = re.sub(r'\d+', 'N', parsed.netloc.lower())
    path_clean   = re.sub(r'[a-f0-9]{8,}', 'HASH', parsed.path.lower())
    path_clean   = re.sub(r'\d+', 'N', path_clean)
    skeleton = f"{parsed.scheme}://{domain_clean}{path_clean}"
    return hashlib.sha256(skeleton.encode()).hexdigest()[:16]


def _check_encoding(url: str) -> dict:
    decoded        = urllib.parse.unquote(url)
    double_decoded = urllib.parse.unquote(decoded)
    issues = []
    if decoded != url:
        issues.append("URL uses percent-encoding (possible obfuscation)")
    if double_decoded != decoded:
        issues.append("Double URL-encoding detected — high obfuscation risk")
    for enc in ["%00", "%0d", "%0a", "%2e%2e", "%252e", "%2f%2e%2e"]:
        if enc in url.lower():
            issues.append(f"Dangerous encoded sequence: {enc}")
    return {
        "is_encoded": decoded != url,
        "is_double_encoded": double_decoded != decoded,
        "decoded_url": decoded,
        "issues": issues,
    }


# ── Network enrichment using phishguard modules ───────────────────────────────

def _pg_ssl(domain: str) -> dict:
    """SSL check using phishguard.ssl_checker."""
    try:
        from phishguard.ssl_checker import check_ssl
        return check_ssl(domain)
    except Exception as e:
        return {"valid": False, "issuer": "Unknown", "subject": domain,
                "expires_in_days": 0, "status": "error", "error": str(e)[:80]}


def _pg_whois(domain: str) -> dict:
    """WHOIS check using phishguard.whois_checker."""
    try:
        from phishguard.whois_checker import check_whois
        return check_whois(domain)
    except Exception as e:
        return {"age_days": 0, "registrar": "Unknown", "creation_date": "Unknown",
                "expiration_date": "Unknown", "country": "Unknown",
                "domain_resolvable": False, "status": "error", "error": str(e)[:80]}


def _pg_html(url: str) -> dict:
    """HTML analysis using phishguard.html_analyzer."""
    try:
        from phishguard.html_analyzer import analyze_html
        return analyze_html(url)
    except Exception as e:
        return {"has_password_input": False, "has_login_form": False, "has_iframe": False,
                "has_hidden_elements": False, "external_form_action": False,
                "suspicious_scripts": 0, "favicon_mismatch": False,
                "risk_flags": [], "error": str(e)[:80]}


def _check_server_cookies(url: str) -> dict:
    """Fetch URL cookies from HTTP response and inspect for security issues."""
    try:
        import requests as _req
        resp = _req.get(url, timeout=6, allow_redirects=True, verify=False,
                        headers={"User-Agent": "Mozilla/5.0 PhishGuard/2.0"})
        issues, cookie_details = [], []
        for c in resp.cookies:
            httponly = (c.has_nonstandard_attr("HttpOnly") or
                        c.has_nonstandard_attr("httponly"))
            info = {
                "name": c.name, "secure": c.secure, "httponly": httponly,
                "samesite": c.get_nonstandard_attr("SameSite", "Not Set"),
            }
            if not c.secure and url.startswith("https"):
                issues.append(f"{c.name}: Missing Secure flag")
            if not httponly and any(k in c.name.lower() for k in
                                    ["session","auth","token","id","sid"]):
                issues.append(f"{c.name}: Missing HttpOnly flag")
            cookie_details.append(info)

        status = "no_cookies" if len(resp.cookies) == 0 else (
                 "issues_found" if issues else "ok")
        return {"total_cookies": len(resp.cookies), "issues": issues,
                "cookie_details": cookie_details, "risk": bool(issues),
                "status": status, "error": ""}
    except Exception as e:
        return {"total_cookies": 0, "issues": [], "cookie_details": [],
                "risk": False, "status": "unreachable",
                "error": f"{type(e).__name__}: {str(e)[:60]}"}


# ── Risk aggregation ───────────────────────────────────────────────────────────

_SUSPICIOUS_TLD  = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",
                    ".online",".site",".info",".biz",".ru",".cn",".pw",".cc",".ws"}
_TRUSTED_DOMAINS = {"google.com","youtube.com","microsoft.com","apple.com",
                    "amazon.com","facebook.com","linkedin.com","barclays.co.uk",
                    "barclays.com","github.com","paypal.com","gov.uk"}

def _aggregate_risk(ml: dict, enc: dict, ssl_r: dict, whois_r: dict,
                    url_fmt: dict, html_r: Optional[dict] = None,
                    cookie_r: Optional[dict] = None) -> tuple[str, float, list[str]]:
    """Combine all 6 pipeline signals into a risk score 0-1 and verdict."""
    score, reasons = 0.0, []
    html_r   = html_r   or {}
    cookie_r = cookie_r or {}

    # Weight 1: ML model (primary, 45%)
    ml_prob = ml.get("probability", 0.5)
    score  += ml_prob * 0.45
    if ml.get("label") == "phishing":
        reasons.append(f"XGBoost ML: {ml_prob:.0%} phishing probability")
        reasons.extend(ml.get("risk_factors", [])[:3])
    elif ml.get("label") == "suspicious":
        reasons.append(f"XGBoost ML: URL pattern suspicious ({ml_prob:.0%})")

    # Weight 2: SSL/TLS (15%)
    ssl_status = ssl_r.get("status", "")
    days_left  = ssl_r.get("expires_in_days", ssl_r.get("days_remaining", 365))
    if ssl_status in ("invalid", "error"):
        score += 0.15; reasons.append("SSL certificate invalid or untrusted")
    elif ssl_status in ("no_https", "no_ssl"):
        score += 0.10; reasons.append("No HTTPS — traffic is unencrypted")
    elif isinstance(days_left, (int, float)) and 0 <= days_left < 14:
        score += 0.08; reasons.append(f"SSL expires in {days_left} days")

    # Weight 3: Domain age (15%) — only penalize if WHOIS succeeded
    age    = whois_r.get("age_days", -1)
    w_stat = whois_r.get("status", "unknown")
    w_ok   = w_stat not in ("dns_failed", "whois_failed", "error", "skipped", "unknown")
    if w_ok and 0 <= age < 30:
        score += 0.15; reasons.append(f"Domain only {age} days old — freshly registered")
    elif w_ok and 30 <= age < 90:
        score += 0.10; reasons.append(f"Domain registered {age} days ago (suspicious)")
    elif w_ok and 90 <= age < 180:
        score += 0.05; reasons.append(f"Domain is {age} days old (relatively new)")

    # Weight 4: HTML content analysis (15%)
    if html_r.get("external_form_action"):
        score += 0.15; reasons.append("Form submits to external domain — credential harvest risk")
    if html_r.get("has_login_form") and html_r.get("has_password_input"):
        score += 0.10; reasons.append("Login form with password field detected on page")
    if html_r.get("has_iframe"):
        score += 0.05; reasons.append("Hidden iframes found — possible content injection")
    sc = html_r.get("suspicious_scripts", 0)
    if isinstance(sc, (int, float)) and sc > 2:
        score += 0.05; reasons.append(f"{sc} suspicious script(s) detected")
    reasons.extend(html_r.get("risk_flags", [])[:2])

    # Weight 5: Cookie security (5%)
    if cookie_r.get("risk"):
        score += 0.05
        for issue in cookie_r.get("issues", [])[:2]:
            reasons.append(f"Cookie: {issue}")

    # Weight 6: URL format signals (10%)
    if url_fmt.get("is_ip_address"):
        score += 0.10; reasons.append("URL uses raw IP address instead of domain name")
    if url_fmt.get("has_brand_keywords") and not url_fmt.get("uses_https"):
        score += 0.05; reasons.append("Brand keywords in URL without HTTPS")
    if url_fmt.get("url_length", 0) > 100:
        score += 0.03; reasons.append(f"Unusually long URL ({url_fmt['url_length']} chars)")

    # Encoding bonus
    if enc.get("is_double_encoded"):
        score += 0.10; reasons.append("Double URL-encoding — strong obfuscation indicator")
    elif enc.get("is_encoded"):
        score += 0.03; reasons.append("URL percent-encoding detected")
    reasons.extend(enc.get("issues", [])[:2])

    # TLD risk
    tld = _tld(url_fmt.get("domain", ""))
    if tld in _SUSPICIOUS_TLD:
        score += 0.05; reasons.append(f"High-risk TLD: {tld}")

    score = min(1.0, score)
    if score < 0.30:    verdict = "SAFE"
    elif score < 0.60:  verdict = "SUSPICIOUS"
    else:               verdict = "DANGEROUS"

    return verdict, round(score, 3), list(dict.fromkeys(reasons))  # deduplicated


# ── Public API ─────────────────────────────────────────────────────────────────

def fast_scan(url: str) -> Dict[str, Any]:
    """
    Full 6-layer PhishGuard pipeline — mirrors flask_api.run_full_analysis().

    Steps (all run concurrently where independent):
      1. XGBoost ML classification  (phishguard.predictor)
      2. SSL/TLS certificate check  (phishguard.ssl_checker)
      3. WHOIS domain age           (phishguard.whois_checker)
      4. HTTP cookie inspection     (server-side requests)
      5. URL encoding analysis      (offline, instant)
      6. HTML content analysis      (phishguard.html_analyzer)

    Returns structured dict with both `metrics` (legacy) and `details` (full).
    """
    t0  = time.time()
    url = _normalise(url)
    dom = _domain(url)

    # ── Step 1: XGBoost ML (offline, fast) ───────────────────────────────
    try:
        predictor = _get_predictor()
        ml = predictor.predict(url)
    except Exception as e:
        ml = {"label": "error", "probability": 0.5, "risk_factors": [],
              "safe_factors": [], "summary_report": f"ML error: {e}"}

    # ── Step 5: URL encoding (offline, instant) ───────────────────────────
    enc     = _check_encoding(url)
    url_fmt = _url_format_analysis(url)
    fp      = _compute_fingerprint(url)

    # ── Steps 2–4 + 6: Network checks (all parallel, hard timeouts) ───────
    ssl_r    = {"status": "skipped", "valid": None, "expires_in_days": -1, "issuer": "N/A"}
    whois_r  = {"age_days": -1, "registrar": "Unknown", "status": "skipped",
                "creation_date": "Unknown", "expiration_date": "Unknown"}
    html_r   = {"has_password_input": False, "has_login_form": False, "has_iframe": False,
                "external_form_action": False, "suspicious_scripts": 0,
                "favicon_mismatch": False, "risk_flags": [], "status": "skipped"}
    cookie_r = {"total_cookies": 0, "issues": [], "cookie_details": [],
                "risk": False, "status": "skipped"}

    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {
            ex.submit(_pg_ssl,              dom): "ssl",
            ex.submit(_pg_whois,            dom): "whois",
            ex.submit(_pg_html,             url): "html",
            ex.submit(_check_server_cookies, url): "cookies",
        }
        for fut in as_completed(futures, timeout=12):
            key = futures[fut]
            try:
                result = fut.result(timeout=12)
                if key == "ssl":     ssl_r    = result
                elif key == "whois": whois_r  = result
                elif key == "html":  html_r   = result
                elif key == "cookies": cookie_r = result
            except Exception:
                pass  # use defaults if any check times out

    if not url.startswith("https://"):
        ssl_r = {"status": "no_https", "valid": False, "expires_in_days": 0, "issuer": "N/A"}

    # ── Step 6: Risk aggregation across all 6 signals ─────────────────────
    verdict, risk_score, risk_reasons = _aggregate_risk(
        ml, enc, ssl_r, whois_r, url_fmt, html_r, cookie_r)

    # ── Build response matching flask_api.run_full_analysis() format ──────
    return {
        "url":           url,
        "domain":        dom,
        "verdict":       verdict,
        "risk_score":    risk_score,
        "risk_score_pct": round(risk_score * 100, 1),
        "scan_type":     "full",
        "risk_reasons":  risk_reasons,
        # details key — same structure as flask_api.py so renderers are shared
        "details": {
            "ml_model": {
                "label":          ml.get("label", "error"),
                "probability":    round(ml.get("probability", 0.5) * 100, 2),
                "risk_factors":   ml.get("risk_factors", []),
                "safe_factors":   ml.get("safe_factors", []),
                "summary_report": ml.get("summary_report", ""),
            },
            "ssl":      ssl_r,
            "whois":    whois_r,
            "cookies":  cookie_r,
            "encoding": enc,
            "html":     html_r,
        },
        # legacy metrics key (kept for backward-compat with existing renderers)
        "metrics": {
            "ml_label":          ml.get("label", "error"),
            "ml_probability":    round(ml.get("probability", 0.5) * 100, 1),
            "ml_risk_factors":   ml.get("risk_factors", []),
            "ml_safe_factors":   ml.get("safe_factors", []),
            "ml_summary":        ml.get("summary_report", ""),
            "url_length":        url_fmt["url_length"],
            "url_scheme":        url_fmt["scheme"],
            "path_depth":        url_fmt["path_depth"],
            "query_params":      url_fmt["query_param_count"],
            "readability":       f"{url_fmt['readability_score']}/10",
            "has_brand_words":   url_fmt["has_brand_keywords"],
            "is_ip_address":     url_fmt["is_ip_address"],
            "uses_https":        url_fmt["uses_https"],
            "has_fragment":      url_fmt["has_fragment"],
            "url_encoded":       enc["is_encoded"],
            "double_encoded":    enc["is_double_encoded"],
            "decoded_url":       enc.get("decoded_url", url)[:120],
            "ssl_status":        ssl_r.get("status", "unknown"),
            "ssl_valid":         ssl_r.get("valid", None),
            "ssl_days_left":     ssl_r.get("expires_in_days", ssl_r.get("days_remaining", -1)),
            "ssl_issuer":        ssl_r.get("issuer", "Unknown"),
            "domain_age_days":   whois_r.get("age_days", -1),
            "domain_created":    whois_r.get("creation_date", whois_r.get("created", "Unknown")),
            "domain_registrar":  whois_r.get("registrar", "Unknown"),
            "domain_age_status": whois_r.get("status", "unknown"),
            "html_login_form":   html_r.get("has_login_form", False),
            "html_password":     html_r.get("has_password_input", False),
            "html_iframe":       html_r.get("has_iframe", False),
            "html_ext_form":     html_r.get("external_form_action", False),
            "cookies_total":     cookie_r.get("total_cookies", 0),
            "cookies_risk":      cookie_r.get("risk", False),
            "fingerprint":       fp,
            "url_format":        url_fmt,
        },
        "processing_ms": round((time.time() - t0) * 1000),
        "timestamp":     time.time(),
    }


# deep_scan is removed — use fast_scan which already includes all enrichment.
# Kept as alias for backwards compatibility with any callers.
def deep_scan(url: str) -> Dict[str, Any]:
    """Deprecated: use fast_scan() — it now includes SSL/WHOIS/domain-age."""
    result = fast_scan(url)
    result["scan_type"] = "deep"   # flag for any UI checks
    return result


def scan_urls(urls: List[str], mode: str = "fast") -> List[Dict[str, Any]]:
    """
    Scan a list of URLs concurrently (both fast and deep use fast_scan now).
    Returns results in the same order as input.
    """
    if not urls:
        return []

    results = [None] * len(urls)
    with ThreadPoolExecutor(max_workers=min(len(urls), 4)) as ex:
        future_map = {ex.submit(fast_scan, u): i for i, u in enumerate(urls)}
        for fut in as_completed(future_map):
            idx = future_map[fut]
            try:
                results[idx] = fut.result(timeout=15)
            except Exception as e:
                results[idx] = {
                    "url": urls[idx], "verdict": "ERROR",
                    "risk_score": 0.5, "risk_score_pct": 50.0,
                    "scan_type": "full", "risk_reasons": [f"Scan error: {str(e)[:80]}"],
                    "details": {}, "metrics": {}, "processing_ms": 0, "timestamp": time.time(),
                }
    return [r for r in results if r is not None]


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all unique HTTP(S) URLs from raw text."""
    pattern = r'https?://[^\s<>"\')\]};,]+'
    found = re.findall(pattern, text, re.IGNORECASE)
    seen, unique = set(), []
    for u in found:
        u = u.rstrip(".")
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique