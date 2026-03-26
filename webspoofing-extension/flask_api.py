"""
flask_api.py – Full PhishGuard Analysis Pipeline
========================================================
Unified Flask API that accepts a single URL and runs:
  1. XGBoost ML model (URL features)
  2. SSL certificate check
  3. WHOIS domain age check
  4. HTTP Cookie security check
  5. URL Encoding analysis
  6. HTML content analysis

Run with:
    python flask_api.py
    or:
    python -m flask_api

Frontend: http://localhost:5000
API:      http://localhost:5000/analyze  (POST, JSON: {"url": "..."})
"""
from __future__ import annotations

import time
import urllib.parse
import warnings
import ssl
import requests as _requests
warnings.filterwarnings("ignore")

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# ── Internal App Modules ───────────────────────────────────────────────────────
from app.predictor import Predictor
from app.ssl_checker import check_ssl
from app.whois_checker import check_whois
from app.html_analyzer import analyze_html
from app.logger import logger

# ── Initialise Flask ───────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="dashboard", static_url_path="")
CORS(app, resources={r"/*": {"origins": "*"}})

# Load ML model once at startup
predictor = Predictor()
logger.info("PhishGuard Flask API ready.")


# ── Helper: Extract Domain ─────────────────────────────────────────────────────
def extract_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urlparse(url).netloc


# ── Helper: Encoding Check ─────────────────────────────────────────────────────
def check_encoding(url: str) -> dict:
    decoded = urllib.parse.unquote(url)
    double_decoded = urllib.parse.unquote(decoded)
    is_encoded = decoded != url
    is_double_encoded = double_decoded != decoded

    issues = []
    if is_encoded:
        issues.append("URL uses percent-encoding (potential obfuscation)")
    if is_double_encoded:
        issues.append("URL uses double encoding (high obfuscation risk)")

    # Check for suspicious encoded chars
    suspicious_encoded = ["%00", "%0d", "%0a", "%2e%2e", "%252e"]
    for enc in suspicious_encoded:
        if enc in url.lower():
            issues.append(f"Suspicious encoded sequence detected: {enc}")

    return {
        "is_encoded": is_encoded,
        "is_double_encoded": is_double_encoded,
        "decoded_url": decoded,
        "issues": issues,
        "risk": len(issues) > 0
    }


# ── Helper: Server Cookie Check ───────────────────────────────────────────────
def check_server_cookies(url: str) -> dict:
    """
    Fetch URL and inspect Set-Cookie headers from the HTTP response.
    """
    try:
        resp = _requests.get(
            url,
            timeout=6,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 PhishGuard/1.0"}
        )

        issues = []
        cookie_details = []
        cookies = resp.cookies

        for c in cookies:
            httponly = c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly")
            cookie_info = {
                "name": c.name,
                "secure": c.secure,
                "httponly": httponly,
                "samesite": c.get_nonstandard_attr("SameSite", "Not Set"),
                "issues": []
            }

            if not c.secure and url.startswith("https"):
                cookie_info["issues"].append("Missing Secure flag on HTTPS")
                issues.append(f"{c.name}: Missing Secure flag")

            if not httponly:
                is_session = any(k in c.name.lower() for k in ["session", "auth", "token", "id", "sid"])
                if is_session:
                    cookie_info["issues"].append("Session cookie missing HttpOnly flag")
                    issues.append(f"{c.name}: Missing HttpOnly flag")

            cookie_details.append(cookie_info)

        status = "ok"
        if len(cookies) == 0:
            status = "no_cookies"
        elif len(issues) > 0:
            status = "issues_found"

        return {
            "total_cookies": len(cookies),
            "issues": issues,
            "cookie_details": cookie_details,
            "risk": len(issues) > 0,
            "status": status,
            "error": ""
        }

    except _requests.exceptions.ConnectionError:
        return {"total_cookies": 0, "issues": [], "cookie_details": [], "risk": False,
                "status": "unreachable", "error": "Site is unreachable — cannot check cookies"}
    except _requests.exceptions.Timeout:
        return {"total_cookies": 0, "issues": [], "cookie_details": [], "risk": False,
                "status": "timeout", "error": "Connection timed out"}
    except Exception as e:
        short = str(e)[:80]
        return {"total_cookies": 0, "issues": [], "cookie_details": [], "risk": False,
                "status": "error", "error": f"{type(e).__name__}: {short}"}


# ── Risk Score Calculator ──────────────────────────────────────────────────────
def calculate_risk(results: dict) -> dict:
    """
    Combines all check results into a unified risk score and verdict.
    DNS-unresolvable domains are treated as HIGH RISK (a major phishing signal).
    """
    score = 0.0
    reasons = []

    # 1. ML Model score (weight: 40%)
    ml_prob = results.get("ml_probability", 0.0)
    ml_label = results.get("ml_label", "legitimate")
    score += ml_prob * 0.40
    if ml_label == "phishing":
        reasons.append("AI model detected phishing URL pattern")
    elif ml_label == "suspicious":
        reasons.append("AI model considers URL suspicious")

    # 2. SSL check (weight: up to 30%)
    ssl_data = results.get("ssl", {})
    ssl_status = ssl_data.get("status", "")
    if ssl_status == "unreachable":
        # Domain doesn't resolve at all — MAJOR red flag
        score += 0.30
        reasons.append("Domain is unreachable / does not resolve in DNS (dead or fake domain)")
    elif ssl_status in ("invalid", "expired"):
        score += 0.25
        reasons.append(f"SSL certificate is {ssl_status} — site cannot be trusted")
    elif ssl_status == "no_ssl":
        score += 0.15
        reasons.append("Site does not support HTTPS (no SSL)")
    elif not ssl_data.get("valid", True):
        score += 0.20
        reasons.append("SSL certificate is not valid")
    elif ssl_data.get("expires_in_days", 365) < 14:
        score += 0.10
        reasons.append(f"SSL expires in {ssl_data.get('expires_in_days')} days — suspicious")

    # 3. WHOIS domain age (weight: up to 25%)
    whois_data = results.get("whois", {})
    whois_status = whois_data.get("status", "ok")
    age_days = whois_data.get("age_days", 9999)

    if whois_status == "dns_failed" or not whois_data.get("domain_resolvable", True):
        # Already counted in SSL — add slight extra
        score += 0.10
        reasons.append("WHOIS: Domain registration not found (unregistered or taken down)")
    elif whois_status == "new_domain" or (age_days > 0 and age_days < 30):
        score += 0.25
        reasons.append(f"Domain is only {age_days} days old — very new (common in phishing)")
    elif age_days > 0 and age_days < 180:
        score += 0.12
        reasons.append(f"Domain is relatively new ({age_days} days old)")
    elif whois_status == "whois_failed" and age_days == 0:
        score += 0.05  # small penalty for privacy/hidden WHOIS

    # 4. Cookie issues (weight: 10%)
    cookie_data = results.get("cookies", {})
    if cookie_data.get("risk", False):
        n = len(cookie_data.get("issues", []))
        score += min(n * 0.05, 0.15)
        reasons.append(f"Cookie security: {n} issue(s) detected (missing Secure/HttpOnly flags)")

    # 5. Encoding (weight: up to 15%)
    enc_data = results.get("encoding", {})
    if enc_data.get("is_double_encoded"):
        score += 0.15
        reasons.append("Double URL-encoding detected — URL is being obfuscated")
    elif enc_data.get("risk"):
        score += 0.05
        reasons.append("URL percent-encoding detected — possible obfuscation")

    # 6. HTML analysis (bonus flags, up to 0.25)
    html_data = results.get("html", {})
    if html_data.get("external_form_action"):
        score += 0.20
        reasons.append("Page form submits credentials to an EXTERNAL domain")
    if html_data.get("has_password_input") and html_data.get("has_iframe"):
        score += 0.10
        reasons.append("Login form + hidden iFrame detected")
    if html_data.get("favicon_mismatch"):
        score += 0.05
        reasons.append("Favicon loaded from an external/different domain")
    if html_data.get("suspicious_scripts", 0) > 1:
        score += 0.05
        reasons.append(f"{html_data['suspicious_scripts']} suspicious JavaScript patterns found")

    # Cap at 1.0
    final_score = min(score, 1.0)

    if final_score < 0.30:
        verdict = "SAFE"
        verdict_color = "green"
    elif final_score < 0.60:
        verdict = "SUSPICIOUS"
        verdict_color = "orange"
    else:
        verdict = "DANGEROUS"
        verdict_color = "red"

    return {
        "score": round(final_score, 3),
        "verdict": verdict,
        "verdict_color": verdict_color,
        "reasons": reasons
    }


# ── Main Pipeline ──────────────────────────────────────────────────────────────
def run_full_analysis(url: str) -> dict:
    """
    Master pipeline: runs all checks in parallel and combines results.
    """
    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    domain = extract_domain(url)

    # Run ML model inline (fast, no I/O)
    try:
        ml_result = predictor.predict(url)
    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        ml_result = {
            "label": "error",
            "probability": 0.5,
            "is_phishing": False,
            "risk_factors": [],
            "safe_factors": [],
            "summary_report": f"ML check failed: {e}"
        }

    # Encoding check (pure CPU, instant)
    enc_result = check_encoding(url)

    # Run network checks in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        ssl_future    = executor.submit(check_ssl, domain)
        whois_future  = executor.submit(check_whois, domain)
        cookie_future = executor.submit(check_server_cookies, url)
        html_future   = executor.submit(analyze_html, url)

        ssl_result    = ssl_future.result()
        whois_result  = whois_future.result()
        cookie_result = cookie_future.result()
        html_result   = html_future.result()

    # Calculate combined risk
    risk_input = {
        "ml_probability": ml_result["probability"],
        "ml_label": ml_result["label"],
        "ssl": ssl_result,
        "whois": whois_result,
        "cookies": cookie_result,
        "encoding": enc_result,
        "html": html_result
    }
    risk = calculate_risk(risk_input)

    return {
        "url": url,
        "domain": domain,
        "verdict": risk["verdict"],
        "risk_score": risk["score"],
        "verdict_color": risk["verdict_color"],
        "risk_reasons": risk["reasons"],
        "details": {
            "ml_model": {
                "label": ml_result["label"],
                "probability": round(ml_result["probability"] * 100, 1),
                "risk_factors": ml_result.get("risk_factors", []),
                "safe_factors": ml_result.get("safe_factors", []),
                "summary": ml_result.get("summary_report", "")
            },
            "ssl": ssl_result,
            "whois": whois_result,
            "cookies": cookie_result,
            "encoding": enc_result,
            "html": html_result
        },
        "timestamp": time.time()
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def serve_dashboard():
    """Serve the built-in web dashboard."""
    return send_from_directory("dashboard", "index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "PhishGuard Full Pipeline API", "version": "2.0"})


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main analysis endpoint.
    
    Body: { "url": "https://example.com" }
    Returns: Full multi-check analysis JSON
    """
    data = request.get_json(silent=True, force=True)
    if not data or not data.get("url"):
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = str(data["url"]).strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    logger.info(f"Analyzing URL: {url}")
    start = time.time()

    try:
        result = run_full_analysis(url)
        result["analysis_time_ms"] = round((time.time() - start) * 1000, 1)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Analysis failed for {url}: {e}")
        return jsonify({"error": f"Analysis failed: {e}"}), 500


@app.route("/analyze/fast", methods=["POST"])
def analyze_fast():
    """
    Fast analysis endpoint — ML + encoding only (no network calls).
    Used by the Chrome extension for instant results.
    
    Body: { "url": "...", "cookies": [...] }
    """
    data = request.get_json(silent=True, force=True)
    if not data or not data.get("url"):
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = str(data["url"]).strip()
    cookies = data.get("cookies", [])

    try:
        # ML model
        ml_result = predictor.predict(url)
        # Encoding
        enc_result = check_encoding(url)
        # Cookie analysis (from extension cookies, not server)
        from app.cookie_detector import CookieDetector
        detector = CookieDetector()
        # Convert extension cookie format to our format
        normalized = []
        for c in cookies:
            normalized.append({
                "name": c.get("name", ""),
                "value": c.get("value", ""),
                "secure": c.get("secure", False),
                "http_only": c.get("httpOnly", c.get("http_only", False)),
                "expires": c.get("expirationDate", c.get("expires", None))
            })
        cookie_res = detector.analyse(url, normalized)

        # Simple combined score
        phish_prob = ml_result["probability"]
        is_dangerous = (
            ml_result["label"] == "phishing" or
            (cookie_res["anomaly_score"] > 0.65) or
            enc_result.get("is_double_encoded", False)
        )
        is_suspicious = (
            ml_result["label"] == "suspicious" or
            cookie_res["anomaly_score"] > 0.3 or
            enc_result.get("risk", False)
        )

        verdict = "DANGEROUS" if is_dangerous else ("SUSPICIOUS" if is_suspicious else "SAFE")

        return jsonify({
            "url": url,
            "verdict": verdict,
            "risk_score": round(phish_prob, 3),
            "details": {
                "ml_model": {
                    "label": ml_result["label"],
                    "probability": round(phish_prob * 100, 1),
                    "risk_factors": ml_result.get("risk_factors", []),
                    "safe_factors": ml_result.get("safe_factors", []),
                    "summary": ml_result.get("summary_report", "")
                },
                "cookies": {
                    "risk_level": cookie_res["risk_level"],
                    "anomaly_score": cookie_res["anomaly_score"],
                    "total_cookies": cookie_res["total_cookies"],
                    "anomalies": cookie_res["anomalies"]
                },
                "encoding": enc_result
            },
            "timestamp": time.time()
        })

    except Exception as e:
        logger.error(f"Fast analysis failed: {e}")
        return jsonify({"error": f"Analysis failed: {e}"}), 500


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting PhishGuard Flask API on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
