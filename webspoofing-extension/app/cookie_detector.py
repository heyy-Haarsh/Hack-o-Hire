"""
cookie_detector.py – Detects cookie manipulation and generates an anomaly score.
Usage:
    from app.cookie_detector import CookieDetector
    detector = CookieDetector()
    res = detector.analyse(url="https://bank.com", cookies=[{"name": "sessionid", "value": "abc123", "secure": False, "http_only": False}])
"""
from __future__ import annotations

import datetime
from typing import Any, TypedDict
import textwrap

class CookieAnomaly(TypedDict):
    anomaly_type: str
    severity: str
    description: str
    affected_cookies: list[str]
    recommendation: str

class CookieAnalysisResult(TypedDict):
    url: str
    total_cookies: int
    anomaly_score: float
    risk_level: str
    anomalies: list[CookieAnomaly]
    analysis_timestamp: str

class CookieDetector:
    """
    Engine to detect cookie manipulations using heuristic rules.
    """
    
    SEVERITY_WEIGHTS = {
        "high": 0.35,
        "medium": 0.15,
        "low": 0.05
    }

    def analyse(self, url: str, cookies: list[dict[str, Any]]) -> CookieAnalysisResult:
        anomalies: list[CookieAnomaly] = []
        score = 0.0
        
        # We will iterate through cookies and check for various rules
        missing_httponly = []
        missing_secure = []
        jwt_payloads = []
        pickle_payloads = []
        excessive_lifetime = []

        now = datetime.datetime.now(datetime.timezone.utc)

        for cookie in cookies:
            name = cookie.get("name", "")
            value = str(cookie.get("value", ""))
            
            # Rule 1: Missing HttpOnly or Secure flags on session/auth cookies
            is_session = "session" in name.lower() or "auth" in name.lower() or "id" in name.lower()
            
            if is_session and not cookie.get("http_only", False):
                missing_httponly.append(name)
            
            # If URL is HTTPS, cookies should be marked Secure
            if url.startswith("https") and not cookie.get("secure", False):
                missing_secure.append(name)
                
            # Rule 2: JWT in plain cookie (Starts with eyJ)
            if value.startswith("eyJ") and len(value) > 30:
                jwt_payloads.append(name)
                
            # Rule 3: Python pickle payloads (Often contain specific byte headers if stringified, or base64 'gASV')
            if "gASV" in value or "c__main__" in value:
                pickle_payloads.append(name)

            # Rule 4: Excessive cookie lifetime (> 90 days)
            expiry = cookie.get("expires")
            if expiry:
                try:
                    # Very rough check assuming expiry could be a timestamp or a future year
                    if isinstance(expiry, (int, float)):
                        exp_date = datetime.datetime.fromtimestamp(expiry, tz=datetime.timezone.utc)
                        days_diff = (exp_date - now).days
                        if days_diff > 90:
                            excessive_lifetime.append(name)
                except Exception:
                    pass

        # Calculate Scores & Anomalies
        if missing_httponly:
            anomalies.append({
                "anomaly_type": "missing_httponly",
                "severity": "high",
                "description": f"Session cookies lack the HttpOnly flag, making them vulnerable to XSS attacks.",
                "affected_cookies": missing_httponly,
                "recommendation": "Set HttpOnly=True for all session and authentication cookies."
            })
            score += self.SEVERITY_WEIGHTS["high"]

        if missing_secure:
            anomalies.append({
                "anomaly_type": "missing_secure",
                "severity": "high",
                "description": f"Secure flag is missing over an HTTPS connection, risking interception.",
                "affected_cookies": missing_secure,
                "recommendation": "Set Secure=True for all cookies transmitted over HTTPS."
            })
            score += self.SEVERITY_WEIGHTS["high"]

        if jwt_payloads:
            anomalies.append({
                "anomaly_type": "jwt_in_plain_cookie",
                "severity": "high",
                "description": f"A potential JWT was found in cookies. If not marked HttpOnly, it can be easily stolen.",
                "affected_cookies": jwt_payloads,
                "recommendation": "Encode JWTs securely and ensure HttpOnly flags are set."
            })
            score += self.SEVERITY_WEIGHTS["high"]

        if pickle_payloads:
            anomalies.append({
                "anomaly_type": "potential_pickle_payload",
                "severity": "high",
                "description": f"A potential serialized Python object (pickle) was found. This can lead to Remote Code Execution.",
                "affected_cookies": pickle_payloads,
                "recommendation": "Never trust serialized objects from the client side. Switch to JSON signatures."
            })
            score += self.SEVERITY_WEIGHTS["high"]

        if excessive_lifetime:
            anomalies.append({
                "anomaly_type": "excessive_lifetime",
                "severity": "low",
                "description": f"Cookies have an excessively long expiration time (>90 days).",
                "affected_cookies": excessive_lifetime,
                "recommendation": "Shorten session cookie lifetimes to reduce the window of Hijacking."
            })
            score += self.SEVERITY_WEIGHTS["low"]

        # Cap score at 1.0
        final_score = min(score, 1.0)
        
        if final_score >= 0.65:
            risk_level = "high_risk"
        elif final_score >= 0.3:
            risk_level = "medium_risk"
        else:
            risk_level = "low_risk"

        return {
            "url": url,
            "total_cookies": len(cookies),
            "anomaly_score": round(final_score, 2),
            "risk_level": risk_level,
            "anomalies": anomalies,
            "analysis_timestamp": now.isoformat()
        }

if __name__ == "__main__":
    import sys
    import json
    import pprint
    
    # If no arguments are passed, run the built-in simulation:
    if len(sys.argv) < 3:
        sample_url = "https://bank.com"
        sample_cookies = [
            {"name": "sessionid", "value": "abc123_valid", "secure": False, "http_only": False},
            {"name": "_tracking", "value": "user_1", "secure": True, "http_only": False, "expires": 4102444800},
            {"name": "auth_token", "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret", "secure": True, "http_only": False}
        ]
        print("\n[!] No arguments provided. Running built-in simulation...")
        print("Usage: python -m app.cookie_detector <url> <json_string_or_filepath>\n")
    else:
        sample_url = sys.argv[1]
        cookie_arg = sys.argv[2]
        
        # Try to load it as a file first, otherwise parse it as a direct JSON string
        try:
            with open(cookie_arg, 'r') as f:
                sample_cookies = json.load(f)
        except Exception:
            try:
                sample_cookies = json.loads(cookie_arg)
            except json.JSONDecodeError:
                print("Error: The second argument must be a valid JSON file path or a raw JSON string.")
                sys.exit(1)
                
    print(f"URL: {sample_url}")
    print("Provided Cookies:", json.dumps(sample_cookies, indent=2))
    
    detector = CookieDetector()
    res = detector.analyse(sample_url, sample_cookies)
    
    print("\n--- Cookie Analysis Report ---")
    print(f"Risk Level: {res['risk_level'].upper().replace('_', ' ')}")
    print(f"Anomaly Score: {res['anomaly_score']} / 1.0")
    print(f"Total Cookies Scanned: {res['total_cookies']}")
    
    if res["anomalies"]:
        print("\nIdentified Anomalies:")
        for idx, anomaly in enumerate(res['anomalies'], 1):
            print(f"  {idx}. [{anomaly['severity'].upper()}] {anomaly['anomaly_type']}")
            wrapper = textwrap.TextWrapper(initial_indent="      ", subsequent_indent="      ", width=80)
            print(wrapper.fill(anomaly["description"]))
            print(f"      Affected Cookies: {', '.join(anomaly['affected_cookies'])}")
            print(wrapper.fill(f"Recommendation: {anomaly['recommendation']}"))
            print("")
    else:
        print("\nNo anomalies detected. Cookies appear safe.")
