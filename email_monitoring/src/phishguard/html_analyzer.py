"""
html_analyzer.py â€“ Fetches a page and analyzes its HTML for phishing patterns.
Uses requests + beautifulsoup4 (install if needed via: pip install beautifulsoup4 requests).
"""
from __future__ import annotations

from typing import TypedDict


class HTMLResult(TypedDict):
    has_password_input: bool
    has_login_form: bool
    has_iframe: bool
    has_hidden_elements: bool
    external_form_action: bool
    suspicious_scripts: int
    favicon_mismatch: bool
    risk_flags: list[str]
    error: str


def analyze_html(url: str, timeout: int = 8) -> HTMLResult:
    """
    Fetches page HTML and checks for common phishing indicators.
    """
    try:
        import requests
        from urllib.parse import urlparse

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }

        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True, verify=False)
        html = resp.text

        try:
            from bs4 import BeautifulSoup
        except ImportError:
            # BeautifulSoup not installed - do basic regex analysis
            import re
            risk_flags = []
            has_password = bool(re.search(r'type=["\']password["\']', html, re.I))
            has_iframe = bool(re.search(r'<iframe', html, re.I))
            if has_password:
                risk_flags.append("Password input field detected")
            if has_iframe:
                risk_flags.append("Hidden iFrame detected")
            return {
                "has_password_input": has_password,
                "has_login_form": bool(re.search(r'<form', html, re.I)),
                "has_iframe": has_iframe,
                "has_hidden_elements": False,
                "external_form_action": False,
                "suspicious_scripts": 0,
                "favicon_mismatch": False,
                "risk_flags": risk_flags,
                "error": "BeautifulSoup not installed, basic regex analysis used"
            }

        soup = BeautifulSoup(html, "html.parser")
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc

        risk_flags: list[str] = []

        # 1. Password input field
        password_inputs = soup.find_all("input", attrs={"type": "password"})
        has_password_input = len(password_inputs) > 0
        if has_password_input:
            risk_flags.append("Password input field detected")

        # 2. Login form
        forms = soup.find_all("form")
        has_login_form = False
        external_form_action = False
        for form in forms:
            action = form.get("action", "")
            if any(kw in str(form).lower() for kw in ["login", "signin", "password", "credential"]):
                has_login_form = True
            if action and action.startswith("http"):
                action_domain = urlparse(action).netloc
                if action_domain and action_domain != base_domain:
                    external_form_action = True
                    risk_flags.append(f"Form submits to external domain: {action_domain}")

        if has_login_form:
            risk_flags.append("Login form detected")

        # 3. iFrames (common phishing overlay technique)
        iframes = soup.find_all("iframe")
        has_iframe = len(iframes) > 0
        if has_iframe:
            risk_flags.append(f"iFrame detected ({len(iframes)} found)")

        # 4. Hidden elements
        hidden = soup.find_all(style=lambda s: s and ("display:none" in s.replace(" ", "") or "visibility:hidden" in s.replace(" ", "")))
        hidden += soup.find_all(attrs={"hidden": True})
        has_hidden_elements = len(hidden) > 2
        if has_hidden_elements:
            risk_flags.append(f"Multiple hidden elements detected ({len(hidden)})")

        # 5. Suspicious scripts (eval, atob, document.write)
        scripts = soup.find_all("script")
        suspicious_script_count = 0
        suspicious_keywords = ["eval(", "document.write(", "atob(", "unescape(", "fromCharCode"]
        for script in scripts:
            script_text = script.string or ""
            if any(kw in script_text for kw in suspicious_keywords):
                suspicious_script_count += 1
        if suspicious_script_count > 0:
            risk_flags.append(f"Suspicious JavaScript patterns found ({suspicious_script_count} scripts)")

        # 6. Favicon domain mismatch
        favicon_mismatch = False
        favicon_link = soup.find("link", rel=lambda r: r and "icon" in r)
        if favicon_link:
            href = favicon_link.get("href", "")
            if href.startswith("http"):
                fav_domain = urlparse(href).netloc
                if fav_domain and fav_domain != base_domain:
                    favicon_mismatch = True
                    risk_flags.append(f"Favicon loaded from external domain: {fav_domain}")

        return {
            "has_password_input": has_password_input,
            "has_login_form": has_login_form,
            "has_iframe": has_iframe,
            "has_hidden_elements": has_hidden_elements,
            "external_form_action": external_form_action,
            "suspicious_scripts": suspicious_script_count,
            "favicon_mismatch": favicon_mismatch,
            "risk_flags": risk_flags,
            "error": ""
        }

    except Exception as e:
        return {
            "has_password_input": False,
            "has_login_form": False,
            "has_iframe": False,
            "has_hidden_elements": False,
            "external_form_action": False,
            "suspicious_scripts": 0,
            "favicon_mismatch": False,
            "risk_flags": [],
            "error": f"HTML analysis failed: {e}"
        }

