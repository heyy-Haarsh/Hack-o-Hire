import imaplib
import os
import time
import email
import sys
from pathlib import Path

# ── Path setup: make phishguard importable from src/ ──────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables from .env
from json import loads
from dotenv import load_dotenv
load_dotenv()

# Streamlit for UI
import streamlit as st
from lib.info import get_email_body
from lib.attachments import extract_attachments
from llm import return_ans
from attachment_analyzer import analyze_email
from bert_detector import DistilBertEmailDetector
from url_scanner import scan_urls, extract_urls_from_text, fast_scan, deep_scan
import ollama as _ollama

# Ensure storage directory exists at startup (absolute path)
_SRC_DIR = Path(__file__).parent
_PROJECT_ROOT = _SRC_DIR.parent
os.makedirs(str(_PROJECT_ROOT / "extracted_attachments"), exist_ok=True)

# Absolute path for rag.json (used in routing section)
_RAG_JSON_PATH = str(_SRC_DIR / "data" / "rag.json")

# ── DistilBERT email detector (lazy-loads on first email) ─────────────────
detector = DistilBertEmailDetector()

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Email Security Monitor",
    page_icon="🛡️",
    layout="wide",
)

# ─────────────────────────────────────────────────────────────────────────────
# CUSTOM CSS  — clean white / light professional theme
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

/* ── Main background ── */
.stApp { 
    background: #fdfdff; 
}
section[data-testid="stSidebar"] { 
    background: #ffffff; 
    border-right: 1px solid #eef2ff; 
}

/* ── Header ── */
.pg-header {
    background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
    border-radius: 20px;
    padding: 32px 40px;
    margin-bottom: 28px;
    display: flex;
    align-items: center;
    gap: 20px;
    box-shadow: 0 8px 30px rgba(99,102,241,0.15);
}
.pg-header h1 { margin:0; font-size:2.2rem; font-weight:800; color: #ffffff; letter-spacing:-0.02em; }
.pg-header p  { margin:6px 0 0; font-size:1rem; color: rgba(255,255,255,0.9); font-weight:400; }

/* ── Panels & Cards ── */
.url-scan-panel {
    background: rgba(255, 255, 255, 0.7);
    backdrop-filter: blur(10px);
    border: 1px solid #eef2ff;
    border-radius: 18px;
    padding: 24px;
    margin: 16px 0;
    box-shadow: 0 4px 12px rgba(0,0,0,0.03);
}
.url-scan-panel h4 { margin:0 0 16px; color:#4338ca; font-size:1.1rem; font-weight:700; }

.url-card {
    border-radius: 14px;
    padding: 16px 20px;
    margin-bottom: 14px;
    border: 1px solid;
    transition: transform 0.2s ease;
}
.url-card:hover { transform: translateX(4px); }

.url-card.safe      { background:#f0fdf4; border-color:#dcfce7; }
.url-card.suspicious{ background:#fffbeb; border-color:#fef3c7; }
.url-card.dangerous { background:#fef2f2; border-color:#fee2e2; }
.url-card.error     { background:#f8fafc; border-color:#f1f5f9; }

.url-verdict {
    font-size:1.15rem; font-weight:800; letter-spacing:.02em;
    display:flex; align-items:center; gap:8px; margin-bottom:6px;
}
.url-verdict.safe      { color:#15803d; }
.url-verdict.suspicious{ color:#b45309; }
.url-verdict.dangerous { color:#be123c; }
.url-verdict.error     { color:#475569; }

/* ── Section Tags ── */
.section-tag {
    display:inline-block; padding:4px 14px; border-radius:30px;
    font-size:.75rem; font-weight:700; letter-spacing:.05em;
    text-transform:uppercase; margin-bottom:10px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.02);
}
.tag-purple { background:#f5f3ff; color:#6366f1; border:1px solid #e0e7ff; }
.tag-green  { background:#f0fdf4; color:#16a34a; border:1px solid #dcfce7; }
.tag-red    { background:#fef2f2; color:#dc2626; border:1px solid #fee2e2; }
.tag-yellow { background:#fffbeb; color:#d97706; border:1px solid #fef3c7; }

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: #ffffff;
    border: 1px solid #f1f5f9;
    border-radius: 16px;
    padding: 20px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.02);
    transition: all 0.3s ease;
}
[data-testid="metric-container"]:hover {
    border-color: #6366f1;
    transform: translateY(-2px);
    box-shadow: 0 6px 15px rgba(99,102,241,0.08);
}

/* ── Sidebar ── */
[data-testid="stSidebarNav"] { padding-top: 2rem; }
.stMarkdown h2 { color: #1e1b4b; font-weight: 800; }

/* ── URL score bar ── */
.score-track {
    background:#f1f5f9; border-radius:4px; height:6px; margin:8px 0 4px;
    overflow:hidden;
}
.score-fill { height:6px; border-radius:4px; transition:width .4s ease; }
.url-score  { font-size:.8rem; color:#64748b; }
.url-domain { font-size:.85rem; color:#475569; font-family:monospace; margin:4px 0; word-break:break-all; }

/* ── Reason chips ── */
.reason-chip {
    display:inline-block; background:#f1f5f9; color:#475569;
    border:1px solid #e2e8f0; border-radius:20px;
    padding:2px 10px; font-size:.72rem; margin:2px 3px 2px 0;
}

/* ── Cookie security table ── */
.ck-table {
    width:100%; border-collapse:collapse; font-size:.82rem;
    margin-top:8px; border-radius:8px; overflow:hidden;
}
.ck-table th {
    background:#f8fafc; color:#64748b; font-weight:600;
    padding:7px 10px; text-align:left; border-bottom:1px solid #e2e8f0;
}
.ck-table td {
    padding:6px 10px; border-bottom:1px solid #f1f5f9; color:#374151;
}
.ck-table tr:last-child td { border-bottom:none; }
.flag-ok  { color:#16a34a; font-weight:600; }
.flag-bad { color:#dc2626; font-weight:600; }

</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="pg-header">
    <div style="font-size:2.5rem">🛡️</div>
    <div>
        <h1>Email Security Monitor</h1>
        <p>AI-powered fraud detection · Voice deepfake scan · PhishGuard URL analysis</p>
    </div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# LOGIN FORM
# ─────────────────────────────────────────────────────────────────────────────
col_a, col_b = st.columns(2)
with col_a:
    email_id = st.text_input("📧 Gmail Address", placeholder="johndoe@gmail.com")
with col_b:
    app_password = st.text_input("🔑 App Password", placeholder="xxxx xxxx xxxx xxxx", type="password")

monitor = st.button("🚀 Start Monitoring", use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# LLM SMS ALERT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────
def generate_sms_alert(sender: str, subject: str, risk_level: str,
                       llm_explanation: str, red_flags: list) -> str:
    """
    Ask Ollama to draft a concise SMS-style security alert (≤160 chars).
    Returns the SMS text or a fallback string on error.
    """
    flags_text = "; ".join(red_flags[:3]) if red_flags else "suspicious content"
    prompt = f"""You are a cybersecurity alert system. Write a SHORT SMS alert (max 160 chars) for a security team.
Email from: {sender}
Subject: {subject}
Risk: {risk_level}
Red flags: {flags_text}
Explanation: {llm_explanation[:200]}

Respond with ONLY the SMS text. No preamble, no quotes, no explanation. Must be under 160 characters."""
    try:
        resp = _ollama.chat(
            model="qwen3:8b",
            messages=[{"role": "user", "content": prompt}]
        )
        sms = resp['message']['content'].strip().strip('"').strip("'")
        # Enforce 160 char hard limit
        return sms[:160]
    except Exception as e:
        return f"⚠️ FRAUD ALERT: Email from {sender[:30]} flagged as {risk_level}. Review immediately."


def _verdict_class(verdict: str) -> str:
    v = verdict.upper()
    if "DANGER" in v: return "dangerous"
    if "SUSP"   in v: return "suspicious"
    if "SAFE"   in v: return "safe"
    return "error"

def _verdict_icon(verdict: str) -> str:
    v = verdict.upper()
    if "DANGER" in v: return "🚨"
    if "SUSP"   in v: return "⚠️"
    if "SAFE"   in v: return "✅"
    return "❓"


def _render_enhanced_url(res: dict):
    """Render enhanced URL scan result with 30+ metrics and full security panels."""
    url     = res.get("url", "—")
    verdict = res.get("verdict", "ERROR")
    score   = res.get("risk_score_pct", res.get("risk_score", 0) * 100)
    reasons = res.get("risk_reasons", [])
    domain  = res.get("domain", "")
    mx      = res.get("metrics", {})
    det     = res.get("details", {})
    cls     = _verdict_class(verdict)
    icon    = _verdict_icon(verdict)

    bar_color = {"dangerous": "#ef4444", "suspicious": "#f59e0b"}.get(cls, "#10b981")
    reasons_html = "".join(f'<span class="reason-chip">⚑ {r}</span>' for r in reasons[:5])

    ssl_badge = ""
    if mx.get("ssl_status") == "valid":
        ssl_badge = '<span style="background:#16a34a22;color:#4ade80;border:1px solid #16a34a;border-radius:4px;padding:1px 6px;font-size:.65rem;margin-left:6px">🔒 SSL Valid</span>'
    elif mx.get("ssl_status") in ("invalid", "expired", "no_https"):
        ssl_badge = '<span style="background:#dc262622;color:#f87171;border:1px solid #dc2626;border-radius:4px;padding:1px 6px;font-size:.65rem;margin-left:6px">⚠️ SSL Issue</span>'

    age_days = mx.get("domain_age_days", -1)
    age_text = f"{age_days}d" if age_days > 0 else "Unknown"
    age_badge = ""
    if age_days > 0 and age_days < 90:
        age_badge = f'<span style="background:#ca8a0422;color:#fbbf24;border:1px solid #ca8a04;border-radius:4px;padding:1px 6px;font-size:.65rem;margin-left:6px">🆕 New Domain ({age_text})</span>'

    # Cookie issue badge
    cookie_det = det.get("cookies", {})
    n_cookie_issues = len(cookie_det.get("issues", []))
    cookie_badge = ""
    if n_cookie_issues > 0:
        cookie_badge = (
            f'<span style="background:#ca8a0422;color:#fbbf24;border:1px solid #ca8a04;'
            f'border-radius:4px;padding:1px 6px;font-size:.65rem;margin-left:6px">'
            f'🍪 {n_cookie_issues} Cookie Issue(s)</span>'
        )

    st.markdown(f"""
    <div class="url-card {cls}">
        <div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px">
            <div class="url-verdict {cls}">{icon} {verdict}</div>
            {ssl_badge}{age_badge}{cookie_badge}
        </div>
        <div class="url-domain">🌐 {url}</div>
        <div class="score-track"><div class="score-fill" style="width:{min(score,100):.1f}%;background:{bar_color}"></div></div>
        <div class="url-score">Risk: <strong>{score:.1f}%</strong></div>
        <div style="margin-top:8px">{reasons_html}</div>
    </div>
    """, unsafe_allow_html=True)

    if mx or det:
        with st.expander(f"📊 Full Security Analysis — {domain}", expanded=False):
            # ── Summary metrics row ───────────────────────────────────────────
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("ML Verdict",    mx.get("ml_label","—").upper())
                st.metric("ML Confidence", f"{mx.get('ml_probability',0):.1f}%")
            with c2:
                st.metric("SSL Status",    (mx.get("ssl_status") or "—").upper())
                st.metric("TLS Version",   mx.get("tls_version","—"))
                st.metric("SSL Issuer",    mx.get("ssl_issuer","—")[:22] if mx.get("ssl_issuer") else "—")
            with c3:
                st.metric("Domain Age",    age_text)
                st.metric("Registrar",     (mx.get("domain_registrar","—") or "—")[:20])
            with c4:
                st.metric("URL Length",    mx.get("url_length","—"))
                st.metric("Path Depth",    mx.get("path_depth","—"))
                st.metric("Query Params",  mx.get("query_params","—"))

            # URL format details
            fmt = mx.get("url_format", {})
            if fmt:
                st.markdown("**🔤 URL Format Analysis**")
                fc1, fc2, fc3 = st.columns(3)
                with fc1:
                    st.write(f"Has IP address: {'⚠️ Yes' if fmt.get('is_ip_address') else '✅ No'}")
                    st.write(f"URL encoded: {'⚠️ Yes' if fmt.get('url_encoded') else '✅ No'}")
                    st.write(f"Double encoded: {'🚨 Yes' if fmt.get('double_encoded') else '✅ No'}")
                with fc2:
                    st.write(f"Brand in subdomain: {'⚠️ Yes' if fmt.get('brand_in_subdomain') else '✅ No'}")
                    st.write(f"Readability: {fmt.get('readability_score',0):.0f}/10")
                with fc3:
                    st.write(f"Scheme: {fmt.get('url_scheme','—').upper()}")
                    st.write(f"Hyphens in domain: {fmt.get('hyphens_in_domain',0)}")
                    st.write(f"Dot count: {fmt.get('dot_count',0)}")

            # Fingerprint
            if mx.get("fingerprint"):
                st.caption(f"🔑 Campaign Fingerprint: `{mx['fingerprint'][:48]}`")

            # ML factors
            if mx.get("ml_risk_factors"):
                st.markdown("**⚠️ Risk Factors:**")
                for rf in mx["ml_risk_factors"][:5]: st.write(f"  • {rf}")
            if mx.get("ml_safe_factors"):
                st.markdown("**✅ Safe Factors:**")
                for sf in mx["ml_safe_factors"][:3]: st.write(f"  • {sf}")

            # ── SSL Certificate ───────────────────────────────────────────────
            ssl = det.get("ssl", {})
            if ssl and ssl.get("status") not in ("skipped", None):
                st.divider()
                st.markdown('<span class="section-tag tag-green">🔒 SSL Certificate</span>', unsafe_allow_html=True)
                ssl_valid   = ssl.get("valid", False)
                ssl_status  = (ssl.get("status") or "unknown").upper()
                ssl_expiry  = ssl.get("expires_in_days", "?")
                ssl_issuer  = ssl.get("issuer") or "Unknown CA"
                ssl_subject = ssl.get("subject") or domain
                sc1, sc2, sc3 = st.columns(3)
                with sc1:
                    st.metric("Status", ssl_status)
                with sc2:
                    st.metric("Valid & Trusted", "✅ Yes" if ssl_valid else "❌ No")
                with sc3:
                    st.metric("Expires In", f"{ssl_expiry} days" if isinstance(ssl_expiry, int) else ssl_expiry)
                st.caption(f"**Issuer:** {ssl_issuer}  ·  **Subject:** {ssl_subject}")
                if ssl.get("error"):
                    st.warning(f"⚠️ {ssl['error']}")

            # ── WHOIS / Domain Age ────────────────────────────────────────────
            whois = det.get("whois", {})
            if whois and whois.get("status") not in ("skipped", None):
                st.divider()
                st.markdown('<span class="section-tag tag-yellow">🌍 WHOIS Lookup</span>', unsafe_allow_html=True)
                w_age      = whois.get("age_days", 0)
                w_created  = whois.get("creation_date", "Unknown")
                w_expires  = whois.get("expiration_date", "Unknown")
                w_registrar= whois.get("registrar", "Unknown")
                w_country  = whois.get("country", "Unknown")
                w_status   = (whois.get("status") or "unknown").replace("_", " ").title()
                wc1, wc2, wc3 = st.columns(3)
                with wc1:
                    st.metric("Domain Age",  f"{w_age} days" if w_age else "Unknown")
                    st.metric("Status",      w_status)
                with wc2:
                    st.metric("Registered",  w_created)
                    st.metric("Expires",     w_expires)
                with wc3:
                    st.metric("Registrar",   (w_registrar or "Unknown")[:24])
                    st.metric("Country",     w_country or "Unknown")
                if whois.get("error"):
                    st.warning(f"⚠️ {whois['error']}")

            # ── Cookie Security ───────────────────────────────────────────────
            cookies = det.get("cookies", {})
            if cookies and cookies.get("status") not in ("skipped", None):
                st.divider()
                st.markdown('<span class="section-tag tag-red">🍪 Cookie Security</span>', unsafe_allow_html=True)
                total_ck = cookies.get("total_cookies", 0)
                ck_issues = cookies.get("issues", [])
                ck1, ck2 = st.columns(2)
                with ck1:
                    st.metric("Cookies Found",   total_ck)
                with ck2:
                    st.metric("Security Issues", len(ck_issues))

                ck_details = cookies.get("cookie_details", [])
                if ck_details:
                    rows = ""
                    for c in ck_details:
                        sec_cls  = "flag-ok"  if c.get("secure")   else "flag-bad"
                        http_cls = "flag-ok"  if c.get("httponly") else "flag-bad"
                        sec_txt  = "✓ Secure"   if c.get("secure")   else "✗ Missing"
                        http_txt = "✓ HttpOnly" if c.get("httponly") else "✗ Missing"
                        samesite = c.get("samesite") or "Not Set"
                        rows += (
                            f"<tr><td><code>{c.get('name','?')}</code></td>"
                            f"<td class='{sec_cls}'>{sec_txt}</td>"
                            f"<td class='{http_cls}'>{http_txt}</td>"
                            f"<td>{samesite}</td></tr>"
                        )
                    st.markdown(f"""
                    <table class="ck-table">
                        <thead><tr><th>Cookie Name</th><th>Secure Flag</th><th>HttpOnly Flag</th><th>SameSite</th></tr></thead>
                        <tbody>{rows}</tbody>
                    </table>""", unsafe_allow_html=True)

                if ck_issues:
                    st.write("**Issues detected:**")
                    for iss in ck_issues:
                        st.write(f"  🍪 {iss}")
                elif total_ck > 0:
                    st.success("No cookie security issues found.")

                if cookies.get("error"):
                    st.warning(f"⚠️ {cookies['error']}")

            # ── URL Encoding ──────────────────────────────────────────────────
            enc = det.get("encoding", {})
            if enc:
                st.divider()
                is_encoded = enc.get("is_encoded", False)
                is_double  = enc.get("is_double_encoded", False)
                enc_issues = enc.get("issues", [])
                if is_double or is_encoded or enc_issues:
                    st.markdown('<span class="section-tag tag-yellow">🔗 URL Encoding</span>', unsafe_allow_html=True)
                    ec1, ec2 = st.columns(2)
                    with ec1:
                        st.write(f"Percent-Encoded: {'⚠️ Yes' if is_encoded else '✅ No'}")
                    with ec2:
                        st.write(f"Double-Encoded: {'🚨 Yes' if is_double else '✅ No'}")
                    for iss in enc_issues:
                        st.warning(f"⚠️ {iss}")
                else:
                    st.markdown('<span class="section-tag tag-green">🔗 URL Encoding</span>', unsafe_allow_html=True)
                    st.success("✅ Clean — no obfuscation or suspicious encoding detected.")

            # ── HTML Analysis ─────────────────────────────────────────────────
            html_d = det.get("html", {})
            if html_d and html_d.get("status") not in ("skipped", None):
                st.divider()
                st.markdown('<span class="section-tag tag-red">🌐 HTML Analysis</span>', unsafe_allow_html=True)
                risk_flags = html_d.get("risk_flags", [])
                hc1, hc2, hc3, hc4 = st.columns(4)
                with hc1:
                    st.metric("Password Field",  "⚠️ Yes" if html_d.get("has_password_input") else "✅ None")
                with hc2:
                    st.metric("Login Form",      "⚠️ Yes" if html_d.get("has_login_form") else "✅ None")
                with hc3:
                    st.metric("Ext. Form Action","🚨 Yes" if html_d.get("external_form_action") else "✅ Clean")
                with hc4:
                    st.metric("iFrames",         "⚠️ Yes" if html_d.get("has_iframe") else "✅ None")

                susp_scripts = html_d.get("suspicious_scripts", 0)
                fav_mismatch = html_d.get("favicon_mismatch", False)
                sc1, sc2 = st.columns(2)
                with sc1:
                    st.metric("Suspicious Scripts", susp_scripts if susp_scripts else "✅ None")
                with sc2:
                    st.metric("Favicon Mismatch",   "⚠️ Yes" if fav_mismatch else "✅ No")

                if risk_flags:
                    st.write("**🚩 Risk Flags:**")
                    for flag in risk_flags:
                        st.write(f"  • {flag}")
                elif not html_d.get("error"):
                    st.success("✅ No phishing patterns detected in page content.")

                if html_d.get("error"):
                    st.caption(f"Note: {html_d['error']}")


def render_url_scan_result(res: dict, expanded: bool = False):
    """Render a single URL scan result inline in the Streamlit app."""
    url      = res.get("url", "—")
    verdict  = res.get("verdict", "ERROR")
    score    = res.get("risk_score_pct", res.get("risk_score", 0) * 100)
    reasons  = res.get("risk_reasons", [])
    details  = res.get("details", {})
    domain   = res.get("domain", "")
    scan_t   = res.get("scan_type", "fast")
    cls      = _verdict_class(verdict)
    icon     = _verdict_icon(verdict)

    # Score bar colour
    if cls == "dangerous":  bar_color = "#ef4444"
    elif cls == "suspicious": bar_color = "#f59e0b"
    else:                     bar_color = "#10b981"

    reasons_html = "".join(f'<span class="reason-chip">⚑ {r}</span>' for r in reasons[:5])

    st.markdown(f"""
    <div class="url-card {cls}">
        <div class="url-verdict {cls}">{icon} {verdict}</div>
        <div class="url-domain">🌐 {url}</div>
        <div class="score-track"><div class="score-fill" style="width:{min(score,100):.1f}%;background:{bar_color}"></div></div>
        <div class="url-score">Risk Score: <strong>{score:.1f}%</strong> &nbsp;·&nbsp; Scan: <strong>{scan_t.upper()}</strong></div>
        <div style="margin-top:8px">{reasons_html}</div>
    </div>
    """, unsafe_allow_html=True)

    if details and expanded:
        with st.expander("🔬 Full Analysis Details"):
            # ML model
            ml = details.get("ml_model", {})
            if ml:
                st.markdown('<span class="section-tag tag-purple">AI/ML Model</span>', unsafe_allow_html=True)
                mc1, mc2 = st.columns(2)
                with mc1:
                    st.metric("Label",       ml.get("label", "—").upper())
                    st.metric("Probability", f"{ml.get('probability',0):.1f}%")
                with mc2:
                    if ml.get("risk_factors"):
                        st.write("**Risk Factors:**")
                        for rf in ml["risk_factors"]: st.write(f"  ⚠ {rf}")
                    if ml.get("safe_factors"):
                        st.write("**Safe Factors:**")
                        for sf in ml["safe_factors"]: st.write(f"  ✓ {sf}")
                if ml.get("summary"):
                    st.info(ml["summary"])

            # SSL
            ssl = details.get("ssl", {})
            if ssl:
                st.markdown('<span class="section-tag tag-green">SSL Certificate</span>', unsafe_allow_html=True)
                sc1, sc2, sc3 = st.columns(3)
                with sc1: st.metric("Status",   ssl.get("status", "—").upper())
                with sc2: st.metric("Valid",     "✅ Yes" if ssl.get("valid") else "❌ No")
                with sc3: st.metric("Expires In", f"{ssl.get('expires_in_days','?')} days")
                if ssl.get("error"):  st.warning(ssl["error"])
                if ssl.get("issuer"): st.caption(f"Issuer: {ssl['issuer']}")

            # WHOIS
            whois = details.get("whois", {})
            if whois:
                st.markdown('<span class="section-tag tag-yellow">WHOIS / Domain Age</span>', unsafe_allow_html=True)
                wc1, wc2 = st.columns(2)
                with wc1: st.metric("Domain Age", f"{whois.get('age_days','?')} days")
                with wc2: st.metric("Status",     whois.get("status","—").replace("_"," ").title())
                if whois.get("registrar"): st.caption(f"Registrar: {whois['registrar']}")

            # Cookies
            cookies = details.get("cookies", {})
            if cookies:
                st.markdown('<span class="section-tag tag-red">Cookie Security</span>', unsafe_allow_html=True)
                ck1, ck2 = st.columns(2)
                with ck1: st.metric("Total Cookies", cookies.get("total_cookies", 0))
                with ck2: st.metric("Security Issues", len(cookies.get("issues", [])))

                ck_details = cookies.get("cookie_details", [])
                if ck_details:
                    rows = ""
                    for c in ck_details:
                        sec_cls  = "flag-ok" if c.get("secure")   else "flag-bad"
                        http_cls = "flag-ok" if c.get("httponly") else "flag-bad"
                        sec_txt  = "✓" if c.get("secure")   else "✗"
                        http_txt = "✓" if c.get("httponly") else "✗"
                        rows += (
                            f"<tr><td>{c.get('name','?')}</td>"
                            f"<td class='{sec_cls}'>{sec_txt} Secure</td>"
                            f"<td class='{http_cls}'>{http_txt} HttpOnly</td>"
                            f"<td>{c.get('samesite','?')}</td></tr>"
                        )
                    st.markdown(f"""
                    <table class="ck-table">
                        <thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead>
                        <tbody>{rows}</tbody>
                    </table>""", unsafe_allow_html=True)

                if cookies.get("issues"):
                    st.write("**Issues:**")
                    for iss in cookies["issues"]: st.write(f"  🍪 {iss}")

            # Encoding
            enc = details.get("encoding", {})
            if enc and enc.get("risk"):
                st.markdown('<span class="section-tag tag-yellow">URL Encoding</span>', unsafe_allow_html=True)
                for iss in enc.get("issues", []): st.warning(iss)

            # HTML
            html_d = details.get("html", {})
            if html_d and not html_d.get("error"):
                st.markdown('<span class="section-tag tag-red">HTML Analysis</span>', unsafe_allow_html=True)
                hc1, hc2, hc3 = st.columns(3)
                with hc1: st.metric("Password Input", "⚠ Yes" if html_d.get("has_password_input") else "No")
                with hc2: st.metric("iFrame",         "⚠ Yes" if html_d.get("has_iframe") else "No")
                with hc3: st.metric("Ext. Form",      "🚨 Yes" if html_d.get("external_form_action") else "No")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN MONITORING LOOP
# ─────────────────────────────────────────────────────────────────────────────
if monitor and email_id and app_password:

    # Log into the IMAP server
    imap = imaplib.IMAP4_SSL(os.environ["GMAIL_IMAP_SERVER"], os.environ["GMAIL_IMAP_PORT"])
    imap.login(email_id, app_password)

    while True:
        imap.select('INBOX')
        typ, data = imap.search(None, '(UNSEEN)')

        if typ == 'OK':
            if len(data[0].split()) == 0:
                st.info("📭 No new unseen messages.", icon="ℹ️")
            else:
                st.success(f"📬 {len(data[0].split())} new email(s) found! Analysing…")

            for num in data[0].split():
                typ, msg_data = imap.fetch(num, '(RFC822)')
                if typ != 'OK':
                    continue

                raw_email     = msg_data[0][1]
                email_message = email.message_from_bytes(raw_email)
                subject       = email_message['Subject']
                sender        = email_message['From']
                body          = get_email_body(email_message)

                # ── Full pipeline analysis ─────────────────────────
                analysis     = analyze_email(email_message=email_message,
                                             sender=sender or "",
                                             subject=subject or "",
                                             body=body or "")

                fraud         = analysis["fraud_analysis"]["is_fraud"]
                ai_written    = analysis["ai_detection"]["is_ai_generated"]
                risk_level    = analysis["overall_risk"]
                extracted     = analysis.get("extracted_data", {"urls": [], "credentials": []})
                found_urls    = [u["url"] for u in extracted.get("urls", [])]

                # ── Expander colour ────────────────────────────────
                if "HIGH"   in risk_level: risk_icon = "🔴"
                elif "MEDIUM" in risk_level: risk_icon = "🟡"
                else:                        risk_icon = "🟢"

                with st.expander(f"{risk_icon} {subject}", expanded=True):

                    # ── Basic info ─────────────────────────────────
                    st.subheader("📨 Email Details")
                    di1, di2 = st.columns(2)
                    with di1:
                        st.write(f"**From:** {sender}")
                        st.write(f"**Subject:** {subject}")
                    with di2:
                        if "HIGH"   in risk_level: st.error(f"**{risk_level}**")
                        elif "MEDIUM" in risk_level: st.warning(f"**{risk_level}**")
                        else:                        st.success(f"**{risk_level}**")

                    with st.expander("📄 Email Body"):
                        st.write(body)

                    st.divider()

                    # ── Pipeline Summary Card ──────────────────────
                    fsd = analysis.get("fused_score_details", {}) or {}
                    if fsd:
                        fs_score    = fsd.get("risk_score", 0)
                        fs_tier     = fsd.get("tier",   "UNKNOWN")
                        fs_action   = fsd.get("outlook_action", "—")
                        fs_scorer   = fsd.get("scorer_used", "—")
                        fs_roberta  = fsd.get("roberta_prob")
                        fs_rule     = fsd.get("rule_score", 0)
                        fs_ai       = fsd.get("ai_prob", 0)
                        fs_header   = fsd.get("header_score", 0)
                        tier_color  = {"CRITICAL":"#dc2626","HIGH":"#ea580c",
                                       "MEDIUM":"#ca8a04","LOW":"#16a34a"}.get(fs_tier,"#6b7280")
                        score_bar   = "█" * int(fs_score / 10) + "░" * (10 - int(fs_score / 10))
                        st.markdown(f"""
<div style="background:linear-gradient(135deg,#0f172a,#1e293b);
     border:1px solid {tier_color}55;border-radius:12px;padding:16px 20px;margin-bottom:12px">
  <div style="font-size:.72rem;color:#94a3b8;font-weight:600;letter-spacing:.08em;
       text-transform:uppercase;margin-bottom:10px">🧠 FraudShield AI — 7-Layer Pipeline Score</div>
  <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">
    <div style="font-size:2.2rem;font-weight:800;color:{tier_color}">{fs_score}</div>
    <div>
      <div style="font-size:.9rem;color:#e2e8f0;font-weight:700">{fs_tier} — {fs_action}</div>
      <div style="font-family:monospace;color:{tier_color};font-size:.85rem;letter-spacing:1px">{score_bar}</div>
      <div style="font-size:.72rem;color:#64748b;margin-top:2px">Scorer: {fs_scorer}</div>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px">
    <div style="background:#0f172a;border-radius:8px;padding:8px;text-align:center">
      <div style="font-size:.65rem;color:#64748b">RoBERTa</div>
      <div style="font-size:1rem;color:#818cf8;font-weight:700">{f"{fs_roberta:.0%}" if fs_roberta is not None else "N/A"}</div>
    </div>
    <div style="background:#0f172a;border-radius:8px;padding:8px;text-align:center">
      <div style="font-size:.65rem;color:#64748b">Rule-Based</div>
      <div style="font-size:1rem;color:#f59e0b;font-weight:700">{fs_rule:.0f}/100</div>
    </div>
    <div style="background:#0f172a;border-radius:8px;padding:8px;text-align:center">
      <div style="font-size:.65rem;color:#64748b">AI-Text</div>
      <div style="font-size:1rem;color:#a78bfa;font-weight:700">{fs_ai:.0%}</div>
    </div>
    <div style="background:#0f172a;border-radius:8px;padding:8px;text-align:center">
      <div style="font-size:.65rem;color:#64748b">Header</div>
      <div style="font-size:1rem;color:#34d399;font-weight:700">{fs_header}/100</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)
                        if fsd.get("top_indicators"):
                            with st.expander("🔎 ML Indicators", expanded=False):
                                for ind in fsd["top_indicators"]:
                                    st.write(f"• {ind}")

                    # ── Unified Phishing Score Card ────────────────
                    uni = analysis.get("unified_score", {}) or {}
                    fsd = analysis.get("fused_score_details", {}) or {}
                    if uni:
                        fs   = uni.get("final_score", 0)
                        tier = uni.get("tier", "LOW")
                        act  = uni.get("outlook_action", "ALLOW")
                        verd = uni.get("verdict", "LEGITIMATE")
                        conf = uni.get("confidence_label", "")
                        expl = uni.get("explanation", "")
                        sigs = uni.get("all_signals", {})
                        tc   = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#ca8a04","LOW":"#16a34a"}.get(tier,"#6b7280")
                        bar  = "█" * int(fs/10) + "░" * (10 - int(fs/10))
                        st.markdown(f"""
<div style="background:linear-gradient(135deg,#0f172a,#1e293b);
     border:2px solid {tc}66;border-radius:14px;padding:20px 24px;margin-bottom:14px">
  <div style="font-size:.68rem;color:#94a3b8;font-weight:600;letter-spacing:.1em;
       text-transform:uppercase;margin-bottom:10px">🧠 FraudShield AI — Unified Phishing Score</div>
  <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
    <div style="font-size:3rem;font-weight:800;color:{tc};line-height:1">{fs}</div>
    <div>
      <div style="font-size:1rem;color:#e2e8f0;font-weight:700">{verd} — {tier} ({'⚠️ Action: ' + act})</div>
      <div style="font-family:monospace;color:{tc};font-size:.9rem;letter-spacing:2px;margin:2px 0">{bar}</div>
      <div style="font-size:.75rem;color:#94a3b8">{conf}</div>
    </div>
  </div>
  <div style="background:#0f172a;border-radius:8px;padding:12px;margin-top:12px;
       font-size:.88rem;color:#cbd5e1;line-height:1.6;border-left:3px solid {tc}">
    <strong>🔍 Analyst Summary:</strong> {expl}
  </div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px">
    <div style="background:#1e293b;border-radius:8px;padding:8px;text-align:center">
      <div style="font-size:.6rem;color:#64748b;text-transform:uppercase">ML Model</div>
      <div style="font-size:.95rem;color:#818cf8;font-weight:700">{sigs.get('ml_score',0):.0f}/100</div>
      <div style="font-size:.6rem;color:#475569">{sigs.get('scorer_used','?')}</div>
    </div>
    <div style="background:#1e293b;border-radius:8px;padding:8px;text-align:center">
      <div style="font-size:.6rem;color:#64748b;text-transform:uppercase">LLM Analysis</div>
      <div style="font-size:.95rem;color:#f59e0b;font-weight:700">{sigs.get('llm_score',0):.0f}/100</div>
    </div>
    <div style="background:#1e293b;border-radius:8px;padding:8px;text-align:center">
      <div style="font-size:.6rem;color:#64748b;text-transform:uppercase">Rule-Based</div>
      <div style="font-size:.95rem;color:#34d399;font-weight:700">{sigs.get('rule_score',0):.0f}/100</div>
    </div>
    <div style="background:#1e293b;border-radius:8px;padding:8px;text-align:center">
      <div style="font-size:.6rem;color:#64748b;text-transform:uppercase">Voice</div>
      <div style="font-size:.95rem;color:#a78bfa;font-weight:700">{sigs.get('voice_score',0)}/100</div>
    </div>
  </div>
</div>""", unsafe_allow_html=True)
                        if uni.get("top_indicators"):
                            with st.expander("🔎 All Detection Indicators", expanded=False):
                                for i, ind in enumerate(uni["top_indicators"], 1):
                                    st.write(f"**{i}.** {ind}")

                    # ── Attachments ────────────────────────────────
                    st.subheader("📎 Attachments")
                    raw_files = analysis.get("attachments", {}).get("files", [])
                    if not raw_files:
                        st.write("No attachments found.")
                    else:
                        st.write(f"**{len(raw_files)} attachment(s) found:**")
                        for att in raw_files:
                            fname = att.get('filename', att.get('name', 'unknown'))
                            ftype = att.get('type',     att.get('extension', ''))
                            va    = att.get('voice_analysis')
                            st.write(f"• `{fname}` ({ftype})")

                            if va:
                                st.markdown("---")
                                verdict_v = va.get('verdict', 'UNKNOWN')
                                risk_v    = va.get('risk_score', 0)
                                tier_v    = va.get('tier', 'UNKNOWN')
                                conf_v    = va.get('confidence_pct', 'N/A')
                                ind_v     = va.get('indicators', [])
                                err_v     = va.get('error')
                                st.markdown(f"##### 🎙️ Voice Deepfake Scan — `{fname}`")
                                if err_v: st.warning(f"⚠️ Scan note: {err_v}")
                                if "FAKE" in str(verdict_v):
                                    st.error(f"🚨 **{verdict_v}** — AI-generated voice detected!")
                                else:
                                    st.success(f"✅ **{verdict_v}** — Voice appears authentic")
                                vc1, vc2, vc3 = st.columns(3)
                                with vc1: st.metric("Risk Score",  f"{risk_v}/100")
                                with vc2: st.metric("Tier",        tier_v)
                                with vc3: st.metric("Confidence",  conf_v)
                                st.info(f"**Recommended Action:** {va.get('action','')}")
                                if ind_v:
                                    st.write("**🔍 Voice Indicators:**")
                                    for i in ind_v: st.write(f"• {i}")
                                with st.expander("🔧 Technical Details"):
                                    st.write(f"**Model**: {va.get('model_used','best_eer.pt')}")
                                    st.write(f"**Audio chunks analyzed**: {va.get('chunks_analyzed',0)}")
                                    st.write(f"**Speech chunks used**: {va.get('speech_chunks',0)}")
                                    st.write(f"**Processing time**: {va.get('processing_ms',0)} ms")
                                st.markdown("---")

                    st.divider()

                    # ── Fraud Detection ────────────────────────────
                    st.subheader("🚨 Fraud Detection")
                    fd1, fd2 = st.columns(2)
                    with fd1:
                        st.metric("Fraud Detected",    "YES ⚠️" if fraud else "NO ✅")
                        st.metric("Rule-Based Score",  f"{analysis['fraud_analysis']['rule_based']['score']}/100")
                    with fd2:
                        st.metric("LLM Verdict",       analysis['fraud_analysis']['llm_based']['verdict'])
                        st.metric("LLM Confidence",    str(analysis['fraud_analysis']['llm_based']['confidence']))

                    rule_reasons = analysis['fraud_analysis']['rule_based']['reasons']
                    if rule_reasons:
                        st.write("**🔍 Rule-Based Indicators:**")
                        for r in rule_reasons: st.write(f"• {r}")
                    llm_flags = analysis['fraud_analysis']['llm_based']['red_flags']
                    if llm_flags:
                        st.write("**🤖 LLM Red Flags:**")
                        for f in llm_flags: st.write(f"• {f}")
                    llm_expl = analysis['fraud_analysis']['llm_based']['explanation']
                    if llm_expl:
                        st.info(f"**LLM Analysis:** {llm_expl}")

                    st.divider()

                    # ── AI Content Detection ───────────────────────
                    st.subheader("🤖 AI-Generated Content Detection")
                    ac1, ac2 = st.columns(2)
                    with ac1: st.metric("AI Written", "YES 🤖" if ai_written else "NO ✍️")
                    with ac2: st.metric("AI Score",   f"{analysis['ai_detection']['confidence_score']}/100")
                    ai_ind = analysis['ai_detection']['indicators']
                    if ai_ind:
                        st.write("**AI Writing Indicators:**")
                        for i in ai_ind: st.write(f"• {i}")

                    st.divider()

                    # ── DistilBERT Zero-Shot Classifier (supplemental) ─────
                    st.subheader("🤗 DistilBERT Supplemental Classifier")
                    with st.spinner("🤖 Running DistilBERT zero-shot classification…"):
                        try:
                            ml_res = detector.predict(body or "")
                        except Exception as _e:
                            ml_res = {
                                "label": "unknown", "confidence": "N/A",
                                "risk_level": "UNKNOWN ⚪", "is_phishing": False,
                                "is_ai_generated": False, "probabilities": {},
                                "error": str(_e), "model": "failed",
                            }

                    ml1, ml2, ml3 = st.columns(3)
                    with ml1:
                        st.metric("🛡️ Verdict",
                                  "PHISHING 🚨" if ml_res['is_phishing'] else "CLEAN ✅")
                    with ml2:
                        st.metric("🔖 Confidence", ml_res['confidence'])
                    with ml3:
                        st.metric("⚠️ Risk", ml_res['risk_level'])

                    if ml_res.get('top_category'):
                        st.caption(
                            f"🎯 DistilBERT top category: **{ml_res['top_category']}**  "
                            f"— model: `{ml_res.get('model', 'distilbert-zero-shot')}`"
                        )

                    if ml_res.get('all_scores'):
                        with st.expander("📊 Category Scores", expanded=False):
                            for cat, sc in ml_res['all_scores'].items():
                                is_phish_cat = any(
                                    k in cat for k in ["phishing", "fraud", "malware", "spam"]
                                )
                                bar_color = "🟥" if is_phish_cat else "🟩"
                                st.write(f"{bar_color} `{cat}`: **{sc}**")
                    elif ml_res.get('note'):
                        st.caption(f"⚠️ {ml_res['note']}")
                    if ml_res.get('error'):
                        st.error(f"DistilBERT error: {ml_res['error']}")

                    st.divider()

                    # ── Extracted Metadata ─────────────────────────
                    st.subheader("🕵️ Extracted Data")
                    if extracted["urls"]:
                        st.write(f"**🔗 {len(found_urls)} URL(s) found in email:**")
                        for u_info in extracted["urls"]:
                            label = "🚨" if u_info["type"] == "SUSPICIOUS" else "🔗"
                            st.write(f"{label} `{u_info['url']}`")
                    if extracted["credentials"]:
                        st.write("**🔐 Sensitive Info Found:**")
                        for c in extracted["credentials"]:
                            if c["type"] in ["EXTRACTED_PASSWORD","CVV","PIN","CREDIT_CARD_FORMAT"]:
                                st.error(f"⚠️ **{c['type']}**: `{c['value']}`")
                            else:
                                st.write(f"🔐 **{c['type']}**: `{c['value']}`")

                    # ════════════════════════════════════════════════
                    # 🔍  PHISHGUARD URL SCANNER  ════════════════════
                    # ════════════════════════════════════════════════
                    if found_urls:
                        st.divider()
                        st.subheader("🔍 PhishGuard URL Scanner")

                        # Build a unique key combining email number + subject hash
                        email_key = f"email_{num.decode() if isinstance(num,bytes) else num}"

                        # Session state keys
                        fs_key   = f"{email_key}_fast_done"
                        ds_key   = f"{email_key}_deep_done"
                        fs_res   = f"{email_key}_fast_results"
                        ds_res   = f"{email_key}_deep_results"

                        # ── Fast Scan (enhanced, runs automatically on first view) ──
                        if fs_key not in st.session_state:
                            with st.spinner(f"⚡ Scanning {len(found_urls)} URL(s) — ML + SSL + WHOIS + Fingerprint…"):
                                st.session_state[fs_res] = scan_urls(found_urls, mode="fast")
                            st.session_state[fs_key] = True

                        fast_results = st.session_state.get(fs_res, [])

                        # ── Summary stats ──────────────────────────────────
                        st.markdown("""
                        <div class="url-scan-panel">
                            <h4>🔍 URL Threat Intelligence (30+ metrics)</h4>
                        </div>
                        """, unsafe_allow_html=True)

                        n_dangerous  = sum(1 for r in fast_results if _verdict_class(r.get("verdict","")) == "dangerous")
                        n_suspicious = sum(1 for r in fast_results if _verdict_class(r.get("verdict","")) == "suspicious")
                        n_safe       = sum(1 for r in fast_results if _verdict_class(r.get("verdict","")) == "safe")

                        fcols = st.columns(4)
                        with fcols[0]: st.metric("Total URLs",   len(fast_results))
                        with fcols[1]: st.metric("🚨 Dangerous",  n_dangerous)
                        with fcols[2]: st.metric("⚠️ Suspicious", n_suspicious)
                        with fcols[3]: st.metric("✅ Safe",        n_safe)

                        for res in fast_results:
                            _render_enhanced_url(res)

                    else:
                        st.info("🔗 No URLs found in this email — URL scan skipped.")

                    # ── Credential Scanner Section ──────────────────
                    cred_scan = analysis.get("credential_scan", {}) or {}
                    if cred_scan and cred_scan.get("total_findings", 0) > 0:
                        st.divider()
                        st.subheader("🔐 Credential & Sensitive Data Scanner")
                        rl = cred_scan.get("risk_label", "LOW")
                        rl_color = {"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#ca8a04","LOW":"#16a34a"}.get(rl.upper(),"#64748b")
                        cs1, cs2, cs3 = st.columns(3)
                        with cs1: st.metric("Credentials Found", cred_scan.get("total_findings",0))
                        with cs2: st.metric("Risk Level",        rl)
                        with cs3: st.metric("Risk Score",        f"{cred_scan.get('risk_score',0)}/100")
                        if cred_scan.get("human_summary"):
                            st.markdown(f'<div style="background:#1e293b;border-left:3px solid {rl_color};'
                                        f'border-radius:6px;padding:10px 14px;color:#e2e8f0;font-size:.88rem;margin-bottom:10px">'
                                        f'📋 {cred_scan["human_summary"]}</div>', unsafe_allow_html=True)
                        findings = cred_scan.get("findings", [])
                        if findings:
                            with st.expander(f"🔍 View {len(findings)} Credential Finding(s)", expanded=False):
                                for fnd in findings:
                                    sev  = fnd.get("severity","LOW").upper()
                                    icon = {"CRITICAL":"🚨","HIGH":"⚠️","MEDIUM":"🔶","LOW":"ℹ️"}.get(sev,"•")
                                    val  = str(fnd.get("value",""))
                                    masked = val[:4] + "****" + val[-2:] if len(val) > 6 else "****"
                                    st.write(f"{icon} **{fnd.get('type','?')}** [{sev}]: `{masked}`")
                                    if fnd.get("context"):
                                        st.caption(f"   Context: {str(fnd['context'])[:80]}")

                    st.divider()

                    # ── Routing ────────────────────────────────────
                    st.subheader("📤 Routing")
                    try:
                        with open(_RAG_JSON_PATH, 'r') as f:
                            rag_data = loads(f.read())
                        raw_routing = return_ans(
                            f"From: {sender}\n\nSubject: {subject}\n\nBody: {body or ''}"
                        )['team']
                        clean_id = "".join(filter(str.isdigit, raw_routing))
                        team_name = "Unknown Team"
                        for node in rag_data['nodes']:
                            if str(node.get('id')) == clean_id:
                                team_name = node['name']
                                break
                        st.success(f"**Routed to**: {team_name} (ID: {clean_id})")
                        st.write(f"This email has been assigned to the **{team_name}** department.")
                    except Exception as e:
                        st.error(f"Routing Error: {e}")

                    if fraud:
                        st.warning("⚠️ Fraud suspected — please verify before acting on this routing.")

                    # ── n8n Incident & Human-in-Loop ───────────────────────
                    n8n_inc = analysis.get("n8n_incident", {}) or {}
                    if n8n_inc:
                        st.divider()
                        st.subheader("🔔 Incident Response (n8n)")
                        fsd2   = analysis.get("fused_score_details", {}) or {}
                        inc_id = n8n_inc.get("incident_id", "—")
                        pred_id= analysis.get("prediction_id", "—")
                        if n8n_inc.get("triggered"):
                            n8n_tier = fsd2.get("tier","HIGH")
                            n8n_color= {"CRITICAL":"#dc2626","HIGH":"#ea580c",
                                        "MEDIUM":"#ca8a04","LOW":"#16a34a"}.get(n8n_tier,"#6b7280")
                            st.markdown(f"""
<div style="background:#0f172a;border:1px solid {n8n_color}88;
     border-radius:10px;padding:14px 18px;margin-bottom:10px">
  <div style="font-size:.68rem;color:#94a3b8;font-weight:600;letter-spacing:.08em;
       text-transform:uppercase;margin-bottom:8px">🔔 n8n Incident Created</div>
  <div style="color:#e2e8f0">
    <strong>Incident ID:</strong> <code style="color:{n8n_color}">{inc_id}</code> &nbsp;|&nbsp;
    <strong>Prediction ID:</strong> <code>{pred_id}</code> &nbsp;|&nbsp;
    <strong>Tier:</strong> <span style="color:{n8n_color};font-weight:700">{n8n_tier}</span>
  </div>
  <div style="font-size:.8rem;color:#64748b;margin-top:4px">{n8n_inc.get("message","")}</div>
</div>""", unsafe_allow_html=True)

                            # Human-in-loop for CRITICAL tier
                            approve_url = n8n_inc.get("approve_url")
                            reject_url  = n8n_inc.get("reject_url")
                            if approve_url and reject_url:
                                st.markdown("""
<div style="background:linear-gradient(135deg,#450a0a,#1c0505);
     border:1px solid #dc262688;border-radius:10px;padding:14px 18px">
  <div style="font-size:.72rem;color:#fca5a5;font-weight:600;letter-spacing:.08em;
       text-transform:uppercase;margin-bottom:8px">🚨 CRITICAL — Human Approval Required</div>
  <div style="font-size:.85rem;color:#fecdd3;margin-bottom:10px">
    This email has been escalated. A bank analyst must approve or reject the action below.
  </div>
""", unsafe_allow_html=True)
                                col_a, col_r = st.columns(2)
                                with col_a:
                                    st.link_button("✅  APPROVE quarantine", approve_url,
                                                   use_container_width=True, type="primary")
                                with col_r:
                                    st.link_button("❌  REJECT — allow email", reject_url,
                                                   use_container_width=True)
                                st.markdown("</div>", unsafe_allow_html=True)
                                st.caption(f"Prediction ID for audit: `{pred_id}`")
                        else:
                            st.info(f"ℹ️ n8n not triggered ({n8n_inc.get('message','score below threshold')})")

                    # ── LLM SMS Alert (HIGH RISK only) ─────────────────────
                    if "HIGH" in risk_level:
                        st.divider()
                        st.subheader("📱 LLM-Generated SMS Alert")
                        sms_key = f"sms_{email_key}"
                        if sms_key not in st.session_state:
                            with st.spinner("✍️ Generating SMS alert via LLM…"):
                                llm_expl_for_sms = analysis['fraud_analysis']['llm_based']['explanation']
                                llm_flags_for_sms = analysis['fraud_analysis']['llm_based']['red_flags']
                                st.session_state[sms_key] = generate_sms_alert(
                                    sender or "Unknown",
                                    subject or "No Subject",
                                    risk_level,
                                    llm_expl_for_sms,
                                    llm_flags_for_sms,
                                )
                        sms_text = st.session_state.get(sms_key, "")
                        st.markdown("""
                        <div style="background:#1a0a2e;border:1px solid rgba(168,85,247,.4);
                            border-radius:12px;padding:18px 22px;">
                            <div style="font-size:.72rem;color:#a78bfa;font-weight:600;
                                letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">
                                📲 Draft SMS Alert (160 chars)
                            </div>
                        </div>""", unsafe_allow_html=True)
                        st.code(sms_text, language=None)
                        char_count = len(sms_text)
                        color = "#4ade80" if char_count <= 160 else "#f87171"
                        st.caption(f"Characters: **{char_count}/160** — "
                                   f"{'✅ Within SMS limit' if char_count <= 160 else '⚠️ Exceeds SMS limit'}")
                        if st.button("🔄 Regenerate SMS", key=f"regen_sms_{email_key}"):
                            st.session_state.pop(sms_key, None)
                            st.rerun()


        with st.spinner('🔄 Checking for new mail in 10 seconds…'):
            time.sleep(10)