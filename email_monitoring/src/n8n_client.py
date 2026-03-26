"""
n8n_client.py
─────────────────────────────────────────────────────────────────────────────
Client for posting fraud incidents to the n8n automation workflow.

Workflow: fraudshield_n8n_v3.json
  Webhook:          POST http://localhost:5678/webhook/fraudshield
  Approval webhook: POST http://localhost:5678/webhook/fraudshield-approval
                        ?incident_id=X&approved=true|false&prediction_id=Y

Fires for:
  CRITICAL (score ≥ 70) → LLM summary → approval email → human-in-loop
  HIGH     (score ≥ 61) → LLM summary → Slack alert

Low-latency by design — HTTP timeout 5 s, two retries (1 s gap) so the
Streamlit UI never blocks for long if n8n is down.
"""
from __future__ import annotations

import time
import json
import uuid
import urllib.request
import urllib.error
import urllib.parse
from typing import Optional
import approval_server   # auto-starts local approval server on port 5679

# ── Configuration ──────────────────────────────────────────────────────────────
N8N_BASE_URL          = "http://localhost:5678"
INCIDENT_WEBHOOK      = f"{N8N_BASE_URL}/webhook/fraudshield"
APPROVAL_WEBHOOK_BASE = f"{N8N_BASE_URL}/webhook/fraudshield-approval"

_MIN_SCORE_FOR_N8N = 61          # Only HIGH and CRITICAL trigger n8n
_TIMEOUT_SECONDS   = 5
_RETRIES           = 2


# ── Helpers ────────────────────────────────────────────────────────────────────

def _approval_url(incident_id: str, prediction_id: str, approved: bool) -> str:
    params = urllib.parse.urlencode({
        "incident_id":   incident_id,
        "approved":      "true" if approved else "false",
        "prediction_id": prediction_id,
    })
    return f"{APPROVAL_WEBHOOK_BASE}?{params}"


def _post_json(url: str, payload: dict) -> dict:
    data    = json.dumps(payload, default=str).encode("utf-8")
    req     = urllib.request.Request(
        url,
        data    = data,
        method  = "POST",
        headers = {"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ── Public API ─────────────────────────────────────────────────────────────────

def trigger_incident(
    risk_score:        int,
    verdict:           str,
    tier:              str,
    outlook_action:    str,
    top_indicators:    list,
    sender:            str,
    subject:           str,
    llm_summary:       str           = "",
    ai_prob:           float         = 0.0,
    voice_deepfake:    bool          = False,
    prediction_id:     Optional[str] = None,
) -> dict:
    """
    Post a fraud incident to the n8n webhook.

    Only fires when risk_score ≥ 61 (HIGH or CRITICAL).
    Returns a dict with:
        triggered       bool
        incident_id     str
        approve_url     str   (CRITICAL only)
        reject_url      str   (CRITICAL only)
        message         str
        n8n_response    dict | None
    """
    if prediction_id is None:
        prediction_id = f"FS-{int(time.time() * 1000)}"

    # Below threshold — do not call n8n (avoid noise)
    if risk_score < _MIN_SCORE_FOR_N8N:
        return {
            "triggered":   False,
            "incident_id": prediction_id,
            "approve_url": None,
            "reject_url":  None,
            "message":     f"score {risk_score} below threshold ({_MIN_SCORE_FOR_N8N})",
            "n8n_response": None,
        }

    incident_id  = f"INC-{uuid.uuid4().hex[:8].upper()}"
    # Local approval server handles the GET click from email; no dependency on n8n Wait node
    a_url = approval_server.approve_url(incident_id, prediction_id) if tier == "CRITICAL" else None
    r_url = approval_server.reject_url(incident_id, prediction_id)  if tier == "CRITICAL" else None

    payload = {
        # Core fields expected by fraudshield_n8n_v3.json
        "risk_score":               risk_score,
        "verdict":                  verdict,
        "tier":                     tier,
        "outlook_action":           outlook_action,
        "prediction_id":            prediction_id,
        "top_indicators":           top_indicators[:6],
        # Email meta
        "email_preview":            f"From: {sender}\nSubject: {subject}",
        "sender":                   sender,
        "subject":                  subject,
        # Optional enrichment
        "llm_summary":              llm_summary[:500] if llm_summary else "",
        "ai_generated_probability": round(ai_prob, 4),
        "voice_deepfake_detected":  voice_deepfake,
        # Incident tracking
        "incident_id":              incident_id,
        "source_module":            "email_monitoring",
        "timestamp":                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # Human-in-loop URLs — served by local approval_server (port 5679), always work
        "approve_url":              a_url,
        "reject_url":               r_url,
    }

    n8n_resp = None
    for attempt in range(1, _RETRIES + 1):
        try:
            n8n_resp = _post_json(INCIDENT_WEBHOOK, payload)
            print(f"[n8n] ✅ Incident {incident_id} posted (score={risk_score}, tier={tier})")
            break
        except urllib.error.URLError as exc:
            msg = f"[n8n] attempt {attempt}/{_RETRIES} failed: {exc}"
            print(msg)
            if attempt < _RETRIES:
                time.sleep(1.0)
        except Exception as exc:
            print(f"[n8n] unexpected error: {exc}")
            break

    return {
        "triggered":    True,
        "incident_id":  incident_id,
        "approve_url":  a_url,
        "reject_url":   r_url,
        "message":      f"{tier} incident {incident_id} posted to n8n" if n8n_resp is not None
                        else "n8n unreachable — incident logged locally",
        "n8n_response": n8n_resp,
    }
