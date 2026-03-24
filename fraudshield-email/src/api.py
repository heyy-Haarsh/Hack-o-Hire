# src/api.py
import os
import sys
import email as email_lib
from pathlib import Path
from contextlib import asynccontextmanager
import threading
import requests as http_requests
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from evaluate import load_models, predict_email
from database import init_db, log_prediction, save_feedback, get_feedback_stats
from ai_text_detector import load_ai_detector, load_perplexity_model

# ── n8n Integration ────────────────────────────────────────────────
N8N_WEBHOOK_URL = os.environ.get(
    "N8N_WEBHOOK_URL",
    "http://localhost:5678/webhook/fraudshield"
)
N8N_ENABLED = True  # set False to disable without code change


def fire_n8n_webhook(result: dict, email_text: str, source: str = "email_api"):
    """
    Fire-and-forget POST to n8n incident response workflow.
    Always runs in a daemon thread — NEVER blocks email analysis.
    Only triggers for HIGH and CRITICAL tiers.
    """
    if not N8N_ENABLED:
        return
    tier = result.get("tier", "LOW")
    if tier not in ("CRITICAL", "HIGH"):
        return

    payload = {
        "source":      source,
        "tier":        tier,
        "risk_score":  result.get("risk_score", 0),
        "verdict":     result.get("verdict", "UNKNOWN"),
        "prediction_id": result.get("prediction_id"),
        "top_indicators": result.get("top_indicators", [])[:5],
        "header_flags":   result.get("header_flags", [])[:3],
        "ai_generated":   result.get("ai_generated_probability", 0) > 0.5,
        "outlook_action": result.get("outlook_action", "FLAG"),
        "email_preview":  email_text[:300] if email_text else "",
        "llm_summary":    result.get("explanation", ""),
    }

    def _post():
        try:
            http_requests.post(N8N_WEBHOOK_URL, json=payload, timeout=3)
            print(f"[n8n] Incident fired — tier={tier} score={payload['risk_score']}")
        except Exception as e:
            print(f"[n8n] Webhook skipped (n8n not running): {e}")

    t = threading.Thread(target=_post, daemon=True)
    t.start()


# ── Lifespan — runs on startup and shutdown ────────────────────────
@asynccontextmanager
async def lifespan(app):
    app.state.tokenizer, app.state.model = load_models()
    load_ai_detector()
    load_perplexity_model()
    init_db()
    print("[API] All models pre-loaded. Ready on port 8001.")
    yield


# ── App — defined ONCE with lifespan and middleware ────────────────
app = FastAPI(
    title="FraudShield Email API",
    description="AI phishing detection — Barclays Hack-o-Hire",
    version="1.0.0",
    lifespan=lifespan
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)


# ── Request models ─────────────────────────────────────────────────
class EmailRequest(BaseModel):
    text:     str
    subject:  str  = ""
    sender:   str  = ""
    receiver: str  = ""
    reply_to: str  = ""
    cc:       str  = ""
    use_llm:  bool = False


class FeedbackRequest(BaseModel):
    email_text:    str = ""
    email_subject: str = ""
    email_sender:  str = ""
    model_verdict: str = ""
    model_score:   int = 0
    user_verdict:  str = ""
    prediction_id: int = None
    notes:         str = ""


# ── Endpoints ──────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "module": "email_phishing_detector", "port": 8001}


@app.post("/analyze/email")
async def analyze_email(req: EmailRequest):
    result = predict_email(
        email_text = req.text,
        subject    = req.subject,
        sender     = req.sender,
        receiver   = req.receiver,
        reply_to   = req.reply_to,
        cc         = req.cc,
        tokenizer  = app.state.tokenizer,
        model      = app.state.model,
        use_llm    = req.use_llm
    )
    pred_id = log_prediction(result, req.text)
    result["prediction_id"] = pred_id
    # ── n8n incident response ──────────────────────────────────────
    fire_n8n_webhook(result, req.text, source="email_api")
    return result


@app.post("/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files supported")
    content  = await file.read()
    msg      = email_lib.message_from_bytes(content)
    subject  = msg.get("Subject",  "")
    sender   = msg.get("From",     "")
    reply_to = msg.get("Reply-To", "")
    receiver = msg.get("To",       "")
    cc       = msg.get("Cc",       "")
    body     = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(
                    "utf-8", errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
    result = predict_email(
        email_text = body,
        subject    = subject,
        sender     = sender,
        receiver   = receiver,
        reply_to   = reply_to,
        cc         = cc,
        tokenizer  = app.state.tokenizer,
        model      = app.state.model
    )
    pred_id = log_prediction(result, body)
    result["prediction_id"] = pred_id
    # ── n8n incident response ──────────────────────────────────────
    fire_n8n_webhook(result, body, source="eml_upload")
    return result


@app.post("/outlook/webhook")
async def outlook_webhook(payload: dict):
    subject  = payload.get("subject", "")
    body     = payload.get("body", {}).get("content", "")
    sender   = payload.get("sender", {}).get(
                   "emailAddress", {}).get("address", "")
    reply_to = payload.get("replyTo", [{}])[0].get(
                   "emailAddress", {}).get("address", "") \
               if payload.get("replyTo") else ""
    receiver = payload.get("toRecipients", [{}])[0].get(
                   "emailAddress", {}).get("address", "") \
               if payload.get("toRecipients") else ""
    result = predict_email(
        email_text = body,
        subject    = subject,
        sender     = sender,
        receiver   = receiver,
        reply_to   = reply_to,
        tokenizer  = app.state.tokenizer,
        model      = app.state.model
    )
    pred_id = log_prediction(result, body)
    result["prediction_id"] = pred_id
    # ── n8n incident response ──────────────────────────────────────
    fire_n8n_webhook(result, body, source="outlook_webhook")
    return {
        "messageId":     payload.get("id", ""),
        "action":        result["outlook_action"],
        "riskScore":     result["risk_score"],
        "verdict":       result["verdict"],
        "tier":          result["tier"],
        "topIndicators": result["top_indicators"][:3],
        "headerFlags":   result.get("header_flags", []),
        "aiGenerated":   result["ai_generated_probability"] > 0.5,
        "predictionId":  pred_id,
    }


@app.post("/feedback")
async def submit_feedback(req: FeedbackRequest):
    if req.user_verdict not in ("LEGITIMATE", "PHISHING"):
        raise HTTPException(400, "user_verdict must be LEGITIMATE or PHISHING")
    return save_feedback(
        email_subject = req.email_subject,
        email_sender  = req.email_sender,
        email_text    = req.email_text,
        model_verdict = req.model_verdict,
        model_score   = req.model_score,
        user_verdict  = req.user_verdict,
        prediction_id = req.prediction_id,
        notes         = req.notes,
    )


@app.get("/feedback/stats")
async def feedback_statistics():
    return get_feedback_stats()


@app.get("/n8n/status")
def n8n_status():
    """Check if n8n incident-response workflow is reachable."""
    try:
        r = http_requests.get("http://localhost:5678/healthz", timeout=2)
        reachable = r.status_code == 200
    except Exception:
        reachable = False
    return {
        "n8n_enabled":     N8N_ENABLED,
        "n8n_reachable":   reachable,
        "webhook_url":     N8N_WEBHOOK_URL,
        "message":         "n8n is online — incident response active" if reachable
                           else "n8n offline — incidents will be logged locally only",
    }


if __name__ == "__main__":
    cert_dir  = Path.home() / ".office-addin-dev-certs"
    key_path  = cert_dir / "localhost.key"
    cert_path = cert_dir / "localhost.crt"

    print(f"Starting HTTPS on port 8001")
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8001,
        ssl_keyfile=str(key_path),
        ssl_certfile=str(cert_path),
        reload=False
    )