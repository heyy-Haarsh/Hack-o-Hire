"""
approval_server.py
─────────────────────────────────────────────────────────────────────────────
Lightweight local HTTP server that handles human-in-loop approval clicks.

Why this exists:
  Email clients open links as GET requests. n8n's Wait-node webhook requires
  a POST to a dynamic URL that only exists while the execution is running.
  This server bridges the gap: approval emails link here, responses are stored
  locally, and n8n is notified via POST.

Usage (auto-started when imported):
  import approval_server
  url = approval_server.approve_url("INC-ABC123", "FS-999", approved=True)
  decisions = approval_server.get_decision("INC-ABC123")

Endpoints (port 5679):
  GET  /approve?incident_id=X&approved=true|false&prediction_id=Y
      → Returns a styled HTML confirmation page
      → Stores decision in approvals.json
      → POSTs decision to n8n webhook

  GET  /status?incident_id=X
      → Returns JSON { incident_id, approved, timestamp, prediction_id }
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.request
import urllib.parse
from http.server        import HTTPServer, BaseHTTPRequestHandler
from pathlib            import Path
from datetime           import datetime, timezone

# ── Config ─────────────────────────────────────────────────────────────────────
PORT              = 5679
N8N_WEBHOOK       = "http://localhost:5678/webhook/fraudshield"
_DATA_DIR         = Path(__file__).parent.parent / "data"
_DECISIONS_FILE   = _DATA_DIR / "approvals.json"
_DATA_DIR.mkdir(exist_ok=True)

_lock = threading.Lock()


# ── Decision store ──────────────────────────────────────────────────────────────

def _load() -> dict:
    if _DECISIONS_FILE.exists():
        try:
            return json.loads(_DECISIONS_FILE.read_text("utf-8"))
        except Exception:
            pass
    return {}


def _save(data: dict) -> None:
    _DECISIONS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _record_decision(incident_id: str, prediction_id: str, approved: bool) -> None:
    with _lock:
        data = _load()
        data[incident_id] = {
            "incident_id":   incident_id,
            "prediction_id": prediction_id,
            "approved":      approved,
            "action":        "QUARANTINE" if approved else "ALLOW",
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        }
        _save(data)

    # Async notify n8n (fire-and-forget)
    def _notify():
        try:
            body = json.dumps({
                "incident_id":   incident_id,
                "prediction_id": prediction_id,
                "approved":      approved,
                "action":        "QUARANTINE" if approved else "ALLOW",
                "source":        "human_approval",
                "timestamp":     datetime.now(timezone.utc).isoformat(),
            }, default=str).encode("utf-8")
            req = urllib.request.Request(
                N8N_WEBHOOK, data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # n8n might not be running; decision is already stored locally

    threading.Thread(target=_notify, daemon=True).start()


def get_decision(incident_id: str) -> dict | None:
    """Return the stored human decision for an incident, or None if pending."""
    with _lock:
        return _load().get(incident_id)


# ── HTML responses ──────────────────────────────────────────────────────────────

def _html_response(approved: bool, incident_id: str) -> str:
    if approved:
        icon, color, title, msg = "🔒", "#dc2626", "Email Quarantined", \
            "The email has been quarantined. The sender has been blocked and the incident logged for audit."
    else:
        icon, color, title, msg = "✅", "#16a34a", "Email Marked as Safe", \
            "The email has been released and marked as a false positive. The model will be updated accordingly."
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FraudShield — {title}</title>
<style>
  body{{font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
  .card{{background:#1e293b;border:1px solid {color}44;border-radius:16px;
         padding:40px 48px;max-width:520px;text-align:center;box-shadow:0 8px 32px #0008}}
  .icon{{font-size:64px;margin-bottom:16px}}
  h1{{color:{color};font-size:1.8rem;margin:0 0 12px}}
  p{{color:#94a3b8;font-size:1rem;line-height:1.6;margin:0 0 20px}}
  .badge{{display:inline-block;background:{color}22;color:{color};
          border:1px solid {color}55;border-radius:8px;padding:6px 16px;
          font-size:.8rem;font-weight:600;letter-spacing:.05em}}
  .footer{{color:#475569;font-size:.75rem;margin-top:24px}}
</style></head>
<body>
  <div class="card">
    <div class="icon">{icon}</div>
    <h1>{title}</h1>
    <p>{msg}</p>
    <div class="badge">Incident: {incident_id}</div>
    <div class="footer">FraudShield AI — Barclays Hack-o-Hire &nbsp;|&nbsp;
      Decision recorded at {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
    </div>
  </div>
</body></html>"""


# ── HTTP request handler ────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def _send(self, code: int, content_type: str, body: str | bytes) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed    = urllib.parse.urlparse(self.path)
        params    = dict(urllib.parse.parse_qsl(parsed.query))
        path      = parsed.path.rstrip("/")

        if path == "/approve":
            incident_id   = params.get("incident_id", "UNKNOWN")
            prediction_id = params.get("prediction_id", "")
            approved      = params.get("approved", "false").lower() == "true"

            _record_decision(incident_id, prediction_id, approved)
            html = _html_response(approved, incident_id)
            self._send(200, "text/html; charset=utf-8", html)

        elif path == "/status":
            incident_id = params.get("incident_id", "")
            decision    = get_decision(incident_id)
            body        = json.dumps(decision or {"status": "pending", "incident_id": incident_id})
            self._send(200, "application/json", body)

        elif path == "/health":
            self._send(200, "application/json", '{"status":"ok","port":5679}')

        else:
            self._send(404, "text/plain", "Not found")


# ── Server lifecycle ────────────────────────────────────────────────────────────

_server: HTTPServer | None = None
_started = False


def start(blocking: bool = False) -> None:
    """Start the approval server. Called automatically on import."""
    global _server, _started
    if _started:
        return
    try:
        _server = HTTPServer(("", PORT), _Handler)
        _started = True
        if blocking:
            _server.serve_forever()
        else:
            t = threading.Thread(target=_server.serve_forever, daemon=True, name="approval-server")
            t.start()
            print(f"[ApprovalServer] Listening on http://localhost:{PORT}")
    except OSError:
        # Port already in use — another instance is running
        _started = True


# ── Public URL helpers ──────────────────────────────────────────────────────────

def approve_url(incident_id: str, prediction_id: str) -> str:
    p = urllib.parse.urlencode({"incident_id": incident_id,
                                "prediction_id": prediction_id, "approved": "true"})
    return f"http://localhost:{PORT}/approve?{p}"


def reject_url(incident_id: str, prediction_id: str) -> str:
    p = urllib.parse.urlencode({"incident_id": incident_id,
                                "prediction_id": prediction_id, "approved": "false"})
    return f"http://localhost:{PORT}/approve?{p}"


# Auto-start daemon on import
start()
