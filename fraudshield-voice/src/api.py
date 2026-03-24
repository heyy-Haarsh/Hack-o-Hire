# src/api.py
import os
import tempfile
import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from fastapi import WebSocket, WebSocketDisconnect
import numpy as np

from evaluate import load_models, predict
from feedback import log_prediction, submit_feedback, get_feedback_stats, init_db
from transcript_analyzer import combined_analysis, transcribe_audio


app = FastAPI(
    title="FraudShield Voice API",
    description="Deepfake voice detection for Barclays Hack-o-Hire",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SUPPORTED_FORMATS = {
    ".wav", ".mp3", ".flac", ".ogg",   # native librosa
    ".m4a", ".aac", ".wma",             # via pydub
    ".mp4", ".webm", ".3gp",            # video audio extraction
}

@app.on_event("startup")
async def startup():
    """Load both models once at startup — not on every request."""
    app.state.deep, app.state.rf = load_models()
    print("[API] Models loaded. Ready to accept requests.")


@app.get("/health")
def health():
    return {
        "status":        "ok",
        "models_loaded": True,
        "device":        str(app.state.deep.parameters().__next__().device)
    }



@app.post("/analyze/voice")
async def analyze_voice(
    file:      UploadFile = File(...),
    caller_id: str  = "",
    channel:   str  = "unknown",
    use_llm:   bool = False
):
    ext = Path(file.filename).suffix.lower()
    if ext not in SUPPORTED_FORMATS:
        raise HTTPException(400, f"Unsupported format '{ext}'")

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        result = predict(tmp_path, app.state.deep,
                         app.state.rf, use_llm=use_llm)
        result["caller_id"]       = caller_id
        result["channel"]         = channel
        result["original_format"] = ext

        # Log every prediction for feedback loop
        pred_id = log_prediction(result)
        result["prediction_id"] = pred_id

        return result
    except Exception as e:
        raise HTTPException(500, str(e))
    finally:
        os.unlink(tmp_path)

@app.websocket("/ws/realtime")
async def realtime_stream(websocket: WebSocket):
    """
    WebSocket endpoint for real-time audio streaming.
    Client sends raw PCM float32 audio chunks.
    Server responds with JSON risk assessment every 3 seconds.
    """
    await websocket.accept()
    buffer    = np.array([], dtype=np.float32)
    deep      = websocket.app.state.deep
    rf        = websocket.app.state.rf

    print("[WS] Real-time session started")

    try:
        while True:
            # Receive audio chunk from client
            data  = await websocket.receive_bytes()
            chunk = np.frombuffer(data, dtype=np.float32)
            buffer = np.concatenate([buffer, chunk])

            # Score every 3 seconds of accumulated audio
            if len(buffer) >= CLIP_SAMPLES:
                audio_chunk  = buffer[:CLIP_SAMPLES]
                buffer       = buffer[CLIP_SAMPLES:]

                # Score it
                import librosa
                audio_chunk = librosa.util.normalize(audio_chunk)

                with torch.no_grad():
                    from features import extract_sequence, extract_aggregate
                    seq = torch.tensor(
                        extract_sequence(audio_chunk)
                    ).unsqueeze(0).to(DEVICE)
                    ds = deep(seq).squeeze().item()

                rs    = rf.predict_proba(
                    [extract_aggregate(audio_chunk)]
                )[0][1]
                final = 0.6 * ds + 0.4 * rs
                risk  = int(final * 100)

                tiers = [
                    (86,"CRITICAL","BLOCK"),
                    (61,"HIGH","ESCALATE"),
                    (31,"MEDIUM","FLAG"),
                    (0, "LOW","ALLOW")
                ]
                tier, action = next(
                    (t,a) for thresh,t,a in tiers if risk >= thresh
                )

                response = {
                    "verdict":    "FAKE" if final >= 0.5 else "REAL",
                    "risk_score":  risk,
                    "tier":        tier,
                    "action":      action,
                    "deep_score":  round(ds,    4),
                    "rf_score":    round(rs,    4),
                    "final_score": round(final, 4),
                    "timestamp":   time.time(),
                }
                await websocket.send_json(response)

    except WebSocketDisconnect:
        print("[WS] Session ended")
@app.post("/feedback/{prediction_id}")
async def submit_review(
    prediction_id: int,
    correct_label: str,
    reviewer_id:   str = "analyst",
    notes:         str = ""
):
    """
    Submit human review on a prediction.
    correct_label must be 'REAL' or 'FAKE'
    """
    if correct_label not in ("REAL", "FAKE"):
        raise HTTPException(400, "correct_label must be REAL or FAKE")
    return submit_feedback(prediction_id, correct_label,
                           reviewer_id, notes)


@app.get("/feedback/stats")
async def feedback_statistics():
    """Get overall system accuracy from human reviews."""
    return get_feedback_stats()


@app.get("/feedback/history")
async def feedback_history(limit: int = 20):
    """Get recent predictions with their feedback status."""
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT p.id, p.timestamp, p.verdict, p.risk_score,
               p.tier, p.caller_id, f.correct_label, f.was_correct
        FROM predictions p
        LEFT JOIN feedback f ON p.id = f.prediction_id
        ORDER BY p.timestamp DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"predictions": rows, "count": len(rows)}

@app.post("/analyze/combined")
async def analyze_combined(
    file:       UploadFile = File(...),
    transcript: str  = "",
    caller_id:  str  = "",
    use_llm:    bool = False
):
    """
    Full analysis: voice deepfake detection + transcript phishing analysis.
    If transcript not provided, auto-transcribes using Whisper.
    """
    ext = Path(file.filename).suffix.lower()
    if ext not in SUPPORTED_FORMATS:
        raise HTTPException(400, f"Unsupported format '{ext}'")

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        # Voice analysis
        voice_result = predict(tmp_path, app.state.deep,
                               app.state.rf, use_llm=use_llm)

        # Combined analysis
        result = combined_analysis(
            tmp_path, voice_result,
            transcript if transcript else None
        )
        result["caller_id"] = caller_id

        # Log prediction
        pred_id = log_prediction(result)
        result["prediction_id"] = pred_id

        return result
    finally:
        os.unlink(tmp_path)
        
if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)