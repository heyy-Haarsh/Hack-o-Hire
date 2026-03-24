# src/feedback.py
import sqlite3
import json
import numpy as np
from datetime import datetime
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from config import OUTPUTS_DIR, MODELS_DIR

DB_PATH = OUTPUTS_DIR / "fraudshield.db"


def init_db():
    """Create feedback database tables."""
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            file_hash     TEXT,
            verdict       TEXT,
            risk_score    INTEGER,
            tier          TEXT,
            deep_score    REAL,
            rf_score      REAL,
            top_indicators TEXT,
            caller_id     TEXT,
            channel       TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction_id   INTEGER,
            timestamp       TEXT,
            reviewer_id     TEXT,
            correct_label   TEXT,
            was_correct     INTEGER,
            notes           TEXT,
            FOREIGN KEY (prediction_id) REFERENCES predictions(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS retraining_queue (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            features_path TEXT,
            correct_label TEXT,
            source        TEXT
        )
    """)

    conn.commit()
    conn.close()


def log_prediction(result: dict) -> int:
    """Log a prediction to the database. Returns prediction ID."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    import hashlib
    file_hash = hashlib.md5(
        result.get("audio_file", "").encode()
    ).hexdigest()[:16]

    c.execute("""
        INSERT INTO predictions
        (timestamp, file_hash, verdict, risk_score, tier,
         deep_score, rf_score, top_indicators, caller_id, channel)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        file_hash,
        result.get("verdict"),
        result.get("risk_score"),
        result.get("tier"),
        result.get("deep_score"),
        result.get("rf_score"),
        json.dumps(result.get("top_indicators", [])),
        result.get("caller_id", ""),
        result.get("channel", ""),
    ))

    pred_id = c.lastrowid
    conn.commit()
    conn.close()
    return pred_id


def submit_feedback(
    prediction_id: int,
    correct_label: str,
    reviewer_id:   str = "analyst",
    notes:         str = ""
):
    """
    Submit reviewer feedback on a prediction.
    correct_label: 'REAL' or 'FAKE'
    """
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    # Get original prediction
    c.execute("SELECT verdict FROM predictions WHERE id=?",
              (prediction_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"error": f"Prediction {prediction_id} not found"}

    was_correct = 1 if row[0] == correct_label else 0

    c.execute("""
        INSERT INTO feedback
        (prediction_id, timestamp, reviewer_id,
         correct_label, was_correct, notes)
        VALUES (?,?,?,?,?,?)
    """, (
        prediction_id,
        datetime.now().isoformat(),
        reviewer_id,
        correct_label,
        was_correct,
        notes
    ))

    # Add to retraining queue if wrong
    if not was_correct:
        c.execute("""
            INSERT INTO retraining_queue
            (timestamp, features_path, correct_label, source)
            VALUES (?,?,?,?)
        """, (
            datetime.now().isoformat(),
            f"feedback_{prediction_id}",
            correct_label,
            "human_review"
        ))
        print(f"  Added to retraining queue — prediction {prediction_id} "
              f"was {row[0]}, correct is {correct_label}")

    conn.commit()
    conn.close()

    return {
        "prediction_id": prediction_id,
        "was_correct":   bool(was_correct),
        "correct_label": correct_label,
        "queued_for_retraining": not was_correct
    }


def get_feedback_stats() -> dict:
    """Get overall system performance from human feedback."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    c.execute("SELECT COUNT(*) FROM predictions")
    total_predictions = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM feedback")
    total_reviews = c.fetchone()[0]

    c.execute("SELECT SUM(was_correct), COUNT(*) FROM feedback")
    row = c.fetchone()
    accuracy = round(row[0]/row[1]*100, 1) if row[1] > 0 else None

    c.execute("SELECT COUNT(*) FROM retraining_queue")
    queue_size = c.fetchone()[0]

    c.execute("""
        SELECT correct_label, COUNT(*) as cnt
        FROM feedback WHERE was_correct=0
        GROUP BY correct_label
    """)
    errors = dict(c.fetchall())

    c.execute("""
        SELECT DATE(timestamp) as day, COUNT(*) as cnt
        FROM predictions
        GROUP BY day ORDER BY day DESC LIMIT 7
    """)
    daily = dict(c.fetchall())

    conn.close()

    return {
        "total_predictions":   total_predictions,
        "total_reviews":       total_reviews,
        "human_verified_accuracy": accuracy,
        "retraining_queue_size":   queue_size,
        "false_positives": errors.get("REAL", 0),
        "false_negatives": errors.get("FAKE", 0),
        "daily_predictions":   daily,
    }


def get_retraining_candidates(min_queue_size: int = 50) -> bool:
    """
    Returns True if enough feedback collected to trigger retraining.
    In production this would kick off an automated retraining job.
    """
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) FROM retraining_queue")
    size = c.fetchone()[0]
    conn.close()

    if size >= min_queue_size:
        print(f"Retraining triggered — {size} corrections in queue")
        return True
    print(f"Queue size: {size}/{min_queue_size} — not enough for retraining yet")
    return False


# Initialize DB on import
init_db()