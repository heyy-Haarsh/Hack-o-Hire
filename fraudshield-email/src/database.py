# src/database.py
# PostgreSQL connection and schema for FraudShield feedback system

import sys
from pathlib import Path
from datetime import datetime
sys.path.insert(0, str(Path(__file__).parent))

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    print("  psycopg2 not found — falling back to SQLite")

import sqlite3
from config import OUTPUTS_DIR

# ── Database config ────────────────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "database": "fraudshield",
    "user":     "fraudshield_user",
    "password": "fraudshield123"
}

# ── Flag — set to False to use SQLite fallback ─────────────────────
USE_POSTGRES = PSYCOPG2_AVAILABLE
SQLITE_PATH  = OUTPUTS_DIR / "feedback.db"


def get_connection():
    """Get database connection — PostgreSQL or SQLite fallback."""
    if USE_POSTGRES:
        return psycopg2.connect(**DB_CONFIG)
    else:
        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(str(SQLITE_PATH))


def init_db():
    """Create all tables if they don't exist."""
    if USE_POSTGRES:
        _init_postgres()
    else:
        _init_sqlite()
    print(f"  Database initialized ({'PostgreSQL' if USE_POSTGRES else 'SQLite'})")


def _init_postgres():
    conn = get_connection()
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id            SERIAL PRIMARY KEY,
            timestamp     TIMESTAMP DEFAULT NOW(),
            email_subject TEXT,
            email_sender  TEXT,
            email_receiver TEXT,
            verdict       TEXT,
            risk_score    INTEGER,
            tier          TEXT,
            outlook_action TEXT,
            roberta_prob  FLOAT,
            rule_score    FLOAT,
            ai_prob       FLOAT,
            header_score  INTEGER,
            top_indicators TEXT[],
            processing_ms INTEGER,
            email_text    TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id             SERIAL PRIMARY KEY,
            timestamp      TIMESTAMP DEFAULT NOW(),
            prediction_id  INTEGER REFERENCES predictions(id),
            email_subject  TEXT,
            email_sender   TEXT,
            model_verdict  TEXT,
            model_score    INTEGER,
            user_verdict   TEXT,
            was_correct    BOOLEAN,
            reviewer_id    TEXT DEFAULT 'analyst',
            notes          TEXT,
            email_text     TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS retraining_queue (
            id            SERIAL PRIMARY KEY,
            timestamp     TIMESTAMP DEFAULT NOW(),
            email_text    TEXT,
            correct_label TEXT,
            source        TEXT DEFAULT 'human_review',
            processed     BOOLEAN DEFAULT FALSE
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


def _init_sqlite():
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS predictions (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT,
            email_subject  TEXT,
            email_sender   TEXT,
            email_receiver TEXT,
            verdict        TEXT,
            risk_score     INTEGER,
            tier           TEXT,
            outlook_action TEXT,
            roberta_prob   REAL,
            rule_score     REAL,
            ai_prob        REAL,
            header_score   INTEGER,
            top_indicators TEXT,
            processing_ms  INTEGER,
            email_text     TEXT
        );
        CREATE TABLE IF NOT EXISTS feedback (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT,
            prediction_id  INTEGER,
            email_subject  TEXT,
            email_sender   TEXT,
            model_verdict  TEXT,
            model_score    INTEGER,
            user_verdict   TEXT,
            was_correct    INTEGER,
            reviewer_id    TEXT DEFAULT 'analyst',
            notes          TEXT,
            email_text     TEXT
        );
        CREATE TABLE IF NOT EXISTS retraining_queue (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            email_text    TEXT,
            correct_label TEXT,
            source        TEXT DEFAULT 'human_review',
            processed     INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


def log_prediction(result: dict, email_text: str = "") -> int:
    """Log every prediction to database. Returns prediction ID."""
    if USE_POSTGRES:
        return _log_prediction_postgres(result, email_text)
    else:
        return _log_prediction_sqlite(result, email_text)


def _log_prediction_postgres(result: dict, email_text: str) -> int:
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO predictions
        (email_subject, email_sender, verdict, risk_score, tier,
         outlook_action, roberta_prob, rule_score, ai_prob,
         header_score, top_indicators, processing_ms, email_text)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
    """, (
        result.get("subject", ""),
        result.get("sender", ""),
        result.get("verdict"),
        result.get("risk_score"),
        result.get("tier"),
        result.get("outlook_action"),
        result.get("roberta_phishing_prob"),
        result.get("rule_based_score"),
        result.get("ai_generated_probability"),
        result.get("header_risk_score", 0),
        result.get("top_indicators", []),
        result.get("processing_ms"),
        email_text[:2000]
    ))
    pred_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return pred_id


def _log_prediction_sqlite(result: dict, email_text: str) -> int:
    import json
    conn = sqlite3.connect(str(SQLITE_PATH))
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO predictions
        (timestamp, email_subject, email_sender, verdict, risk_score,
         tier, outlook_action, roberta_prob, rule_score, ai_prob,
         header_score, top_indicators, processing_ms, email_text)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        result.get("subject", ""),
        result.get("sender", ""),
        result.get("verdict"),
        result.get("risk_score"),
        result.get("tier"),
        result.get("outlook_action"),
        result.get("roberta_phishing_prob"),
        result.get("rule_based_score"),
        result.get("ai_generated_probability"),
        result.get("header_risk_score", 0),
        json.dumps(result.get("top_indicators", [])),
        result.get("processing_ms"),
        email_text[:2000]
    ))
    pred_id = cur.lastrowid
    conn.commit()
    cur.close()
    conn.close()
    return pred_id


def save_feedback(
    email_subject: str,
    email_sender:  str,
    email_text:    str,
    model_verdict: str,
    model_score:   int,
    user_verdict:  str,
    prediction_id: int = None,
    reviewer_id:   str = "analyst",
    notes:         str = ""
) -> dict:
    """Save human feedback and queue for retraining if wrong."""
    was_correct  = model_verdict == user_verdict

    if USE_POSTGRES:
        _save_feedback_postgres(
            email_subject, email_sender, email_text,
            model_verdict, model_score, user_verdict,
            was_correct, prediction_id, reviewer_id, notes
        )
        if not was_correct:
            _queue_retraining_postgres(email_text, user_verdict)
    else:
        _save_feedback_sqlite(
            email_subject, email_sender, email_text,
            model_verdict, model_score, user_verdict,
            was_correct, prediction_id, reviewer_id, notes
        )
        if not was_correct:
            _queue_retraining_sqlite(email_text, user_verdict)

    return {
        "status":       "saved",
        "was_correct":  was_correct,
        "model_said":   model_verdict,
        "user_said":    user_verdict,
        "impact":       "confirmed_correct" if was_correct else "queued_for_retraining"
    }


def _save_feedback_postgres(subject, sender, text, model_verdict,
                             model_score, user_verdict, was_correct,
                             pred_id, reviewer_id, notes):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO feedback
        (prediction_id, email_subject, email_sender, model_verdict,
         model_score, user_verdict, was_correct, reviewer_id, notes, email_text)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (pred_id, subject, sender, model_verdict, model_score,
          user_verdict, was_correct, reviewer_id, notes, text[:2000]))
    conn.commit()
    cur.close()
    conn.close()


def _save_feedback_sqlite(subject, sender, text, model_verdict,
                           model_score, user_verdict, was_correct,
                           pred_id, reviewer_id, notes):
    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.execute("""
        INSERT INTO feedback
        (timestamp, prediction_id, email_subject, email_sender,
         model_verdict, model_score, user_verdict, was_correct,
         reviewer_id, notes, email_text)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (datetime.now().isoformat(), pred_id, subject, sender,
          model_verdict, model_score, user_verdict,
          1 if was_correct else 0, reviewer_id, notes, text[:2000]))
    conn.commit()
    conn.close()


def _queue_retraining_postgres(email_text: str, correct_label: str):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO retraining_queue (email_text, correct_label)
        VALUES (%s, %s)
    """, (email_text[:2000], correct_label))
    conn.commit()
    cur.close()
    conn.close()


def _queue_retraining_sqlite(email_text: str, correct_label: str):
    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.execute("""
        INSERT INTO retraining_queue (timestamp, email_text, correct_label)
        VALUES (?,?,?)
    """, (datetime.now().isoformat(), email_text[:2000], correct_label))
    conn.commit()
    conn.close()


def _get_stats_postgres() -> dict:
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT COUNT(*) as total FROM feedback")
    total = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) as correct FROM feedback WHERE was_correct=TRUE")
    correct = cur.fetchone()["correct"]

    cur.execute("""
        SELECT COUNT(*) as cnt FROM feedback
        WHERE was_correct=FALSE AND user_verdict='LEGITIMATE'
    """)
    false_positives = cur.fetchone()["cnt"]

    cur.execute("""
        SELECT COUNT(*) as cnt FROM feedback
        WHERE was_correct=FALSE AND user_verdict='PHISHING'
    """)
    false_negatives = cur.fetchone()["cnt"]

    cur.execute("SELECT COUNT(*) as cnt FROM retraining_queue WHERE processed=FALSE")
    queue_size = cur.fetchone()["cnt"]

    cur.execute("""
        SELECT model_verdict, user_verdict, email_subject,
               email_sender, timestamp
        FROM feedback
        ORDER BY timestamp DESC LIMIT 10
    """)
    recent = [dict(r) for r in cur.fetchall()]

    cur.close()
    conn.close()

    accuracy = round(correct / total * 100, 1) if total > 0 else 0
    return {
        "database":          "PostgreSQL",
        "total_feedback":    total,
        "model_accuracy":    f"{accuracy}%",
        "correct":           correct,
        "false_positives":   false_positives,
        "false_negatives":   false_negatives,
        "retraining_queue":  queue_size,
        "retraining_needed": queue_size >= 10,
        "recent_feedback":   recent
    }

def _get_stats_sqlite() -> dict:
    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT COUNT(*) as total FROM feedback")
    total = c.fetchone()["total"]

    c.execute("SELECT SUM(was_correct) as correct FROM feedback")
    correct = c.fetchone()["correct"] or 0

    c.execute("""
        SELECT COUNT(*) as cnt FROM feedback
        WHERE was_correct=0 AND user_verdict='LEGITIMATE'
    """)
    fp = c.fetchone()["cnt"]

    c.execute("""
        SELECT COUNT(*) as cnt FROM feedback
        WHERE was_correct=0 AND user_verdict='PHISHING'
    """)
    fn = c.fetchone()["cnt"]

    c.execute("SELECT COUNT(*) as cnt FROM retraining_queue WHERE processed=0")
    queue = c.fetchone()["cnt"]

    c.execute("""
        SELECT model_verdict, user_verdict, email_subject,
               email_sender, timestamp
        FROM feedback ORDER BY timestamp DESC LIMIT 10
    """)
    recent = [dict(r) for r in c.fetchall()]
    conn.close()

    accuracy = round(correct / total * 100, 1) if total > 0 else 0
    return {
        "database":          "SQLite",
        "total_feedback":    total,
        "model_accuracy":    f"{accuracy}%",
        "correct":           correct,
        "false_positives":   fp,
        "false_negatives":   fn,
        "retraining_queue":  queue,
        "retraining_needed": queue >= 10,
        "recent_feedback":   recent
    }

def get_feedback_stats() -> dict:
    """Get model accuracy statistics from human feedback."""
    if USE_POSTGRES:
        return _get_stats_postgres()
    else:
        return _get_stats_sqlite()

def retrain_from_feedback() -> dict:
    """
    Export misclassified emails from retraining queue.
    Returns dict with emails ready for fine-tuning.
    """
    if USE_POSTGRES:
        conn = get_connection()
        cur  = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT email_text, correct_label, timestamp
            FROM retraining_queue
            WHERE processed = FALSE
            ORDER BY timestamp ASC
        """)
        rows = [dict(r) for r in cur.fetchall()]

        if rows:
            cur.execute("""
                UPDATE retraining_queue
                SET processed = TRUE
                WHERE processed = FALSE
            """)
            conn.commit()

        cur.close()
        conn.close()
    else:
        conn = sqlite3.connect(str(SQLITE_PATH))
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("""
            SELECT email_text, correct_label, timestamp
            FROM retraining_queue WHERE processed=0
            ORDER BY timestamp ASC
        """)
        rows = [dict(r) for r in c.fetchall()]
        if rows:
            conn.execute(
                "UPDATE retraining_queue SET processed=1 WHERE processed=0"
            )
            conn.commit()
        conn.close()

    return {
        "queued_samples": len(rows),
        "samples":        rows,
        "ready_to_retrain": len(rows) >= 10
    }
    
if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    print("Database ready")
    stats = get_feedback_stats()
    print(f"Stats: {stats}")