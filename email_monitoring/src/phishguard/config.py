"""
config.py - Central configuration for the PhishGuard URL scanner.
Model paths resolve relative to THIS file's directory so they work
regardless of where the Streamlit app is launched from.
"""
from __future__ import annotations

from pathlib import Path
from functools import lru_cache

# ── Resolve model directory relative to THIS file ─────────────────────────────
_HERE = Path(__file__).parent          # .../src/phishguard/
_MODELS = _HERE / "models"


class Settings:
    # Model paths (absolute, resolved at import time)
    model_path:           Path = _MODELS / "xgb_phishing.joblib"
    scaler_path:          Path = _MODELS / "scaler.joblib"
    label_encoder_path:   Path = _MODELS / "label_encoder.joblib"

    # Risk thresholds (probability × 100)
    safe_threshold:       int   = 50
    suspicious_threshold: int   = 85

    # Cookie detection
    cookie_anomaly_score_threshold: float = 0.65

    # Logging
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
