"""
config.py – Central application configuration.
All settings are read from environment variables / .env file.
Nothing is hard-coded; no data ever leaves the machine.
"""
from __future__ import annotations

from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ────────────────────────────────────────────────────────────
    database_url: str = (
        "postgresql+asyncpg://phish_user:phish_pass@localhost:5432/phishguard"
    )

    # ── Redis ───────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── JWT / Security ──────────────────────────────────────────────────────
    secret_key: str = "change-me-to-a-long-random-string"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # ── Model paths ─────────────────────────────────────────────────────────
    model_path: Path = Path("models/xgb_phishing.joblib")
    scaler_path: Path = Path("models/scaler.joblib")
    label_encoder_path: Path = Path("models/label_encoder.joblib")

    # ── Logging ─────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_dir: Path = Path("logs")

    # ── Risk thresholds ─────────────────────────────────────────────────────
    safe_threshold: int = 50
    suspicious_threshold: int = 85

    # ── Training ────────────────────────────────────────────────────────────
    data_dir: Path = Path("data")
    test_size: float = 0.20
    cv_folds: int = 5
    random_seed: int = 42

    # ── Cookie detection ────────────────────────────────────────────────────
    cookie_anomaly_score_threshold: float = 0.65


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
