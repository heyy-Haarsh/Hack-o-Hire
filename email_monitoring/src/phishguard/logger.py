"""
logger.py â€“ Structured local-only logging via loguru.
No logs are sent to any external service.
"""
from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

from phishguard.config import settings


def setup_logging() -> None:
    """Configure loguru with console + rotating file output."""
    log_dir: Path = settings.log_dir
    log_dir.mkdir(parents=True, exist_ok=True)

    logger.remove()  # Remove default handler

    # Pretty console output
    logger.add(
        sys.stderr,
        level=settings.log_level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            "<level>{message}</level>"
        ),
        colorize=True,
    )

    # Rotating file â€“ stays local
    logger.add(
        log_dir / "phishguard_{time:YYYY-MM-DD}.log",
        level=settings.log_level,
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        serialize=False,
        enqueue=True,
    )


# Call once at import time so any module can `from phishguard.logger import logger`
setup_logging()

__all__ = ["logger"]

