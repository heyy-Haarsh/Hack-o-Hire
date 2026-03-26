# src/voice/config.py
"""
Configuration for voice deepfake detection module.
"""
import os
from pathlib import Path

# ── Audio settings ──────────────────────────────────────────────────
SAMPLE_RATE  = 16_000          # 16 kHz
CLIP_SAMPLES = SAMPLE_RATE * 3 # 3-second windows = 48000 samples
N_MFCC       = 40
N_FFT        = 1024   # must match fraudshield-voice training config (was 512)
HOP_LENGTH   = 512

# ── Model path ──────────────────────────────────────────────────────
# best_eer.pt is placed 2 levels above email-classifier-main/src/
_SRC_DIR  = Path(__file__).parent.parent  # src/
_ROOT_DIR = _SRC_DIR.parent              # email-classifier-main/
MODELS_DIR = _ROOT_DIR / "models"        # email-classifier-main/models/

# ── Device ──────────────────────────────────────────────────────────
try:
    import torch
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
except ImportError:
    DEVICE = "cpu"
