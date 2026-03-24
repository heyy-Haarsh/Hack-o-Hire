# src/config.py
import torch
from pathlib import Path

ROOT        = Path(__file__).parent.parent
DATA_RAW    = ROOT / "data" / "raw"
DATA_PROC   = ROOT / "data" / "processed"
MODELS_DIR  = ROOT / "models" / "saved"
OUTPUTS_DIR = ROOT / "outputs"

# Model
BASE_MODEL      = "roberta-base"
AI_DETECT_MODEL = "openai-community/roberta-base-openai-detector"
MAX_LENGTH      = 512
BATCH_SIZE      = 16
EPOCHS          = 5
LR              = 2e-5
WEIGHT_DECAY    = 0.01

# Labels
LEGITIMATE = 0
PHISHING   = 1

# Risk tiers
TIERS = [
    (86, "CRITICAL", "QUARANTINE"),
    (61, "HIGH",     "JUNK"),
    (31, "MEDIUM",   "FLAG"),
    (0,  "LOW",      "ALLOW"),
]

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"[config] device = {DEVICE}")