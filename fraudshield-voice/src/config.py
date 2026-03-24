# src/config.py
import torch
from pathlib import Path

ROOT        = Path(__file__).parent.parent
DATA_RAW    = ROOT / "data" / "raw" / "ASVspoof2019_LA" / "LA" / "LA"
DATA_PROC   = ROOT / "data" / "processed"
MODELS_DIR  = ROOT / "models" / "saved"
OUTPUTS_DIR = ROOT / "outputs"

SAMPLE_RATE  = 16000
CLIP_SECONDS = 3
CLIP_SAMPLES = SAMPLE_RATE * CLIP_SECONDS

N_MFCC     = 40
N_FFT      = 1024
HOP_LENGTH = 512
N_MELS     = 128

HIDDEN_SIZE = 64
LSTM_LAYERS = 2
DROPOUT     = 0.5

BATCH_SIZE   = 32
EPOCHS       = 40
LR           = 5e-4
LR_MIN       = 1e-6
WEIGHT_DECAY = 1e-3

REAL = 0
FAKE = 1

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"[config] device = {DEVICE}")