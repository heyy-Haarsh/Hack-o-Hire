# src/model.py
import torch
import torch.nn as nn
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import N_MFCC, HIDDEN_SIZE, LSTM_LAYERS, DROPOUT, DEVICE


class DeepfakeVoiceDetector(nn.Module):
    def __init__(self):
        super().__init__()

        # ── CNN block ──────────────────────────────────────────────
        # Learns local per-frame spectral artifacts left by vocoders
        self.cnn = nn.Sequential(
            nn.Conv1d(N_MFCC, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Dropout(0.3),
        )

        # ── BiLSTM block ───────────────────────────────────────────
        # Learns temporal prosody anomalies across the full clip
        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=HIDDEN_SIZE,
            num_layers=LSTM_LAYERS,
            batch_first=True,
            bidirectional=True,
            dropout=0.3,
        )

        # ── Classifier head ────────────────────────────────────────
        self.classifier = nn.Sequential(
            nn.Linear(HIDDEN_SIZE * 2, 64),
            nn.ReLU(),
            nn.Dropout(DROPOUT),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        # x: [B, N_MFCC, T]
        x = self.cnn(x)             # [B, 128, T//2]
        x = x.permute(0, 2, 1)     # [B, T//2, 128]
        out, _ = self.lstm(x)       # [B, T//2, 128]
        x = out.mean(dim=1)         # [B, 128] — temporal mean pool
        return self.classifier(x)   # [B, 1]


# ── Shape verification ─────────────────────────────────────────────
if __name__ == "__main__":
    print(f"Running on: {DEVICE}")
    model = DeepfakeVoiceDetector().to(DEVICE)

    dummy = torch.randn(4, N_MFCC, 94).to(DEVICE)
    out   = model(dummy)

    print(f"  Input  shape : {dummy.shape}")   # expect [4, 40, 94]
    print(f"  Output shape : {out.shape}")     # expect [4, 1]
    print(f"  Output range : {out.min().item():.4f} → {out.max().item():.4f}")

    total  = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  Total params    : {total:,}")
    print(f"  Trainable params: {trainable:,}")
    print("  model.py OK!")