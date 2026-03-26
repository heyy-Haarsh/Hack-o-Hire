# src/voice/model.py
"""
DeepfakeVoiceDetector — CNN + BiLSTM architecture.
Exactly matches fraudshield-voice training architecture and best_eer.pt checkpoint.
  cnn        : Conv1d(40→64) + BN + ReLU + Conv1d(64→128) + BN + ReLU + MaxPool1d(2) + Dropout(0.3)
  lstm       : BiLSTM(input=128, hidden=64, num_layers=2)
  classifier : Linear(128→64) + ReLU + Dropout + Linear(64→1) + Sigmoid
  aggregation: temporal mean pooling over LSTM outputs
"""
import torch
import torch.nn as nn

# Match training config
N_MFCC = 40


class DeepfakeVoiceDetector(nn.Module):
    """
    MFCC-based voice deepfake detector.
    Input  : [B, N_MFCC, T]  (MFCC sequence from 3-second audio chunks)
    Output : [B, 1]           (probability of being FAKE, 0=REAL, 1=FAKE)
    """

    def __init__(self, n_mfcc: int = N_MFCC, hidden: int = 64, num_layers: int = 2):
        super().__init__()

        # ── CNN feature extractor ───────────────────────────────────
        # Matches fraudshield-voice training architecture exactly:
        # cnn.0=Conv1d(40→64), cnn.1=BN64, cnn.2=ReLU,
        # cnn.3=Conv1d(64→128), cnn.4=BN128, cnn.5=ReLU,
        # cnn.6=MaxPool1d(2), cnn.7=Dropout(0.3)
        self.cnn = nn.Sequential(
            nn.Conv1d(n_mfcc, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),

            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.BatchNorm1d(128),
            nn.ReLU(),

            nn.MaxPool1d(2),     # halves temporal dim → LSTM sees T//2 frames
            nn.Dropout(0.3),
        )

        # ── Bidirectional LSTM ──────────────────────────────────────
        self.lstm = nn.LSTM(
            input_size=128,
            hidden_size=hidden,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=0.3 if num_layers > 1 else 0.0,
        )

        # ── Classifier head ─────────────────────────────────────────
        # Layer named 'classifier' to match best_eer.pt checkpoint keys
        self.classifier = nn.Sequential(
            nn.Linear(hidden * 2, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: [B, N_MFCC, T]
        returns: [B, 1]  — probability of FAKE
        """
        x = self.cnn(x)           # [B, 128, T//2]  (MaxPool halves time)
        x = x.permute(0, 2, 1)   # [B, T//2, 128]  — LSTM expects (batch, seq, features)
        out, _ = self.lstm(x)
        x = out.mean(dim=1)       # [B, 128] — temporal mean pool (matches training)
        return self.classifier(x)  # [B, 1]
