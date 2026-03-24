# src/calibration.py
import numpy as np
import pickle
import torch
from sklearn.linear_model import LogisticRegression
from torch.utils.data import DataLoader
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from dataset import VoiceDataset
from model import DeepfakeVoiceDetector
from explainer import load_rf
from config import DEVICE, MODELS_DIR


class ScoreCalibrator:
    def __init__(self):
        self.calibrator = LogisticRegression()
        self.is_fitted  = False
        self.path       = MODELS_DIR / "calibrator.pkl"

    def fit(self, deep_model, rf_model):
        print("Fitting calibrator on val_split...")
        val_ds     = VoiceDataset("val_split")
        val_loader = DataLoader(val_ds, batch_size=256,
                                shuffle=False, num_workers=0)

        raw_scores, labels = [], []
        deep_model.eval()

        with torch.no_grad():
            for i, (seq, agg, lbl) in enumerate(val_loader):
                # Deep model — batched on GPU
                seq_gpu = seq.to(DEVICE)
                ds_batch = deep_model(seq_gpu).squeeze(1).cpu().numpy()

                # RF — per sample (unavoidable)
                for j in range(len(agg)):
                    rs = rf_model.predict_proba([agg[j].numpy()])[0][1]
                    fs = 0.6 * ds_batch[j] + 0.4 * rs
                    raw_scores.append(float(fs))
                    labels.append(int(lbl[j].item()))

                print(f"  {len(raw_scores)}/{len(val_ds)}", end="\r")

        print(f"\n  Scored {len(raw_scores)} samples")

        X = np.array(raw_scores).reshape(-1, 1)
        y = np.array(labels)

        self.calibrator.fit(X, y)
        self.is_fitted = True

        # Show improvement
        real_scores = [s for s, l in zip(raw_scores, labels) if l == 0]
        fake_scores = [s for s, l in zip(raw_scores, labels) if l == 1]

        raw_real = np.mean(real_scores)
        raw_fake = np.mean(fake_scores)
        cal_real = self.calibrator.predict_proba([[raw_real]])[0][1]
        cal_fake = self.calibrator.predict_proba([[raw_fake]])[0][1]

        print(f"  Before — real mean: {raw_real:.4f}  fake mean: {raw_fake:.4f}")
        print(f"  After  — real prob: {cal_real:.4f}  fake prob: {cal_fake:.4f}")

        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        with open(self.path, "wb") as f:
            pickle.dump(self.calibrator, f)
        print(f"  Calibrator saved → {self.path}")

    def load(self):
        if self.path.exists():
            with open(self.path, "rb") as f:
                self.calibrator = pickle.load(f)
            self.is_fitted = True
            return True
        return False

    def calibrate(self, raw_score: float) -> float:
        if not self.is_fitted:
            return raw_score
        return float(
            self.calibrator.predict_proba([[raw_score]])[0][1]
        )


if __name__ == "__main__":
    from torch import load as tload
    deep = DeepfakeVoiceDetector().to(DEVICE)
    deep.load_state_dict(
        tload(MODELS_DIR / "best_eer.pt", map_location=DEVICE)
    )
    rf  = load_rf()
    cal = ScoreCalibrator()
    cal.fit(deep, rf)