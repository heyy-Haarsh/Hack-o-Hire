# scripts/final_eval.py
import numpy as np
import json
import torch
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.metrics import roc_curve
from tqdm import tqdm
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from evaluate import load_models
from dataset import VoiceDataset
from config import DEVICE, OUTPUTS_DIR


def compute_eer(scores, labels):
    fpr, tpr, _ = roc_curve(labels, scores, pos_label=1)
    fnr = 1 - tpr
    idx = np.nanargmin(np.abs(fpr - fnr))
    return float((fpr[idx] + fnr[idx]) / 2)


def main():
    print("FraudShield — Final Evaluation on Test Set")
    print("=" * 50)

    deep, rf = load_models()
    test_ds  = VoiceDataset("eval")

    all_scores, all_labels = [], []

    deep.eval()
    with torch.no_grad():
        for seq, agg, lbl in tqdm(test_ds, desc="Evaluating"):
            seq_t = seq.unsqueeze(0).to(DEVICE)
            ds    = deep(seq_t).squeeze().item()
            rs    = rf.predict_proba([agg.numpy()])[0][1]
            fs    = 0.6 * ds + 0.4 * rs
            all_scores.append(fs)
            all_labels.append(int(lbl.item()))

    preds  = [1 if s >= 0.5 else 0 for s in all_scores]
    eer    = compute_eer(all_scores, all_labels)
    auc    = roc_auc_score(all_labels, all_scores)
    report = classification_report(
        all_labels, preds,
        target_names=["Real", "Fake"],
        output_dict=True
    )

    results = {
        "EER":                round(eer,  4),
        "AUC_ROC":            round(auc,  4),
        "Accuracy":           round(report["accuracy"], 4),
        "Precision_fake":     round(report["Fake"]["precision"], 4),
        "Recall_fake":        round(report["Fake"]["recall"],    4),
        "F1_fake":            round(report["Fake"]["f1-score"],  4),
        "Precision_real":     round(report["Real"]["precision"], 4),
        "Recall_real":        round(report["Real"]["recall"],    4),
        "F1_real":            round(report["Real"]["f1-score"],  4),
    }

    print("\nResults:")
    for k, v in results.items():
        print(f"  {k:<20} {v}")

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUTS_DIR / "evaluation_report.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nReport saved → {out_path}")
    print(f"\nEER = {eer:.4f}  (published GMM baseline = 0.1480)")
    if eer < 0.148:
        print("  You beat the published baseline!")
    print("=" * 50)


if __name__ == "__main__":
    main()