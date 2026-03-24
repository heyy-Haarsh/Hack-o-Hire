# src/explainer.py
import numpy as np
import shap
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import DATA_PROC, MODELS_DIR, N_MFCC, OUTPUTS_DIR


# ── Feature name generation ────────────────────────────────────────
def make_feature_names():
    names = []
    for stat in ["mean", "std"]:
        for i in range(N_MFCC):
            names.append(f"mfcc_{stat}_{i}")
    for stat in ["mean", "std"]:
        for i in range(N_MFCC):
            names.append(f"delta1_{stat}_{i}")
    for stat in ["mean", "std"]:
        for i in range(N_MFCC):
            names.append(f"delta2_{stat}_{i}")
    for stat in ["mean", "std"]:
        for i in range(7):
            names.append(f"spec_contrast_{stat}_{i}")
    names += [
        "centroid_mean", "centroid_std",
        "rolloff_mean",  "rolloff_std",
        "zcr_mean",      "zcr_std",
    ]
    return names


FEATURE_NAMES = make_feature_names()

# ── Human-readable descriptions for SHAP output ───────────────────
DESCRIPTIONS = {
    **{f"mfcc_mean_{i}": f"MFCC coeff {i} — spectral envelope shape"
       for i in range(N_MFCC)},
    **{f"mfcc_std_{i}":  f"MFCC coeff {i} — spectral stability variance"
       for i in range(N_MFCC)},
    **{f"delta1_mean_{i}": f"MFCC velocity coeff {i} — rate of spectral change"
       for i in range(N_MFCC)},
    **{f"delta2_mean_{i}": f"MFCC acceleration coeff {i} — spectral dynamics"
       for i in range(N_MFCC)},
    **{f"spec_contrast_mean_{i}": f"Spectral contrast band {i} — peak vs valley ratio"
       for i in range(7)},
    "centroid_mean":  "Spectral brightness — overall tonal quality",
    "centroid_std":   "Spectral brightness variance — tonal consistency",
    "rolloff_mean":   "High-frequency energy rolloff point",
    "rolloff_std":    "High-frequency rolloff variance",
    "zcr_mean":       "Voiced/unvoiced transition rate",
    "zcr_std":        "Transition rate variance — prosody smoothness",
}


def train_rf():
    """Train Random Forest on aggregate features. Takes ~2 minutes."""
    print("Loading aggregate features...")
    X_train = np.load(DATA_PROC / "train" / "aggregates.npy")
    y_train = np.load(DATA_PROC / "train" / "labels.npy")
    X_val   = np.load(DATA_PROC / "dev"   / "aggregates.npy")
    y_val   = np.load(DATA_PROC / "dev"   / "labels.npy")

    print(f"  Train: {X_train.shape}  Val: {X_val.shape}")
    print("Training Random Forest (300 trees)...")

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train, y_train)

    print("\nValidation report:")
    print(classification_report(y_val, rf.predict(X_val),
                                 target_names=["Real", "Fake"]))

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(MODELS_DIR / "rf_model.pkl", "wb") as f:
        pickle.dump(rf, f)
    print("RF saved → models/saved/rf_model.pkl")
    return rf


def load_rf():
    """Load saved RF model."""
    with open(MODELS_DIR / "rf_model.pkl", "rb") as f:
        return pickle.load(f)


def get_shap_top5(rf, x_agg: np.ndarray) -> list:
    """
    Returns top-5 contributing features as list of
    (human_readable_description, impact_value) tuples.
    """
    explainer = shap.TreeExplainer(rf)
    shap_vals = explainer.shap_values(x_agg.reshape(1, -1))

    # Handle different SHAP output formats
    if isinstance(shap_vals, list):
        sv = shap_vals[1][0]          # binary classifier — take class 1
    elif hasattr(shap_vals, 'values'):
        sv = shap_vals.values[0, :, 1] # newer SHAP returns Explanation object
    else:
        sv = shap_vals[0]

    # Flatten if still 2D
    if hasattr(sv, 'ndim') and sv.ndim > 1:
        sv = sv[:, 1] if sv.shape[1] > 1 else sv[:, 0]

    ranked = sorted(
        zip(FEATURE_NAMES, sv.tolist()),
        key=lambda x: abs(x[1]),
        reverse=True
    )[:5]

    return [
        (DESCRIPTIONS.get(name, name), float(val))
        for name, val in ranked
    ]


if __name__ == "__main__":
    train_rf()