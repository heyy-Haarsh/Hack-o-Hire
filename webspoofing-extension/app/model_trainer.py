"""
model_trainer.py – Train, evaluate, and persist the XGBoost classifier.

Run directly:  python -m app.model_trainer
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from xgboost import XGBClassifier

from app.config import settings
from app.data_ingestion import DataIngestion
from app.feature_extractor import URLFeatures
from app.logger import logger


class ModelTrainer:
    """
    Trains an XGBoost model on locally-stored URL feature data.
    Saves model, scaler, and label encoder to the models/ directory.
    """

    def __init__(self) -> None:
        self.model_dir = settings.model_path.parent
        self.model_dir.mkdir(parents=True, exist_ok=True)

    def train(self) -> dict:
        """
        Full training pipeline.  Returns a metrics dict.
        """
        logger.info("=== PhishGuard Model Training Started ===")

        # 1. Data loading + feature extraction
        ingestion = DataIngestion()
        X_train, X_test, y_train, y_test, scaler, le = ingestion.train_test()

        n_classes = len(le.classes_)
        logger.info(f"Classes: {le.classes_.tolist()}")

        # 2. XGBoost model definition - Pro Configuration
        model = XGBClassifier(
            n_estimators=1200,
            max_depth=10,
            learning_rate=0.03,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="mlogloss" if n_classes > 2 else "logloss",
            objective="multi:softprob" if n_classes > 2 else "binary:logistic",
            num_class=n_classes if n_classes > 2 else None,
            random_state=settings.random_seed,
            n_jobs=-1,
            tree_method="hist",
        )

        # 3. Cross-validation
        logger.info(f"Running {settings.cv_folds}-fold cross-validation …")
        cv = StratifiedKFold(
            n_splits=settings.cv_folds, shuffle=True, random_state=settings.random_seed
        )
        # Note: CV won't use early stopping unless we use a custom loop. 
        # For simplicity, we'll avoid it during CV.
        cv_scores = cross_val_score(
            model, X_train, y_train,
            cv=cv, scoring="f1_weighted", n_jobs=-1,
        )
        logger.info(
            f"CV F1 (weighted): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}"
        )

        # 4. Final fit on full training set
        model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False,
        )

        # 5. Evaluation on held-out test set
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

        if n_classes == 2:
            roc = roc_auc_score(y_test, y_proba[:, 1])
        else:
            roc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted")

        # Placeholder for confidence, assuming it's derived from y_proba or similar
        # For now, setting to a dummy value or removing if not defined elsewhere
        confidence = np.max(y_proba, axis=1).mean() # Example: average max probability

        metrics = {
            "accuracy": float(round(acc, 4)),
            "precision": float(round(prec, 4)),
            "recall": float(round(rec, 4)),
            "f1_weighted": float(round(f1, 4)),
            "roc_auc": float(round(roc, 4)),
            "confidence": float(round(confidence, 2)),
            "cv_f1_mean": float(round(cv_scores.mean(), 4)),
            "cv_f1_std": float(round(cv_scores.std(), 4)),
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "classes": le.classes_.tolist(),
        }

        logger.info(f"Test metrics: {metrics}")
        logger.info("\n" + classification_report(y_test, y_pred, target_names=le.classes_))

        # 6. Persist artefacts
        joblib.dump(model, settings.model_path)
        joblib.dump(scaler, settings.scaler_path)
        joblib.dump(le, settings.label_encoder_path)

        # Save metrics to JSON alongside the model
        metrics_path = self.model_dir / "metrics.json"
        with metrics_path.open("w") as fh:
            json.dump(metrics, fh, indent=2)

        # Save feature importances
        importance_path = self.model_dir / "feature_importance.json"
        feat_names = URLFeatures.feature_names()
        importances = {
            name: float(imp)
            for name, imp in zip(feat_names, model.feature_importances_)
        }
        with importance_path.open("w") as fh:
            json.dump(importances, fh, indent=2)

        logger.info(f"Model saved → {settings.model_path}")
        logger.info(f"Scaler saved → {settings.scaler_path}")
        logger.info(f"Label encoder saved → {settings.label_encoder_path}")
        logger.info("=== Training Complete ===")

        return metrics


if __name__ == "__main__":
    trainer = ModelTrainer()
    result = trainer.train()
    import pprint
    pprint.pprint(result)
