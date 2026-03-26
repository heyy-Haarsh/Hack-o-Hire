"""
bert_detector.py
────────────────────────────────────────────────────────────────────
Fine-tuned DistilBERT phishing detector.

Model: distilbert-base-uncased fine-tuned on 6 email datasets
       (CEAS_08 / Enron / Ling / Nazario / Nigerian_Fraud / SpamAssasin)
Path:  models/bert_phishing/

This module is the ML layer in the pipeline:
  Email → [Rules] → [DistilBERT ✅] → [LLM Explanation] → [URL Scan] → [Audio MFCC]
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

# ─── Model path ──────────────────────────────────────────────────────────────
_SRC_DIR        = Path(__file__).parent
_MODEL_PATH     = _SRC_DIR.parent / "models" / "bert_phishing"

# ─── Lazy singleton ──────────────────────────────────────────────────────────
_pipe           = None
_load_error: str = ""


def _load():
    """
smoke_test.py — quick end-to-end pipeline check
Run: .venv/Scripts/python.exe smoke_test.py
"""
    global _pipe, _load_error
    if _pipe is not None or _load_error:
        return

    if not (_MODEL_PATH / "config.json").exists():
        _load_error = (
            f"Fine-tuned model not found at {_MODEL_PATH}. "
            "Run: python src/train_bert.py --quick"
        )
        print(f"[BertDetector] ⚠️  {_load_error}")
        return

    try:
        from transformers import pipeline
        import torch

        device = 0 if torch.cuda.is_available() else -1
        device_label = "GPU ✅" if device == 0 else "CPU"
        print(f"[BertDetector] Loading fine-tuned DistilBERT from {_MODEL_PATH} on {device_label}…")

        _pipe = pipeline(
            "text-classification",
            model=str(_MODEL_PATH),
            tokenizer=str(_MODEL_PATH),
            device=device,
            truncation=True,
            max_length=512,
        )
        print("[BertDetector] ✅ Fine-tuned DistilBERT ready.")
    except Exception as e:
        _load_error = str(e)
        print(f"[BertDetector] ✗ Load error: {e}")


# ─── Heuristic safety net ─────────────────────────────────────────────────────
_PHISH_RE = re.compile(
    r"(urgent|click here|verify your account|account suspended"
    r"|confirm your password|act now|login immediately"
    r"|bitcoin|wire transfer|western union|nigerian prince"
    r"|you have won|lottery winner|suspicious activity detected"
    r"|your account will be (closed|suspended|terminated)"
    r"|free gift|limited time offer|congratulations you)",
    re.IGNORECASE,
)


def _heuristic_score(text: str) -> float:
    """Returns a rough phishing probability (0-1) based on keyword hits."""
    hits = len(_PHISH_RE.findall(text))
    if hits >= 3: return 0.90
    if hits == 2: return 0.70
    if hits == 1: return 0.40
    return 0.10


def _make(label: str, phishing_prob: float, confidence: float,
          model: str, note: str = "", top_category: str = "") -> Dict:
    is_phishing = label == "phishing"
    
    # ── HYBRID DECISION LOGIC ──
    # If it's a "legitimate" email but has many phishing keywords, escalate.
    # If it's "phishing" but BERT is unsure (<85%), downgrade to legitimate 
    # unless heuristics are also high.
    
    if phishing_prob >= 0.85:
        risk = "HIGH RISK 🔴"
        final_label = "phishing"
    elif phishing_prob >= 0.55:
        risk = "MEDIUM RISK 🟡"
        final_label = "phishing"
    else:
        risk = "LOW RISK 🟢"
        final_label = "legitimate"

    return {
        "label":         final_label,
        "confidence":    f"{confidence:.2%}",
        "risk_level":    risk,
        "is_phishing":   final_label == "phishing",
        "is_ai_generated": False,
        "probabilities": {
            "phishing":   f"{phishing_prob:.2%}",
            "legitimate": f"{1 - phishing_prob:.2%}",
        },
        "top_category":  top_category or label,
        "model":         model,
        "note":          note,
    }


# ─── Public detector class ────────────────────────────────────────────────────

class DistilBertEmailDetector:
    """
    Fine-tuned DistilBERT email phishing classifier.
    Drop-in replacement for the old RandomForest EmailFraudDetector.

    predict(text) → {
        label, confidence, risk_level, is_phishing,
        is_ai_generated, probabilities, model, note
    }
    """

    def predict(self, text: str) -> Dict:
        if not text or len(text.strip()) < 10:
            return _make("legitimate", 0.05, 0.95,
                         model=f"distilbert-finetuned ✅",
                         note="Text too short to classify.")

        _load()

        # Use fine-tuned model
        if _pipe is not None:
            res = self._run_model(text[:1800])
            
            # ── Hybrid Validation (Strict) ──
            # Over-biased models flag everything. We counter this by checking heuristics.
            h_score   = _heuristic_score(text[:1800])
            bert_prob = float(res['probabilities']['phishing'].strip('%'))
            
            # DECISION:
            # - If Keywords detected (h_score >= 0.4): trust model if > 0.60
            # - IF NO Keywords (h_score < 0.4): only trust model if it's EXTREMELY sure (> 98.5%)
            if res['is_phishing']:
                if h_score < 0.40 and bert_prob < 98.5:
                    res['label']       = "legitimate"
                    res['is_phishing']  = False
                    res['risk_level']   = "LOW RISK 🟢"
                    res['note'] += f" (Downgraded: Model biased ({bert_prob:.1f}%) but no phishing patterns found)"
            elif not res['is_phishing']:
                # Conversely, if model says clean but heuristics are high, escalate to Medium
                if h_score >= 0.70:
                    res['label']       = "phishing"
                    res['is_phishing']  = True
                    res['risk_level']   = "MEDIUM RISK 🟡"
                    res['note'] += " (Escalated: Model said clean but suspicious patterns found)"
                
            return res

        # Fallback if load failed
        h_score = _heuristic_score(text[:1800])
        return _make(
            label         = "phishing" if h_score >= 0.60 else "legitimate",
            phishing_prob = h_score,
            confidence    = h_score if h_score >= 0.5 else 1 - h_score,
            model         = "heuristic-fallback ⚠️",
            note          = "DistilBERT unavailable — rule-based estimate only.",
        )

    def _run_model(self, text: str) -> Dict:
        try:
            result     = _pipe(text)[0]
            raw_label  = result["label"].lower()   # "legitimate" or "phishing"
            score      = result["score"]            # confidence for top label

            is_phishing   = raw_label == "phishing"
            phishing_prob = score if is_phishing else 1.0 - score

            return _make(
                label         = raw_label,
                phishing_prob = phishing_prob,
                confidence    = score,
                model         = "distilbert-finetuned ✅",
                top_category  = (
                    "🚨 Phishing / Fraud" if is_phishing
                    else "✅ Legitimate Email"
                ),
                note = (
                    "Fine-tuned on CEAS/Enron/Ling/Nazario/Nigerian/SpamAssassin datasets."
                ),
            )
        except Exception as e:
            print(f"[BertDetector] Inference error: {e}")
            h_score = _heuristic_score(text)
            return _make(
                label         = "phishing" if h_score >= 0.60 else "legitimate",
                phishing_prob = h_score,
                confidence    = h_score if h_score >= 0.5 else 1 - h_score,
                model         = "heuristic-fallback ⚠️",
                note          = f"Inference failed ({e}). Using rule-based fallback.",
            )
