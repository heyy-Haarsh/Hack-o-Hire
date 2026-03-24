# src/transformer_detector.py
# Layer 2 — DeBERTa transformer model
# protectai/deberta-v3-base-prompt-injection
# 99.99% accuracy on eval set

import torch
from transformers import pipeline
import math

MODEL_NAME = "protectai/deberta-v3-base-prompt-injection"
MAX_LENGTH = 512

_classifier = None


def load_model():
    global _classifier
    if _classifier is None:
        print(f"[transformer] Loading {MODEL_NAME}...")
        device = 0 if torch.cuda.is_available() else -1
        _classifier = pipeline(
            "text-classification",
            model=MODEL_NAME,
            device=device,
            truncation=True,
            max_length=MAX_LENGTH,
        )
        print(f"[transformer] Model loaded on {'GPU' if device == 0 else 'CPU'}")
    return _classifier


def chunk_text(text: str, max_chars: int = 1500) -> list:
    if len(text) <= max_chars:
        return [text]
    chunks = []
    words  = text.split()
    chunk  = []
    length = 0
    for word in words:
        if length + len(word) + 1 > max_chars and chunk:
            chunks.append(" ".join(chunk))
            chunk  = [word]
            length = len(word)
        else:
            chunk.append(word)
            length += len(word) + 1
    if chunk:
        chunks.append(" ".join(chunk))
    return chunks


def run_transformer_scan(text: str) -> dict:
    clf    = load_model()
    chunks = chunk_text(text)

    results     = []
    max_score   = 0.0
    max_label   = "SAFE"

    for chunk in chunks:
        try:
            out   = clf(chunk)[0]
            label = out["label"].upper()
            conf  = out["score"]

            injection_prob = conf if label == "INJECTION" else (1.0 - conf)
            results.append({
                "chunk_preview": chunk[:80] + "..." if len(chunk) > 80 else chunk,
                "label":         label,
                "confidence":    round(conf, 4),
                "injection_prob": round(injection_prob, 4),
            })

            if injection_prob > max_score:
                max_score = injection_prob
                max_label = label

        except Exception as e:
            results.append({"error": str(e)})

    injection_score = round(max_score * 100)

    if injection_score >= 85:
        severity = "CRITICAL"
    elif injection_score >= 65:
        severity = "HIGH"
    elif injection_score >= 40:
        severity = "MEDIUM"
    elif injection_score >= 20:
        severity = "LOW"
    else:
        severity = "CLEAN"

    return {
        "layer":           "transformer",
        "injection_score": injection_score,
        "severity":        severity,
        "label":           max_label,
        "confidence":      round(max_score, 4),
        "chunks_analyzed": len(chunks),
        "chunk_results":   results,
        "model":           MODEL_NAME,
    }
