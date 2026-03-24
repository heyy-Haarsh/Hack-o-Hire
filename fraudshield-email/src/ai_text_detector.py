# src/ai_text_detector.py
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from transformers import GPT2LMHeadModel, GPT2TokenizerFast
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from config import DEVICE

_roberta_tokenizer = None
_roberta_model     = None
_gpt2_model        = None
_gpt2_tokenizer    = None


def load_ai_detector():
    global _roberta_tokenizer, _roberta_model
    if _roberta_model is None:
        print("  Loading AI text detector (roberta-base-openai-detector)...")
        model_id = "openai-community/roberta-base-openai-detector"
        _roberta_tokenizer = AutoTokenizer.from_pretrained(model_id)
        _roberta_model     = AutoModelForSequenceClassification.from_pretrained(
            model_id
        ).to(DEVICE)
        _roberta_model.eval()
        print("  AI detector loaded")


def load_perplexity_model():
    global _gpt2_model, _gpt2_tokenizer
    if _gpt2_model is None:
        print("  Loading GPT-2 perplexity model...")
        _gpt2_tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
        _gpt2_model     = GPT2LMHeadModel.from_pretrained("gpt2").to(DEVICE)
        _gpt2_model.eval()
        print("  GPT-2 loaded")


def compute_perplexity(text: str) -> float:
    """
    Compute GPT-2 perplexity of text.
    Human text     → perplexity typically 50-200  (unpredictable)
    AI-written text → perplexity typically 10-50  (very predictable)
    Lower perplexity = more likely AI-written.
    """
    load_perplexity_model()
    text = text[:500]
    try:
        enc      = _gpt2_tokenizer(text, return_tensors="pt",
                                   truncation=True, max_length=256)
        ids      = enc.input_ids.to(DEVICE)
        with torch.no_grad():
            loss = _gpt2_model(ids, labels=ids).loss
        return float(torch.exp(loss).item())
    except Exception:
        return 100.0


def detect_ai_text(text: str) -> dict:
    """
    Detect if text was written by an AI model.
    Returns probability 0-1 (1 = definitely AI-written).

    Combines:
    - RoBERTa detector (trained to detect GPT-2 outputs)
    - GPT-2 perplexity (low perplexity = likely AI-written)
    """
    load_ai_detector()

    # RoBERTa score
    text_chunk = text[:512]
    inputs = _roberta_tokenizer(
        text_chunk, return_tensors="pt",
        truncation=True, max_length=512
    ).to(DEVICE)

    with torch.no_grad():
        logits = _roberta_model(**inputs).logits
        probs  = torch.softmax(logits, dim=-1)
        # Label 1 = AI-generated in this model
        ai_prob_roberta = float(probs[0][1].item())

    # Perplexity score
    perplexity  = compute_perplexity(text)
    # Normalise: perplexity 10 → score 1.0 (definitely AI)
    #            perplexity 100+ → score 0.0 (likely human)
    perp_score  = max(0.0, min(1.0, (100.0 - perplexity) / 90.0))

    # Fuse: RoBERTa is more reliable, perplexity adds signal
    ai_probability = 0.7 * ai_prob_roberta + 0.3 * perp_score

    return {
        "ai_generated_probability": round(ai_probability, 4),
        "roberta_ai_score":         round(ai_prob_roberta, 4),
        "perplexity":               round(perplexity, 2),
        "perplexity_score":         round(perp_score, 4),
        "likely_ai_written":        ai_probability > 0.5,
    }


if __name__ == "__main__":
    print("Testing AI text detector...")
    print()

    human = "Hey John, just checking in about the meeting tomorrow. Can we push it to 3pm? I have a call before that. Thanks, Sarah"

    ai_phishing = "Dear Valued Customer, We have detected unusual activity on your Barclays account. To ensure the security of your financial information, please verify your credentials immediately by clicking the secure link below. Failure to do so within 24 hours will result in account suspension."

    print("Human-written email:")
    r1 = detect_ai_text(human)
    print(f"  AI probability : {r1['ai_generated_probability']:.0%}")
    print(f"  Perplexity     : {r1['perplexity']}")
    print(f"  Likely AI      : {r1['likely_ai_written']}")

    print()
    print("AI-written phishing email:")
    r2 = detect_ai_text(ai_phishing)
    print(f"  AI probability : {r2['ai_generated_probability']:.0%}")
    print(f"  Perplexity     : {r2['perplexity']}")
    print(f"  Likely AI      : {r2['likely_ai_written']}")  