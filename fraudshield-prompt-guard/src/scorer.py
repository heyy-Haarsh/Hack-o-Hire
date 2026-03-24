# src/scorer.py
# Fuses scores from all detection layers into final verdict

LAYER_WEIGHTS = {
    "regex":       0.25,
    "yara":        0.20,
    "transformer": 0.50,
    "canary":      1.00,
}

BLOCK_THRESHOLD   = 55
WARN_THRESHOLD    = 30
SANITIZE_METHOD   = "both"


def fuse_scores(layer_results: dict) -> dict:
    canary = layer_results.get("canary", {})
    if canary.get("canary_leaked") or canary.get("injection_score", 0) >= 100:
        return {
            "injection_score": 100,
            "verdict":         "CRITICAL",
            "block":           True,
            "action":          "BLOCK_AND_ALERT",
            "reason":          "Canary token leaked — successful prompt injection confirmed",
            "dominant_layer":  "canary",
        }

    weighted_sum = 0.0
    total_weight = 0.0
    dominant     = "none"
    max_raw      = 0

    for layer, weight in LAYER_WEIGHTS.items():
        if layer == "canary":
            continue
        result = layer_results.get(layer, {})
        score  = result.get("injection_score", 0)
        weighted_sum += score * weight
        total_weight += weight
        if score > max_raw:
            max_raw  = score
            dominant = layer

    # ── THIS LINE WAS MISSING ──────────────────────────────────────
    fused_score = round(weighted_sum / total_weight) if total_weight > 0 else 0
    final_score = min(100, max(fused_score, max_raw // 2))
    # ──────────────────────────────────────────────────────────────

    regex_score = layer_results.get("regex", {}).get("injection_score", 0)
    yara_score  = layer_results.get("yara",  {}).get("injection_score", 0)
    rule_max    = max(regex_score, yara_score)

    if final_score >= BLOCK_THRESHOLD or rule_max >= 85:
        verdict = "INJECTION"
        block   = True
        action  = "BLOCK"
    elif final_score >= WARN_THRESHOLD:
        verdict = "SUSPICIOUS"
        block   = False
        action  = "SANITIZE"
    else:
        verdict = "CLEAN"
        block   = False
        action  = "ALLOW"

    return {
        "injection_score": final_score,
        "verdict":         verdict,
        "block":           block,
        "action":          action,
        "dominant_layer":  dominant,
        "layer_scores": {
            layer: layer_results.get(layer, {}).get("injection_score", 0)
            for layer in LAYER_WEIGHTS
        },
    }

def get_human_summary(verdict: str, score: int, dominant: str) -> str:
    if verdict == "CRITICAL":
        return "CRITICAL: Confirmed prompt injection — canary token leaked. LLM was successfully compromised."
    if verdict == "INJECTION":
        return f"Prompt injection detected (score {score}/100) by {dominant} layer. Request blocked."
    if verdict == "SUSPICIOUS":
        return f"Suspicious patterns detected (score {score}/100). Prompt sanitized before processing."
    return f"Input appears clean (score {score}/100). Processing normally."
