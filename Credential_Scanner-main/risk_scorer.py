TIER_POINTS = {
    "Critical": 35,
    "High":     20,
    "Medium":   10,
    "Low":       5,
}

ACTIONS = {
    "Clean":    "No action required. Log for audit.",
    "Low":      "Flag for analyst review within 48 hours.",
    "Medium":   "Assign to fraud analyst within 24 hours.",
    "High":     "Quarantine email. Revoke credentials. Alert customer.",
    "Critical": "IMMEDIATE: Quarantine + escalate to SOC + notify compliance.",
}


def get_label(score: float) -> str:
    if score <= 20: return "Clean"
    if score <= 40: return "Low"
    if score <= 60: return "Medium"
    if score <= 80: return "High"
    return "Critical"


def calculate_risk(findings: list, context: dict) -> dict:
    if not findings:
        return {
            "risk_score":         0.0,
            "risk_label":         "Clean",
            "human_summary":      "No credentials detected. Email appears safe.",
            "recommended_action": ACTIONS["Clean"],
        }

    base = 0.0
    for f in findings:
        points      = TIER_POINTS.get(f["risk_tier"], 5)
        confidence  = f.get("confidence", 0.7)
        layer_count = f.get("layer_count", 1)
        weight      = 0.80 if (f.get("layer") == "llm"
                               and layer_count == 1) else 1.0
        base += points * confidence * weight

    base  = min(base, 100.0)
    score = round(
        min(base * context.get("context_multiplier", 1.0), 100.0), 1
    )
    label = get_label(score)

    counts = {}
    for f in findings:
        counts[f["description"]] = counts.get(f["description"], 0) + 1

    summary  = f"Found {len(findings)} credential(s): "
    summary += ", ".join(f"{v}x {k}" for k, v in counts.items()) + "."

    multi = sum(1 for f in findings if f.get("layer_count", 1) > 1)
    if multi:
        summary += f" {multi} finding(s) confirmed by multiple layers."
    if context.get("has_impersonation_signals"):
        summary += " Bank impersonation signals detected."
    if context.get("has_urgency_language"):
        summary += " Urgency/pressure language present."
    if context.get("has_internal_exposure_signals"):
        summary += " Internal credential exposure likely."

    return {
        "risk_score":         score,
        "risk_label":         label,
        "human_summary":      summary,
        "recommended_action": ACTIONS.get(label, "Review manually."),
    }