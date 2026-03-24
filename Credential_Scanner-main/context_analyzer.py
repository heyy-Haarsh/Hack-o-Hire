import re

URGENCY = [
    "verify your account", "suspended", "unusual activity",
    "click here immediately", "act now", "account will be closed",
    "confirm your details", "unauthorized access", "security alert",
    "otp expires", "update your payment", "validate your","will be blocked", "transaction initiated",
"if this was not you", "verify immediately",
"account will be suspended", "click here",
"re-verification required", "action required"
]

INTERNAL_EXPOSURE = [
    "attached please find", "please use the following",
    "credentials are", "login details", "access details below",
    "here are the details", "please keep confidential",
    "as discussed", "use the following credentials",
]

IMPERSONATION = [
    "barclays bank", "barclays security", "barclays team",
    "dear valued customer", "your barclays account",
    "barclays fraud", "barclays helpdesk","fraud prevention team", "security department",
"barclays alerts", "barclays-secure",
"bank security", "fraud team"
]

def deduplicate(findings: list) -> list:
    """
    Smart deduplication with confidence boosting.
    Handles cases where regex and LLM find the same
    credential but with slightly different text.
    """
    # First pass — exact hash match
    groups = {}
    for f in findings:
        h = f["value_hash"]
        if h not in groups:
            groups[h] = []
        groups[h].append(f)

    # Second pass — fuzzy match
    # Check if one finding's redacted value appears
    # inside another finding's context snippet
    processed = list(groups.values())
    merged = []
    used = set()

    for i, group_a in enumerate(processed):
        if i in used:
            continue
        base_group = list(group_a)

        for j, group_b in enumerate(processed):
            if i == j or j in used:
                continue

            a = group_a[0]
            b = group_b[0]

            # Check if they are talking about the same credential
            # by seeing if their evidence overlaps
            a_evidence = a.get("context_snippet", "").lower()
            b_evidence = b.get("context_snippet", "").lower()
            a_redacted = a.get("redacted_value", "")[:4].lower()
            b_redacted = b.get("redacted_value", "")[:4].lower()

            # If first 4 chars of redacted value match
            # and they are the same credential type family
            same_type = (
                a.get("credential_type", "") == b.get("credential_type", "")
                or (a_redacted and b_redacted and a_redacted == b_redacted)
                or (a_redacted and a_redacted in b_evidence)
                or (b_redacted and b_redacted in a_evidence)
            )

            if same_type and a.get("layer") != b.get("layer"):
                base_group.extend(group_b)
                used.add(j)

        used.add(i)
        merged.append(base_group)

    # Now combine each merged group
    combined = []
    for group in merged:
        if len(group) == 1:
            f = group[0].copy()
            f["detected_by"]  = [f["layer"]]
            f["layer_count"]  = 1
            combined.append(f)
        else:
            base = max(group, key=lambda x: x["confidence"]).copy()
            layers_found        = list(set(f["layer"] for f in group))
            base["detected_by"] = layers_found
            base["layer_count"] = len(layers_found)

            boost = sum(
                f["confidence"] * 0.30
                for f in group if f["layer"] != base["layer"]
            )
            base["confidence"] = min(base["confidence"] + boost, 0.99)

            tier_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
            base["risk_tier"] = max(
                group,
                key=lambda x: tier_order.get(x["risk_tier"], 0)
            )["risk_tier"]

            combined.append(base)

    return combined


def analyze_context(text: str, findings: list) -> dict:
    low = text.lower()

    urgency       = any(p in low for p in URGENCY)
    internal      = any(p in low for p in INTERNAL_EXPOSURE)
    impersonation = any(p in low for p in IMPERSONATION)
    categories    = set(f.get("category", "") for f in findings)
    multi_cred    = len(categories) >= 2
    has_critical  = any(f["risk_tier"] == "Critical" for f in findings)
    has_attachment = bool(re.search(
        r"(?i)(attached|attachment|find attached|see attached)", text))
    multi_layer_confirmed = sum(
        1 for f in findings if f.get("layer_count", 1) > 1
    )

    multiplier = 1.0
    if urgency:        multiplier += 0.25
    if impersonation:  multiplier += 0.30
    if internal:       multiplier += 0.20
    if multi_cred:     multiplier += 0.20
    if has_critical and (urgency or impersonation):
        multiplier += 0.30
    if multi_layer_confirmed >= 2:
        multiplier += 0.15

    return {
        "has_urgency_language":          urgency,
        "has_internal_exposure_signals": internal,
        "has_impersonation_signals":     impersonation,
        "has_multiple_credential_types": multi_cred,
        "has_attachment_reference":      has_attachment,
        "credential_categories":         list(categories),
        "multi_layer_confirmed_count":   multi_layer_confirmed,
        "context_multiplier":            round(multiplier, 2),
    }