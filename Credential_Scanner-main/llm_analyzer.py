import ollama
import json
import hashlib
import re

MODEL = "llama3:latest"

SYSTEM_PROMPT = """
You are a security analyst at Barclays Bank specializing in credential exposure detection.
Your response must be ONLY valid JSON. No text before or after. Start with { end with }.

You MUST detect and report ALL of the following:

STRUCTURED CREDENTIALS:
- Passwords e.g. "Password: Hello@1234"
- PINs e.g. "PIN: 4729" or "PIN is four seven two one"
- OTPs e.g. "OTP: 748291" or "verification code: 847291"
- CVV codes e.g. "CVV: 453"
- Card numbers e.g. "Card Number: 4111 1111 1111 1111"
- Account numbers e.g. "Account Number: GB29 BARC 2014 7093 1111 11"
- Sort codes e.g. "Sort Code: 20-45-53"
- IBAN numbers e.g. "GB29 BARC 2014 7093 1111 11"
- PAN numbers e.g. "ABCDE1234F"sss
- Aadhaar numbers e.g. "2345 6789 0123"
- API keys, tokens, secret keys of any format
- Any number sequence following labels like:
  account number, sort code, card number, pan number,
  aadhaar number, cvv, pin, otp, password, token, key

UNSTRUCTURED CREDENTIALS:
- Credentials written as words e.g. "PIN is four seven two one"
- Implied credentials e.g. "same password as before"
- Security question answers e.g. "maiden name is Henderson"
- Passphrases e.g. "passphrase is golden sunrise delta"

PHISHING SIGNALS:
- Urgency language e.g. "act now", "immediately", "account will be blocked"
- Threats e.g. "account will be suspended", "permanent closure"
- Bank impersonation e.g. "Barclays Security Team", "Barclays Fraud Prevention"
- Fear tactics e.g. "transaction initiated", "unauthorized access"
- Suspicious sender domains e.g. barclays-secure.net, barclays-verify.com

Return ONLY this JSON format:
{
  "credential_findings": [
    {
      "type": "exact credential type e.g. password / card_number / otp / pin",
      "description": "clear human readable description of what was found",
      "risk_tier": "Critical or High or Medium or Low",
      "evidence": "exact text snippet copied from the email",
      "confidence": 0.95
    }
  ],
  "phishing_signals": [
    "each phishing signal as a separate string"
  ]
}

Strict rules:
- Start response with { immediately — no introduction text
- evidence field must contain actual text from the email — never empty
- always populate phishing_signals if ANY urgency or impersonation exists
- report EVERY credential found — never skip any
- if a number follows a credential label — always report it
- confidence must be between 0.0 and 1.0
"""
def run_llm_scan(text: str) -> list:
    # Keep text short to save RAM
    trimmed = text[:1000] if len(text) > 1000 else text
    try:
        response = ollama.chat(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": f"Find credentials:\n\n{trimmed}"
                }
            ],
            options={
                "temperature": 0.0,
                "num_predict": 800,
                "num_ctx":     2048,
            }
        )
        raw = response["message"]["content"].strip()
        print(f"LLM raw response: {raw[:300]}")
        return parse_llm_response(raw)
    except Exception as e:
        print(f"LLM scan error: {e}")
        return []


def parse_llm_response(raw: str) -> list:
    findings = []
    try:
        # Strip markdown code blocks
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()

        # Find JSON boundaries
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start == -1 or end <= start:
            print("No JSON object found in LLM response")
            # Try salvage anyway
            return salvage_llm_response(raw)
        raw = raw[start:end]

        # Try to fix common JSON issues
        # Remove trailing commas before } or ]
        import re as _re
        raw = _re.sub(r',\s*}', '}', raw)
        raw = _re.sub(r',\s*]', ']', raw)

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            print("Attempting to salvage broken JSON...")
            return salvage_llm_response(raw)

        for item in data.get("credential_findings", []):
            try:
                evidence  = str(item.get("evidence",    "")).strip()
                cred_type = str(item.get("type",         "llm_detected")).strip()
                desc      = str(item.get("description",  "")).strip()
                risk      = str(item.get("risk_tier",    "Medium")).strip()

                try:
                    conf = float(item.get("confidence", 0.75))
                except (ValueError, TypeError):
                    conf = 0.75

                if not evidence or evidence in ("", "null", "None"):
                    continue
                if not desc:
                    desc = f"LLM detected: {cred_type}"
                if risk not in ("Critical", "High", "Medium", "Low"):
                    risk = "Medium"
                conf = max(0.0, min(1.0, conf))

                findings.append({
                    "layer":           "llm",
                    "credential_type": cred_type.lower().replace(" ", "_"),
                    "description":     desc,
                    "risk_tier":       risk,
                    "category":        "llm_detected",
                    "redacted_value":  evidence[:4] + "****" if len(evidence) > 4 else "****",
                    "value_hash":      hashlib.sha256(evidence.encode()).hexdigest(),
                    "context_snippet": evidence[:200],
                    "char_position":   0,
                    "confidence":      conf,
                    "llm_detected":    True,
                })
            except Exception as item_err:
                print(f"Skipping malformed finding: {item_err}")
                continue

        signals = data.get("phishing_signals", [])
        if signals:
            signal_text = "; ".join(str(s) for s in signals[:3])
            if signal_text.strip():
                findings.append({
                    "layer":           "llm",
                    "credential_type": "phishing_intent",
                    "description":     "LLM detected: " + signal_text,
                    "risk_tier":       "High",
                    "category":        "phishing",
                    "redacted_value":  "N/A",
                    "value_hash":      hashlib.sha256(signal_text.encode()).hexdigest(),
                    "context_snippet": signal_text,
                    "char_position":   0,
                    "confidence":      0.85,
                    "llm_detected":    True,
                })

    except Exception as e:
        print(f"LLM parse error: {e}")

    return findings

def salvage_llm_response(raw: str) -> dict:
    """
    When LLM returns broken JSON extract
    complete findings using regex on the raw text.
    """
    import re as _re
    findings = []

    evidence_matches = _re.findall(r'"evidence"\s*:\s*"([^"]+)"', raw)
    type_matches     = _re.findall(r'"type"\s*:\s*"([^"]+)"', raw)
    desc_matches     = _re.findall(r'"description"\s*:\s*"([^"]+)"', raw)
    risk_matches     = _re.findall(r'"risk_tier"\s*:\s*"([^"]+)"', raw)
    conf_matches     = _re.findall(r'"confidence"\s*:\s*([\d.]+)', raw)

    for i, evidence in enumerate(evidence_matches):
        findings.append({
            "type":        type_matches[i]  if i < len(type_matches)  else "llm_detected",
            "description": desc_matches[i]  if i < len(desc_matches)  else "LLM detected credential",
            "risk_tier":   risk_matches[i]  if i < len(risk_matches)  else "High",
            "evidence":    evidence,
            "confidence":  float(conf_matches[i]) if i < len(conf_matches) else 0.75,
        })

    return {"credential_findings": findings, "phishing_signals": []}    


def check_ollama_running() -> bool:
    try:
        ollama.list()
        return True
    except Exception:
        return False