import requests
import urllib3

# Suppress the self-signed cert warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

payload = {
    "text": "URGENT: Your Barclays account has been suspended. Verify your card details at http://barclays-secure.xyz or face legal action within 24 hours.",
    "subject": "Account Suspended - Immediate Action Required",
    "sender": "security@barclays-secure.xyz",
    "reply_to": "collect@fraudster.ru"
}

print("Firing test phishing email to FraudShield...")
try:
    # Notice verify=False to skip cert check
    r = requests.post("https://localhost:8001/analyze/email", json=payload, verify=False)
    print(f"Status Code: {r.status_code}")
    print(f"FraudShield Response:\n{r.json()}")
except Exception as e:
    print(f"Error: {e}")
