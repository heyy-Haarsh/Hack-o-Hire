import requests
import urllib3
import json

urllib3.disable_warnings()

# Three distinct scenarios to show off the system logic
SCENARIOS = {
    "1": {
        "name": "🔴 CRITICAL Threat (Triggers n8n Incident & Human-in-the-Loop)",
        "payload": {
            "subject": "URGENT: Account Locked - Identity Verification Required",
            "sender": "security-alert@barclays-secure-auth.xyz",
            "reply_to": "attacker@darkweb.ru",
            "text": "Dear Customer, we detected unusual login activity. Your account has been suspended. You must urgently verify your password and login credentials at http://barclays-secure-auth.xyz/verify immediately, or face legal action."
        }
    },
    "2": {
        "name": "🟠 MEDIUM Threat (Flagged locally, no n8n workflow)",
        "payload": {
            "subject": "Important update regarding your account",
            "sender": "noreply@barcIays.com",  # Spoofed 'I' instead of 'l'
            "reply_to": "support@barclays.com",
            "text": "Hello, we have updated our terms of service. Please review the attached document to stay informed about your account features."
        }
    },
    "3": {
        "name": "🟢 CLEAN Email (Normal business)",
        "payload": {
            "subject": "Lunch tomorrow?",
            "sender": "hr@barclays.com",
            "reply_to": "hr@barclays.com",
            "text": "Hi team, just a reminder that the quarterly lunch is tomorrow at 12:30 in the main cafeteria. Please let me know if you have any dietary restrictions. Thanks!"
        }
    }
}

print("=========================================")
print("  🛡️ FraudShield Live Demo Scenarios")
print("=========================================\n")

for key, data in SCENARIOS.items():
    print(f"[{key}] {data['name']}")

print("\nPress Ctrl+C to exit.")
choice = input("\nSelect a scenario to run (1, 2, or 3): ").strip()

if choice in SCENARIOS:
    print(f"\nSending '{SCENARIOS[choice]['name']}'...")
    payload = SCENARIOS[choice]["payload"]
    payload["use_llm"] = True  # Trigger Ollama generation!
    try:
        r = requests.post(
            "https://localhost:8001/analyze/email", 
            json=payload, 
            verify=False
        )
        res = r.json()
        
        print("\n=== FraudShield Result ===")
        print(f"Verdict : {res.get('verdict')}")
        print(f"Tier    : {res.get('tier')}")
        print(f"Score   : {res.get('risk_score')}/100")
        print(f"Action  : {res.get('outlook_action')}")
        
        if res.get("tier") in ("CRITICAL", "HIGH"):
            print("\n🚨 THRESHOLD MET: n8n Incident Response Webhook Fired!")
            print("   -> Check your n8n Executions tab right now.")
        else:
            print("\n💤 THRESHOLD NOT MET: Email handled locally, n8n bypassed.")
            
    except Exception as e:
        print(f"\nError: Could not connect to API. Is it running? {e}")
else:
    print("Invalid choice.")
