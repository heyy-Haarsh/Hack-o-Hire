import requests
import json
import time

WEBHOOK_URL = "http://localhost:5678/webhook/fraudshield"

PAYLOADS = {
    "1": {
        "name": "📧 Email Phishing Incident (CRITICAL)",
        "data": {
            "source":         "email_api",
            "tier":           "CRITICAL",
            "risk_score":     92,
            "verdict":        "PHISHING",
            "outlook_action": "QUARANTINE",
            "top_indicators": [
                "Urgency language detected (immediate suspension)",
                "Sender domain mismatch (barclays-secure.xyz)",
                "Credential harvesting link found"
            ],
            "email_preview":  "Dear Customer, your account has been suspended due to unusual activity. Click here to verify your identity.",
            "llm_summary":    "The email attempts to steal credentials using an urgent tone and a spoofed Barclays domain. It bypassed initial rule checks but the AI model flagged the domain structure with 92% confidence."
        }
    },
    "2": {
        "name": "🎙️ Voice Deepfake Incident (HIGH)",
        "data": {
            "source":         "voice_api",
            "tier":           "HIGH",
            "risk_score":     81,
            "verdict":        "FAKE",
            "outlook_action": "BLOCK_CALLER",
            "top_indicators": [
                "Unnatural frequency variations (AI generation)",
                "Lack of human breathing artifacts",
                "Voice perfectly matches known CEO impersonation profile"
            ],
            "email_preview":  "Suspicious incoming branch transfer request audio detected.",
            "llm_summary":    "The audio exhibits artificial frequency smoothing consistent with ElevenLabs generation software. It lacks natural human breath pauses and exhibits digital artifacting in the upper register."
        }
    }
}

print("=============================================")
print("  🤖 FraudShield -> n8n Pipeline Demo Suite")
print("=============================================\n")

for key, details in PAYLOADS.items():
    print(f"[{key}] Simulate: {details['name']}")

choice = input("\nSelect a pipeline to trigger (1 or 2): ").strip()

if choice in PAYLOADS:
    scenario = PAYLOADS[choice]
    print(f"\n📡 Pushing {scenario['name']} directly to n8n...")
    try:
        r = requests.post(WEBHOOK_URL, json=scenario["data"], timeout=3)
        print(f"✅ Success! Response code: {r.status_code}")
        print("👀 Look at the n8n Executions tab right now to see the LLM summary!")
    except Exception as e:
        print(f"❌ Error: Could not reach n8n. Ensure 'npx n8n' is running. Details: {e}")
else:
    print("Invalid choice.")
