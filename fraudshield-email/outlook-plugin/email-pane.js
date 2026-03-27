// email-pane.js — FraudShield Email Phishing Analyzer
// Standalone pane: phishing detection + AI content + feedback loop

(function () {

    const EMAIL_API   = "https://localhost:3000/api";
    const N8N_WEBHOOK = "http://localhost:5678/webhook/fraudshield";

    let lastResult    = null;
    let lastEmailData = null;

    Office.onReady(function (info) {
        if (info.host === Office.HostType.Outlook) {
            document.getElementById("analyze-btn").addEventListener("click", analyzeEmail);
            document.getElementById("refresh-btn").addEventListener("click", analyzeEmail);
            document.getElementById("btn-safe").addEventListener("click",  () => submitFeedback("LEGITIMATE"));
            document.getElementById("btn-phish").addEventListener("click", () => submitFeedback("PHISHING"));
        }
    });

    // ── Email analysis ─────────────────────────────────────────────
    async function analyzeEmail() {
        showLoading();
        hideFeedback();

        try {
            const item = Office.context.mailbox.item;
            if (!item) { showError("No email selected."); return; }

            let subject = "";
            let sender  = "";
            try { subject = item.subject || ""; } catch (e) {}
            try { sender  = item.from ? (item.from.emailAddress || "") : ""; } catch (e) {}

            const body = await getEmailBody(item);
            lastEmailData = { subject, sender, body, attachment_names: [] };

            const payload = {
                text:     body.substring(0, 3000),
                subject:  subject,
                sender:   sender,
                receiver: "",
                reply_to: "",
                cc:       "",
                use_llm:  false
            };

            // Trigger n8n pipeline (fire and forget — don't block on failure)
            fetch(N8N_WEBHOOK, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body:    JSON.stringify(payload)
            }).catch(() => {});

            const response = await fetch(`${EMAIL_API}/analyze/email`, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body:    JSON.stringify(payload)
            });

            if (!response.ok) throw new Error(`API returned ${response.status}`);

            lastResult = await response.json();
            displayResults(buildDisplayResult(lastResult));
            showFeedback();

        } catch (error) {
            console.error("Email analysis failed:", error);
            showError(
                "FraudShield Email API not reachable.<br>" +
                "Make sure <strong>python src/api.py</strong> is running on port 8001 and n8n on port 5678.<br>" +
                "<small style='color:#888'>" + error.message + "</small>"
            );
        }
    }

    // ── Feedback ───────────────────────────────────────────────────
    async function submitFeedback(userVerdict) {
        if (!lastResult || !lastEmailData) {
            alert("Please analyze an email first.");
            return;
        }

        const btnSafe  = document.getElementById("btn-safe");
        const btnPhish = document.getElementById("btn-phish");
        const fbMsg    = document.getElementById("feedback-message");

        if (btnSafe)  { btnSafe.disabled  = true; btnSafe.style.opacity  = "0.5"; }
        if (btnPhish) { btnPhish.disabled = true; btnPhish.style.opacity = "0.5"; }
        if (fbMsg)    fbMsg.innerHTML = "<em>Saving feedback...</em>";

        try {
            const response = await fetch(`${EMAIL_API}/feedback`, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email_text:     lastEmailData.body.substring(0, 1000),
                    email_subject:  lastEmailData.subject,
                    email_sender:   lastEmailData.sender,
                    model_verdict:  lastResult.verdict || "",
                    model_score:    lastResult.risk_score || 0,
                    user_verdict:   userVerdict,
                    prediction_id:  lastResult.prediction_id || null
                })
            });

            const result = await response.json();
            if (fbMsg) {
                if (result.was_correct) {
                    fbMsg.innerHTML = `
                        <div style="background:#d4edda;color:#155724;padding:8px;border-radius:6px;font-size:12px;text-align:center">
                            ✅ Confirmed — model was correct. Saved to PostgreSQL.
                        </div>`;
                } else {
                    fbMsg.innerHTML = `
                        <div style="background:#fff3cd;color:#856404;padding:8px;border-radius:6px;font-size:12px;text-align:center">
                            📝 Correction saved — queued for retraining.<br>
                            <small>Model: <strong>${result.model_said}</strong> → You: <strong>${result.user_said}</strong></small>
                        </div>`;
                }
            }
        } catch (err) {
            console.error("Feedback error:", err);
            if (btnSafe)  { btnSafe.disabled  = false; btnSafe.style.opacity  = "1"; }
            if (btnPhish) { btnPhish.disabled = false; btnPhish.style.opacity = "1"; }
            if (fbMsg)    fbMsg.innerHTML = '<span style="color:#dc3545">Failed to save feedback.</span>';
        }
    }

    // ── Display helpers ────────────────────────────────────────────
    function buildDisplayResult(data) {
        const tier  = data.tier || "LOW";
        const score = (data.risk_score || 0) / 100;

        const ruleIndicators = (data.top_indicators || [])
            .filter(i => !i.includes("RoBERTa") && !i.includes("AI-generated"));

        const findings = {
            "Phishing Detection": {
                issues: data.verdict === "PHISHING" ? [
                    `RoBERTa: ${pct(data.roberta_phishing_prob)} phishing confidence`,
                    `Verdict: ${data.verdict} — ${tier}`
                ] : [],
                safe: data.verdict === "LEGITIMATE"
            },
            "AI-Generated Content": {
                issues: (data.ai_generated_probability || 0) > 0.6 ? [
                    `AI-written probability: ${pct(data.ai_generated_probability)}`,
                    "Likely written by GPT-4 or similar"
                ] : [],
                safe: (data.ai_generated_probability || 0) <= 0.6
            },
            "Phishing Language Patterns": {
                issues: ruleIndicators,
                safe:   ruleIndicators.length === 0
            }
        };

        if (data.header_flags && data.header_flags.length > 0) {
            findings["Email Header Analysis"] = {
                issues: data.header_flags,
                safe:   false
            };
        }

        return {
            risk_score:      score,
            risk_level:      tier,
            findings:        findings,
            recommendations: getRecommendations(tier, data.outlook_action),
            explanations: {
                "Risk Score":       `${data.risk_score}/100 — ${tier}`,
                "Action":           data.outlook_action || "ALLOW",
                "RoBERTa Score":    `${pct(data.roberta_phishing_prob)} phishing probability`,
                "Rule Score":       `${data.rule_based_score || 0}% pattern-based`,
                "AI Detection":     `${pct(data.ai_generated_probability)} AI-written`,
                "Processing Time":  `${data.processing_ms}ms`
            }
        };
    }

    function displayResults(result) {
        updateRiskIndicator(result.risk_score, result.risk_level);
        displayFindings(result.findings);
        displayRecommendations(result.recommendations);
        displayExplanations(result.explanations);
        document.getElementById("attachments").innerHTML = "";
        hideLoading();
        document.getElementById("results").style.display = "block";
    }

    function updateRiskIndicator(score, level) {
        const el = document.getElementById("risk-indicator");
        const colors = { LOW: "#28a745", MEDIUM: "#ffc107", HIGH: "#fd7e14", CRITICAL: "#dc3545" };
        el.style.backgroundColor = colors[level] || "#28a745";
        el.style.color = level === "MEDIUM" ? "#333" : "white";
        el.innerHTML = `${level} RISK (${Math.round(score * 100)}%)`;
    }

    function displayFindings(findings) {
        const container = document.getElementById("findings-container");
        container.innerHTML = "";
        for (const [category, details] of Object.entries(findings)) {
            const div = document.createElement("div");
            div.className = "finding-category";
            if (details.issues && details.issues.length > 0) {
                div.innerHTML = `<h4>${category}</h4><ul>${details.issues.map(i => `<li class="issue">⚠ ${i}</li>`).join("")}</ul>`;
            } else if (details.safe) {
                div.innerHTML = `<h4>${category}</h4><p class="safe">✅ No issues detected</p>`;
            }
            if (div.innerHTML) container.appendChild(div);
        }
    }

    function displayRecommendations(recommendations) {
        const c = document.getElementById("recommendations");
        c.innerHTML = "<h4>Recommendations</h4>";
        const ul = document.createElement("ul");
        recommendations.forEach(r => {
            const li = document.createElement("li");
            li.innerHTML = r;
            ul.appendChild(li);
        });
        c.appendChild(ul);
    }

    function displayExplanations(explanations) {
        const c = document.getElementById("explanations");
        c.innerHTML = "<h4>Analysis Details</h4>";
        for (const [k, v] of Object.entries(explanations)) {
            const p = document.createElement("p");
            p.className = "explanation";
            p.innerHTML = `<strong>${k}:</strong> ${v}`;
            c.appendChild(p);
        }
    }

    function showFeedback() {
        const fb = document.getElementById("feedback-section");
        if (!fb) return;
        fb.style.display = "block";
        const btnSafe  = document.getElementById("btn-safe");
        const btnPhish = document.getElementById("btn-phish");
        const fbMsg    = document.getElementById("feedback-message");
        if (btnSafe)  { btnSafe.disabled  = false; btnSafe.style.opacity  = "1"; }
        if (btnPhish) { btnPhish.disabled = false; btnPhish.style.opacity = "1"; }
        if (fbMsg)    fbMsg.innerHTML = "";
    }

    function hideFeedback() {
        const fb = document.getElementById("feedback-section");
        if (fb) fb.style.display = "none";
    }

    function getRecommendations(tier, action) {
        const m = {
            CRITICAL: [
                `⛔ Action: ${action} — Do NOT interact with this email`,
                "Do NOT click any links or open attachments",
                "Report immediately to your security team",
                "Contact sender through a verified separate channel"
            ],
            HIGH: [
                `⚠ Action: ${action} — Treat with extreme caution`,
                "Verify sender identity before responding",
                "Do not open attachments without IT approval"
            ],
            MEDIUM: [
                `🔍 Action: ${action} — Exercise caution`,
                "Verify the sender before clicking links"
            ],
            LOW: [
                "✅ Email appears legitimate",
                "Standard precautions apply"
            ]
        };
        return m[tier] || m.LOW;
    }

    async function getEmailBody(item) {
        return new Promise(resolve => {
            const timeout = setTimeout(() => resolve(""), 10000);
            if (item.body) {
                item.body.getAsync(Office.CoercionType.Text, function (r) {
                    clearTimeout(timeout);
                    resolve(r.status === Office.AsyncResultStatus.Succeeded ? r.value || "" : "");
                });
            } else {
                clearTimeout(timeout);
                resolve("");
            }
        });
    }

    function showLoading() {
        document.getElementById("loading").style.display  = "block";
        document.getElementById("results").style.display  = "none";
        document.getElementById("error").style.display    = "none";
    }

    function hideLoading() {
        document.getElementById("loading").style.display = "none";
    }

    function showError(msg) {
        document.getElementById("error").innerHTML        = msg;
        document.getElementById("error").style.display   = "block";
        document.getElementById("loading").style.display = "none";
    }

    function pct(val) {
        return `${Math.round((val || 0) * 100)}%`;
    }

})();
