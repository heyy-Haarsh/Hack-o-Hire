// outlook-plugin/taskpane.js
// FraudShield AI — Barclays Hack-o-Hire
// Full version: email analysis + voice deepfake + feedback loop

(function () {

    // ── API routes through proxy on port 3000 ─────────────────────
    const EMAIL_API = "https://localhost:3000/api";
    const VOICE_API = "https://localhost:3000/voice";
    const CRED_API = "https://localhost:3000/credential";
    const GUARD_API = "https://localhost:3000/guard";  // Prompt Guard middleware
    const N8N_WEBHOOK = "http://localhost:5678/webhook/fraudshield";  // Direct n8n pipeline webhook

    // ── State ──────────────────────────────────────────────────────
    let lastResult = null;
    let lastEmailData = null;
    let mediaRecorder = null;
    let audioChunks = [];

    // ── Office init ────────────────────────────────────────────────
    Office.onReady(function (info) {
        if (info.host === Office.HostType.Outlook) {
            // Email buttons
            document.getElementById("analyze-btn").addEventListener("click", analyzeEmail);
            document.getElementById("refresh-btn").addEventListener("click", analyzeEmail);

            // Voice buttons — event listeners instead of onclick
            document.getElementById("btn-record").addEventListener("click", startRecording);
            document.getElementById("btn-stop").addEventListener("click", stopRecording);
            document.getElementById("btn-upload-audio").addEventListener("change", uploadAudio);

            // Feedback buttons
            document.getElementById("btn-safe").addEventListener("click", () => submitFeedback("LEGITIMATE"));
            document.getElementById("btn-phish").addEventListener("click", () => submitFeedback("PHISHING"));

            document.getElementById("btn-cred-scan").addEventListener("click", scanCredentials);

            // Prompt Guard buttons
            document.getElementById("btn-guard-scan").addEventListener("click", scanPromptGuard);
            document.getElementById("btn-guard-autofill").addEventListener("click", async () => {
                try {
                    const body = await getEmailBody(Office.context.mailbox.item);
                    document.getElementById("guard-prompt").value = body.substring(0, 1500);
                } catch (e) {
                    document.getElementById("guard-prompt").value = "";
                }
            });
        }
    });

    // ── Prompt Injection Guard ─────────────────────────────────────
    async function scanPromptGuard() {
        const prompt = (document.getElementById("guard-prompt").value || "").trim();
        const resultEl = document.getElementById("guard-result");
        const btn = document.getElementById("btn-guard-scan");

        if (!prompt) {
            resultEl.innerHTML = '<span style="color:#856404">Enter a prompt to scan first.</span>';
            return;
        }

        btn.disabled = true;
        resultEl.innerHTML = '<span style="color:#666">Scanning…</span>';

        try {
            const response = await fetch(`${GUARD_API}/check`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    prompt: prompt,
                    context: "email",
                    session_id: "plugin_" + Date.now()
                })
            });

            if (!response.ok) throw new Error(`Guard API returned ${response.status}`);
            const r = await response.json();

            const verdict   = r.verdict  || "CLEAN";
            const score     = r.injection_score || 0;
            const block     = r.block || false;
            const layer     = r.dominant_layer || "none";
            const summary   = r.human_summary || "";
            const sanitized = r.sanitized_prompt || null;

            const schemeMap = {
                CRITICAL:   { bg: "#dc3545", bar: "#dc3545" },
                INJECTION:  { bg: "#fd7e14", bar: "#fd7e14" },
                SUSPICIOUS: { bg: "#ffc107", bar: "#ffc107" },
                CLEAN:      { bg: "#28a745", bar: "#28a745" },
            };
            const sc = schemeMap[verdict] || schemeMap.CLEAN;

            const layers = r.layer_scores || {};
            const layerRows = Object.entries(layers).map(([name, s]) => {
                const barW = Math.round(s);
                const barC = s >= 75 ? "#dc3545" : s >= 40 ? "#fd7e14" : "#28a745";
                return `
                <div class="guard-layer-row">
                    <span style="text-transform:capitalize">${name}</span>
                    <span>
                        <span style="display:inline-block;width:${barW}px;max-width:80px;
                            height:6px;background:${barC};border-radius:3px;vertical-align:middle"></span>
                        <span class="guard-layer-score" style="color:${barC}">${s}/100</span>
                    </span>
                </div>`;
            }).join("");

            const sanitizedHtml = sanitized
                ? `<div style="margin-top:8px;padding:6px 8px;background:#fff3cd;
                              border-radius:4px;font-size:11px;color:#856404">
                       <strong>Sanitized prompt:</strong><br>
                       <span style="color:#555">${sanitized.substring(0, 120)}${sanitized.length > 120 ? '…' : ''}</span>
                   </div>` : "";

            const actionBadge = block
                ? `<span style="background:#dc3545;color:white;padding:2px 7px;border-radius:3px;font-size:11px;font-weight:600">BLOCKED</span>`
                : `<span style="background:#28a745;color:white;padding:2px 7px;border-radius:3px;font-size:11px;font-weight:600">ALLOWED</span>`;

            resultEl.innerHTML = `
                <div style="background:#f8f9fa;border-radius:6px;padding:10px;
                            border-left:4px solid ${sc.bg};margin-top:4px">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                        <span style="font-weight:700;font-size:13px;color:${sc.bg}">
                            ${verdict} &nbsp;${actionBadge}
                        </span>
                        <span style="font-size:13px;font-weight:600;color:${sc.bg}">${score}/100</span>
                    </div>
                    <div style="background:#e9ecef;border-radius:3px;height:6px;margin-bottom:8px">
                        <div style="width:${score}%;height:100%;background:${sc.bar};border-radius:3px"></div>
                    </div>
                    <div style="font-size:11px;color:#555;margin-bottom:8px">${summary}</div>
                    <div style="border-top:1px solid #dee2e6;padding-top:6px">
                        <div style="font-size:11px;font-weight:600;color:#888;
                                    margin-bottom:4px;text-transform:uppercase">Layer Scores</div>
                        ${layerRows}
                    </div>
                    <div style="font-size:11px;color:#888;margin-top:6px">
                        Dominant signal: <strong>${layer}</strong> &nbsp;|
                        ${r.processing_ms || 0}ms
                    </div>
                    ${sanitizedHtml}
                </div>`;

        } catch (err) {
            console.error("Guard scan error:", err);
            resultEl.innerHTML =
                '<span style="color:#dc3545">⚠ Prompt Guard not reachable. ' +
                'Start: <code>python fraudshield-prompt-guard/src/api.py</code></span>';
        } finally {
            btn.disabled = false;
        }
    }

    async function analyzeEmail() {
        showLoading();
        hideFeedback();

        try {
            const item = Office.context.mailbox.item;
            if (!item) {
                showError("No email selected.");
                return;
            }

            // Crash-proof property extraction — treat everything as optional
            let subject = "";
            let sender = "";
            
            try { subject = item.subject || ""; } catch(e) {}
            try { sender = item.from ? (item.from.emailAddress || "") : ""; } catch(e) {}
            
            // Get body with timeout safeguard
            const body = await getEmailBody(item);

            lastEmailData = { subject, sender, body, attachment_names: [] };

            console.log("Sending payload to n8n pipeline directly...");

            // Build the payload
            const payload = {
                text: body.substring(0, 3000),
                subject: subject,
                sender: sender,
                receiver: "",
                reply_to: "",
                cc: "",
                use_llm: false
            };

            // Send directly to n8n webhook
            const n8nResponse = await fetch(N8N_WEBHOOK, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!n8nResponse.ok) throw new Error(`n8n webhook returned ${n8nResponse.status}`);

            console.log("n8n pipeline triggered successfully");

            // Also send to local API for analysis results
            const response = await fetch(`${EMAIL_API}/analyze/email`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
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

    async function scanCredentials() {
        const emailText = lastEmailData
            ? lastEmailData.body.substring(0, 5000)
            : "";
        const emailSubject = lastEmailData ? lastEmailData.subject : "";
        const emailSender = lastEmailData ? lastEmailData.sender : "";

        // Allow scanning even without prior email analysis
        // Will scan whatever is in the current email
        if (!emailText && !lastEmailData) {
            // Try to get email body directly
            try {
                const item = Office.context.mailbox.item;
                const body = await getEmailBody(item);
                await runCredentialScan(
                    body,
                    item.subject || "",
                    item.from ? item.from.emailAddress : ""
                );
            } catch (e) {
                document.getElementById("cred-result").innerHTML =
                    '<span style="color:#856404">Open an email first.</span>';
            }
            return;
        }

        await runCredentialScan(emailText, emailSubject, emailSender);
    }

    async function runCredentialScan(text, subject, sender) {
        document.getElementById("cred-result").innerHTML =
            '<span style="color:#666">Scanning for credentials...</span>';
        document.getElementById("btn-cred-scan").disabled = true;

        try {
            const response = await fetch(`${CRED_API}/analyze/email`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text, subject, sender })
            });

            if (!response.ok) throw new Error(`API ${response.status}`);
            const result = await response.json();

            const label = result.risk_label || "Clean";
            const score = result.risk_score || 0;
            const total = result.total_findings || 0;
            const critical = result.critical_count || 0;
            const high = result.high_count || 0;

            const color = label === "Critical" ? "#dc3545" :
                label === "High" ? "#fd7e14" :
                    label === "Medium" ? "#ffc107" :
                        label === "Low" ? "#17a2b8" : "#28a745";

            const findings = (result.findings || []).map(f => `
                <div style="font-size:11px;padding:5px 8px;margin:3px 0;
                            background:#f8f9fa;border-left:3px solid ${color};
                            border-radius:2px">
                    <strong>${f.credential_type.replace(/_/g, ' ')}</strong>
                    — <span style="color:${color}">${f.risk_tier}</span>
                    <span style="color:#aaa">(${Math.round(f.confidence * 100)}%)</span>
                    <div style="font-family:monospace;color:#888;font-size:10px">
                        ${f.redacted_value}
                    </div>
                </div>`).join("");

            const emptyMsg = total === 0
                ? '<div style="color:#28a745;font-size:12px">✅ No credentials exposed</div>'
                : "";

            document.getElementById("cred-result").innerHTML = `
                <div style="background:#f8f9fa;padding:10px;border-radius:6px;
                            border-left:4px solid ${color};margin-top:6px">
                    <div style="font-weight:600;color:${color};font-size:13px">
                        ${label} Risk — ${score}/100
                    </div>
                    <div style="font-size:12px;color:#555;margin:4px 0">
                        ${total} finding(s)
                        ${critical > 0 ? `· <strong style="color:#dc3545">${critical} CRITICAL</strong>` : ""}
                        ${high > 0 ? `· <strong style="color:#fd7e14">${high} HIGH</strong>` : ""}
                    </div>
                    <div style="font-size:11px;color:#666;margin:4px 0">
                        ${result.human_summary || ""}
                    </div>
                    ${emptyMsg}
                    ${findings}
                    <div style="font-size:11px;color:#856404;margin-top:6px;
                                background:#fff3cd;padding:4px 8px;border-radius:4px">
                        ${result.recommended_action || ""}
                    </div>
                </div>`;

        } catch (err) {
            console.error("Credential scan error:", err);
            document.getElementById("cred-result").innerHTML =
                '<span style="color:#dc3545">⚠ Credential Scanner not reachable. ' +
                'Start: cd Credential_Scanner-main && python main.py</span>';
        } finally {
            document.getElementById("btn-cred-scan").disabled = false;
        }
    }

    // ── Voice: start recording ─────────────────────────────────────
    async function startRecording() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            audioChunks = [];
            mediaRecorder = new MediaRecorder(stream, { mimeType: "audio/webm" });

            mediaRecorder.ondataavailable = e => {
                if (e.data.size > 0) audioChunks.push(e.data);
            };

            mediaRecorder.start(100);

            document.getElementById("btn-record").disabled = true;
            document.getElementById("btn-record").style.opacity = "0.5";
            document.getElementById("btn-stop").disabled = false;
            document.getElementById("btn-stop").style.opacity = "1";
            document.getElementById("voice-result").innerHTML =
                '<span style="color:#856404">🔴 Recording... speak now</span>';

        } catch (err) {
            console.error("Mic error:", err);
            document.getElementById("voice-result").innerHTML =
                '<span style="color:#dc3545">⚠ Microphone access denied. ' +
                'Allow microphone in browser settings.</span>';
        }
    }

    // ── Voice: stop and analyze ────────────────────────────────────
    function stopRecording() {
        if (!mediaRecorder || mediaRecorder.state === "inactive") return;

        mediaRecorder.stop();
        mediaRecorder.stream.getTracks().forEach(t => t.stop());

        document.getElementById("btn-record").disabled = false;
        document.getElementById("btn-record").style.opacity = "1";
        document.getElementById("btn-stop").disabled = true;
        document.getElementById("btn-stop").style.opacity = "0.5";
        document.getElementById("voice-result").innerHTML =
            '<span style="color:#666">Analyzing voice...</span>';

        mediaRecorder.onstop = async () => {
            const blob = new Blob(audioChunks, { type: "audio/webm" });
            await analyzeVoiceBlob(blob, "recording.webm");
        };
    }

    // ── Voice: upload audio file ───────────────────────────────────
    async function uploadAudio(event) {
        const file = event.target.files[0];
        if (!file) return;

        document.getElementById("voice-result").innerHTML =
            `<span style="color:#666">Analyzing ${file.name}...</span>`;

        await analyzeVoiceBlob(file, file.name);

        // Reset file input so same file can be re-uploaded
        event.target.value = "";
    }

    // ── Voice: send audio to API ───────────────────────────────────
    async function analyzeVoiceBlob(blob, filename) {
        try {
            const formData = new FormData();
            formData.append("file", blob, filename);

            const response = await fetch(`${VOICE_API}/analyze/voice`, {
                method: "POST",
                body: formData
            });

            if (!response.ok) throw new Error(`Voice API returned ${response.status}`);

            const result = await response.json();
            const score = result.risk_score;
            const verdict = result.verdict;
            const tier = result.tier;
            const deep = result.deep_score;
            const rf = result.rf_score;
            const ms = result.processing_ms;

            const color = score > 85 ? "#dc3545" :
                score > 60 ? "#fd7e14" :
                    score > 30 ? "#ffc107" : "#28a745";

            const indicators = (result.top_indicators || []).slice(0, 3)
                .map(i => `<div style="font-size:11px;color:#666;margin:2px 0">• ${i}</div>`)
                .join("");

            document.getElementById("voice-result").innerHTML = `
                <div style="background:#f8f9fa;padding:10px;border-radius:6px;
                            border-left:4px solid ${color};margin-top:6px">
                    <div style="font-weight:600;color:${color};font-size:13px;margin-bottom:4px">
                        ${verdict} — ${tier} (${score}/100)
                    </div>
                    <div style="font-size:12px;color:#555;margin-bottom:4px">
                        Deep model: ${deep} &nbsp;|&nbsp; RF: ${rf} &nbsp;|&nbsp; ${ms}ms
                    </div>
                    ${indicators}
                </div>`;

        } catch (err) {
            console.error("Voice analysis failed:", err);
            document.getElementById("voice-result").innerHTML =
                '<span style="color:#dc3545">⚠ Voice API not reachable. ' +
                'Start: cd fraudshield-voice/src && python api.py</span>';
        }
    }

    // ── Feedback ───────────────────────────────────────────────────
    async function submitFeedback(userVerdict) {
        if (!lastResult || !lastEmailData) {
            alert("Please analyze an email first.");
            return;
        }

        const btnSafe = document.getElementById("btn-safe");
        const btnPhish = document.getElementById("btn-phish");
        const fbMsg = document.getElementById("feedback-message");

        if (btnSafe) { btnSafe.disabled = true; btnSafe.style.opacity = "0.5"; }
        if (btnPhish) { btnPhish.disabled = true; btnPhish.style.opacity = "0.5"; }
        if (fbMsg) fbMsg.innerHTML = "<em>Saving feedback...</em>";

        try {
            const response = await fetch(`${EMAIL_API}/feedback`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email_text: lastEmailData.body.substring(0, 1000),
                    email_subject: lastEmailData.subject,
                    email_sender: lastEmailData.sender,
                    model_verdict: lastResult.verdict || "",
                    model_score: lastResult.risk_score || 0,
                    user_verdict: userVerdict,
                    prediction_id: lastResult.prediction_id || null
                })
            });

            const result = await response.json();

            if (fbMsg) {
                if (result.was_correct) {
                    fbMsg.innerHTML = `
                        <div style="background:#d4edda;color:#155724;padding:8px;
                                    border-radius:6px;font-size:12px;text-align:center">
                            ✅ Confirmed — model was correct. Saved to PostgreSQL.
                        </div>`;
                } else {
                    fbMsg.innerHTML = `
                        <div style="background:#fff3cd;color:#856404;padding:8px;
                                    border-radius:6px;font-size:12px;text-align:center">
                            📝 Correction saved — queued for retraining.<br>
                            <small>Model: <strong>${result.model_said}</strong>
                            → You: <strong>${result.user_said}</strong></small>
                        </div>`;
                }
            }

        } catch (err) {
            console.error("Feedback error:", err);
            if (btnSafe) { btnSafe.disabled = false; btnSafe.style.opacity = "1"; }
            if (btnPhish) { btnPhish.disabled = false; btnPhish.style.opacity = "1"; }
            if (fbMsg) fbMsg.innerHTML =
                '<span style="color:#dc3545">Failed to save feedback.</span>';
        }
    }

    // ── Display helpers ────────────────────────────────────────────
    function buildDisplayResult(data) {
        const tier = data.tier || "LOW";
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
                safe: ruleIndicators.length === 0
            }
        };

        if (data.header_flags && data.header_flags.length > 0) {
            findings["Email Header Analysis"] = {
                issues: data.header_flags,
                safe: false
            };
        }

        return {
            risk_score: score,
            risk_level: tier,
            findings: findings,
            recommendations: getRecommendations(tier, data.outlook_action),
            explanations: {
                "Risk Score": `${data.risk_score}/100 — ${tier}`,
                "Action": data.outlook_action || "ALLOW",
                "RoBERTa Score": `${pct(data.roberta_phishing_prob)} phishing probability`,
                "Rule Score": `${data.rule_based_score || 0}% pattern-based`,
                "AI Detection": `${pct(data.ai_generated_probability)} AI-written`,
                "Processing Time": `${data.processing_ms}ms`
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
                div.innerHTML = `<h4>${category}</h4><ul>${details.issues.map(i => `<li class="issue">⚠ ${i}</li>`).join("")
                    }</ul>`;
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
        if (fb) {
            fb.style.display = "block";
            const btnSafe = document.getElementById("btn-safe");
            const btnPhish = document.getElementById("btn-phish");
            const fbMsg = document.getElementById("feedback-message");
            if (btnSafe) { btnSafe.disabled = false; btnSafe.style.opacity = "1"; }
            if (btnPhish) { btnPhish.disabled = false; btnPhish.style.opacity = "1"; }
            if (fbMsg) fbMsg.innerHTML = "";
        }
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
        return new Promise((resolve) => {
            // Timeout after 10s — if Outlook never fires the callback, proceed with empty string
            const timeout = setTimeout(() => {
                console.warn("[FraudShield] getEmailBody timed out — proceeding with empty body");
                resolve("");
            }, 10000);

            if (item.body) {
                item.body.getAsync(Office.CoercionType.Text, function (r) {
                    clearTimeout(timeout);
                    resolve(r.status === Office.AsyncResultStatus.Succeeded
                        ? r.value || "" : "");
                });
            } else {
                clearTimeout(timeout);
                resolve("");
            }
        });
    }

    function showLoading() {
        document.getElementById("loading").style.display = "block";
        document.getElementById("results").style.display = "none";
        document.getElementById("error").style.display = "none";
    }

    function hideLoading() {
        document.getElementById("loading").style.display = "none";
    }

    function showError(msg) {
        document.getElementById("error").innerHTML = msg;
        document.getElementById("error").style.display = "block";
        document.getElementById("loading").style.display = "none";
    }

    function pct(val) {
        return `${Math.round((val || 0) * 100)}%`;
    }

})();
