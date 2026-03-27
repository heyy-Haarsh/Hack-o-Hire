// credential-pane.js — FraudShield Credential Leak Scanner
// Standalone read-pane: auto-fetches current email and scans for exposed secrets

(function () {

    const CRED_API = "https://localhost:3000/credential";

    Office.onReady(function (info) {
        if (info.host === Office.HostType.Outlook) {
            document.getElementById("btn-scan").addEventListener("click", scanCurrentEmail);
        }
    });

    // ── Scan the currently open email ─────────────────────────────
    async function scanCurrentEmail() {
        const btn     = document.getElementById("btn-scan");
        const loading = document.getElementById("loading-bar");

        btn.disabled        = true;
        loading.style.display = "block";
        document.getElementById("cred-result").innerHTML = "";

        try {
            const item    = Office.context.mailbox.item;
            const body    = await getEmailBody(item);
            let   subject = "";
            let   sender  = "";
            try { subject = item.subject || ""; } catch (e) {}
            try { sender  = item.from ? (item.from.emailAddress || "") : ""; } catch (e) {}

            await runCredentialScan(body, subject, sender);

        } catch (e) {
            console.error("Credential scan error:", e);
            document.getElementById("cred-result").innerHTML =
                '<span style="color:#856404">⚠ Could not read email. Please open an email first.</span>';
        } finally {
            btn.disabled        = false;
            loading.style.display = "none";
        }
    }

    // ── Core scan logic ────────────────────────────────────────────
    async function runCredentialScan(text, subject, sender) {
        const resultEl = document.getElementById("cred-result");
        resultEl.innerHTML = '<span style="color:#666">Scanning for credentials...</span>';

        try {
            const response = await fetch(`${CRED_API}/analyze/email`, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body:    JSON.stringify({
                    text:    text.substring(0, 5000),
                    subject: subject,
                    sender:  sender
                })
            });

            if (!response.ok) throw new Error(`API ${response.status}`);
            const result = await response.json();

            const label    = result.risk_label     || "Clean";
            const score    = result.risk_score      || 0;
            const total    = result.total_findings  || 0;
            const critical = result.critical_count  || 0;
            const high     = result.high_count      || 0;

            const color = label === "Critical" ? "#dc3545" :
                          label === "High"     ? "#fd7e14" :
                          label === "Medium"   ? "#ffc107" :
                          label === "Low"      ? "#17a2b8" : "#28a745";

            const findings = (result.findings || []).map(f => `
                <div style="font-size:11px;padding:5px 8px;margin:3px 0;
                            background:#f8f9fa;border-left:3px solid ${color};border-radius:2px">
                    <strong>${f.credential_type.replace(/_/g, " ")}</strong>
                    — <span style="color:${color}">${f.risk_tier}</span>
                    <span style="color:#aaa">(${Math.round(f.confidence * 100)}%)</span>
                    <div style="font-family:monospace;color:#888;font-size:10px">${f.redacted_value}</div>
                </div>`).join("");

            const emptyMsg = total === 0
                ? '<div style="color:#28a745;font-size:12px;margin-top:6px">✅ No credentials exposed</div>'
                : "";

            resultEl.innerHTML = `
                <div style="background:#f8f9fa;padding:10px;border-radius:6px;
                            border-left:4px solid ${color};margin-top:4px">
                    <div style="font-weight:600;color:${color};font-size:13px">
                        ${label} Risk — ${score}/100
                    </div>
                    <div style="font-size:12px;color:#555;margin:4px 0">
                        ${total} finding(s)
                        ${critical > 0 ? `· <strong style="color:#dc3545">${critical} CRITICAL</strong>` : ""}
                        ${high     > 0 ? `· <strong style="color:#fd7e14">${high} HIGH</strong>`     : ""}
                    </div>
                    <div style="font-size:11px;color:#666;margin:4px 0">${result.human_summary || ""}</div>
                    ${emptyMsg}
                    ${findings}
                    ${result.recommended_action ? `
                    <div style="font-size:11px;color:#856404;margin-top:6px;
                                background:#fff3cd;padding:4px 8px;border-radius:4px">
                        ${result.recommended_action}
                    </div>` : ""}
                </div>`;

        } catch (err) {
            console.error("Credential scan failed:", err);
            document.getElementById("cred-result").innerHTML =
                '<span style="color:#dc3545">⚠ Credential Scanner not reachable. ' +
                'Start: <code>cd Credential_Scanner-main &amp;&amp; python main.py</code></span>';
        }
    }

    // ── Get email body ─────────────────────────────────────────────
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

})();
