// guard-pane.js — FraudShield Prompt Injection Guard
// Standalone pane: 4-layer prompt injection detection with email auto-fill

(function () {

    const GUARD_API = "https://localhost:3000/guard";

    Office.onReady(function (info) {
        if (info.host === Office.HostType.Outlook) {
            document.getElementById("btn-guard-scan").addEventListener("click", scanPromptGuard);
            document.getElementById("btn-guard-autofill").addEventListener("click", autofillFromEmail);
        }
    });

    // ── Auto-fill textarea from current email body ─────────────────
    async function autofillFromEmail() {
        try {
            const item = Office.context.mailbox.item;
            const body = await getEmailBody(item);
            document.getElementById("guard-prompt").value = body.substring(0, 1500);
        } catch (e) {
            document.getElementById("guard-prompt").value = "";
        }
    }

    // ── Run prompt injection scan ──────────────────────────────────
    async function scanPromptGuard() {
        const prompt   = (document.getElementById("guard-prompt").value || "").trim();
        const resultEl = document.getElementById("guard-result");
        const btn      = document.getElementById("btn-guard-scan");

        if (!prompt) {
            resultEl.innerHTML = '<span style="color:#856404">Enter a prompt to scan first.</span>';
            return;
        }

        btn.disabled        = true;
        resultEl.innerHTML  = '<span style="color:#666">Scanning…</span>';

        try {
            const response = await fetch(`${GUARD_API}/check`, {
                method:  "POST",
                headers: { "Content-Type": "application/json" },
                body:    JSON.stringify({
                    prompt:     prompt,
                    context:    "email",
                    session_id: "plugin_" + Date.now()
                })
            });

            if (!response.ok) throw new Error(`Guard API returned ${response.status}`);
            const r = await response.json();

            const verdict   = r.verdict           || "CLEAN";
            const score     = r.injection_score   || 0;
            const block     = r.block              || false;
            const layer     = r.dominant_layer     || "none";
            const summary   = r.human_summary      || "";
            const sanitized = r.sanitized_prompt   || null;

            const schemeMap = {
                CRITICAL:   { bg: "#dc3545" },
                INJECTION:  { bg: "#fd7e14" },
                SUSPICIOUS: { bg: "#ffc107" },
                CLEAN:      { bg: "#28a745" }
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
                       <span style="color:#555">${sanitized.substring(0, 120)}${sanitized.length > 120 ? "…" : ""}</span>
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
                        <div style="width:${score}%;height:100%;background:${sc.bg};border-radius:3px"></div>
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
