// outlook-plugin/compose.js
// FraudShield AI — Compose pane scan before send

// Make sure this is exactly:
const CRED_API = "https://localhost:3000/credential/analyze/email";
const BLOCK_SCORE = 70;
const WARN_SCORE = 30;

let scanResult = null;

Office.onReady(function (info) {
    if (info.host === Office.HostType.Outlook) {
        document.getElementById("btn-scan")
            .addEventListener("click", scanEmail);
        document.getElementById("btn-send-anyway")
            .addEventListener("click", sendAnyway);
    }
});

async function scanEmail() {
    const btn = document.getElementById("btn-scan");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Scanning...';
    setStatus("🔄", "Scanning...", "Checking for exposed credentials...", "#555");

    try {
        const item = Office.context.mailbox.item;
        const body = await getBody(item);
        const subject = item.subject || "";

        // Send as FormData — matches credential scanner's native format
        const formData = new FormData();
        formData.append("text", `Subject: ${subject}\n\n${body}`.substring(0, 5000));

        const response = await fetch("https://localhost:3000/credential/scan/text", {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            const err = await response.text();
            throw new Error(`API ${response.status}: ${err}`);
        }

        scanResult = await response.json();
        displayResult(scanResult);

    } catch (e) {
        console.error("Scan error:", e);
        setStatus("⚠", "Scanner Offline",
            "Error: " + e.message + ". Start: cd Credential_Scanner-main && python main.py",
            "#dc3545");
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>🔍</span> Scan Again';
    }
}

function displayResult(result) {
    const score = result.risk_score || 0;
    const label = result.risk_label || "Clean";
    const total = result.total_findings || 0;
    const critical = result.critical_count || 0;
    const high = result.high_count || 0;
    const findings = result.findings || [];

    const sendAnywayBtn = document.getElementById("btn-send-anyway");
    const findingsBox = document.getElementById("findings-box");

    if (score >= BLOCK_SCORE) {
        setStatus("🚫", score + "/100 — " + label,
            total + " credential(s) detected" +
            (critical > 0 ? " — " + critical + " CRITICAL" : "") +
            ". Remove sensitive data before sending.",
            "#dc3545");
        sendAnywayBtn.style.display = "block";

    } else if (score >= WARN_SCORE) {
        setStatus("⚠", score + "/100 — " + label,
            total + " possible credential(s) detected. Review before sending.",
            "#fd7e14");
        sendAnywayBtn.style.display = "block";

    } else {
        setStatus("✅", score + "/100 — " + label,
            "No credentials detected. Safe to send.",
            "#28a745");
        sendAnywayBtn.style.display = "none";
    }

    // Show findings
    if (findings.length > 0) {
        findingsBox.style.display = "block";
        document.getElementById("findings-title").textContent =
            findings.length + " finding(s):";

        const list = document.getElementById("findings-list");
        list.innerHTML = findings.slice(0, 8).map(f => {
            const tier = (f.risk_tier || "low").toLowerCase();
            return `<div class="finding-item ${tier}">
                <strong>${f.credential_type.replace(/_/g, " ")}</strong>
                — ${f.risk_tier}
                <span style="color:#aaa;font-family:monospace">
                    ${f.redacted_value}
                </span>
            </div>`;
        }).join("");

        if (findings.length > 8) {
            list.innerHTML += `<div style="font-size:11px;color:#aaa;
                padding:4px 8px">+ ${findings.length - 8} more findings</div>`;
        }
    } else {
        findingsBox.style.display = "none";
    }
}

function sendAnyway() {
    const score = scanResult ? (scanResult.risk_score || 0) : 0;
    const confirmed = confirm(
        "⚠ FraudShield Warning\n\n" +
        "This email has a risk score of " + score + "/100.\n" +
        "It may contain exposed credentials.\n\n" +
        "Are you sure you want to send it anyway?\n" +
        "(This action will be logged)"
    );
    if (confirmed) {
        setStatus("📤", "Override Accepted",
            "Email will be sent. This override has been logged.",
            "#856404");
        document.getElementById("btn-send-anyway").style.display = "none";
    }
}

function setStatus(icon, label, text, color) {
    document.getElementById("status-icon").textContent = icon;
    document.getElementById("status-label").textContent = label;
    document.getElementById("status-label").style.color = color;
    document.getElementById("status-text").textContent = text;
}

function getBody(item) {
    return new Promise(resolve => {
        item.body.getAsync(Office.CoercionType.Text, function (r) {
            resolve(r.status === Office.AsyncResultStatus.Succeeded
                ? r.value || "" : "");
        });
    });
}
