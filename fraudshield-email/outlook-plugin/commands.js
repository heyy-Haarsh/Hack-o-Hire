// outlook-plugin/commands.js
// FraudShield AI — Scan Before Send handler

const CRED_API_URL    = "https://localhost:3000/credential/analyze/email";
const BLOCK_THRESHOLD = 70;
const WARN_THRESHOLD  = 30;
const NOTIF_KEY       = "fraudshield_scan_result";

// ── Helper: show notification (add or replace) ────────────────────
function showNotif(item, type, message, persistent, callback) {
    // Try replaceAsync first — if key doesn't exist, fall back to addAsync
    item.notificationMessages.replaceAsync(
        NOTIF_KEY,
        { type, message, icon: "Icon.16x16", persistent: !!persistent },
        function(result) {
            if (result.error) {
                // Key didn't exist — add instead
                item.notificationMessages.addAsync(
                    NOTIF_KEY,
                    { type, message, icon: "Icon.16x16", persistent: !!persistent },
                    callback
                );
            } else if (callback) {
                callback(result);
            }
        }
    );
}

// ── Manual scan — fires when "Scan Before Send" is clicked ────────
function manualScanHandler(event) {
    const item = Office.context.mailbox.item;
    const MSG  = Office.MailboxEnums.ItemNotificationMessageType;

    item.body.getAsync(Office.CoercionType.Text, function(bodyResult) {
        const body    = (bodyResult.value || "").trim();
        const subject = item.subject || "";

        if (!body) {
            showNotif(item, MSG.InformationalMessage,
                "FraudShield: Email body is empty — nothing to scan.",
                false, function() { event.completed(); });
            return;
        }

        try {
            const xhr = new XMLHttpRequest();
            xhr.open("POST", CRED_API_URL, false); // synchronous required
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(JSON.stringify({
                text:    body.substring(0, 5000),
                subject: subject,
                sender:  ""
            }));

            if (xhr.status !== 200) {
                showNotif(item, MSG.ErrorMessage,
                    "FraudShield: Credential Scanner not reachable. " +
                    "Start: cd Credential_Scanner-main && python main.py",
                    true, function() { event.completed(); });
                return;
            }

            const result   = JSON.parse(xhr.responseText);
            const score    = result.risk_score     || 0;
            const label    = result.risk_label     || "Clean";
            const total    = result.total_findings  || 0;
            const critical = result.critical_count  || 0;
            const high     = result.high_count      || 0;

            let type, message, persistent;

            if (score >= BLOCK_THRESHOLD) {
                type      = MSG.ErrorMessage;
                persistent = true;
                message   =
                    "\u26A0 FraudShield BLOCKED (" + score + "/100 \u2014 " + label + "): " +
                    total + " credential(s) detected" +
                    (critical > 0 ? ", " + critical + " CRITICAL" : "") +
                    (high     > 0 ? ", " + high     + " HIGH"     : "") +
                    ". DO NOT SEND. Remove sensitive data first. " +
                    (result.recommended_action || "");

            } else if (score >= WARN_THRESHOLD) {
                type      = MSG.InformationalMessage;
                persistent = true;
                message   =
                    "\u26A0 FraudShield Warning (" + score + "/100): " +
                    total + " possible credential(s) detected. " +
                    "Review carefully before sending.";

            } else {
                type      = MSG.InformationalMessage;
                persistent = true;
                message   =
                    "\u2705 FraudShield: CLEAN (" + score + "/100) \u2014 " +
                    "No credentials detected. Safe to send.";
            }

            showNotif(item, type, message, persistent,
                function() { event.completed(); });

        } catch(e) {
            showNotif(item, MSG.ErrorMessage,
                "FraudShield: Scanner error \u2014 " + e.message,
                true, function() { event.completed(); });
        }
    });
}

// ── onSendHandler — placeholder (ItemSend disabled in Outlook Web) ─
function onSendHandler(event) {
    event.completed({ allowEvent: true });
}

// ── Register ──────────────────────────────────────────────────────
Office.onReady(function() {
    Office.actions.associate("onSendHandler",     onSendHandler);
    Office.actions.associate("manualScanHandler", manualScanHandler);
});
