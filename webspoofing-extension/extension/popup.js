/**
 * popup.js – PhishGuard v3
 *
 * KEY FIX: Reads from chrome.storage.local DIRECTLY.
 * NO message passing for data reads → eliminates "port closed" error.
 * Only uses sendMessage for TRIGGER_ANALYZE (fire-and-forget, no response needed).
 */

document.addEventListener("DOMContentLoaded", init);

function init() {
    loadAndRender();

    document.getElementById("rescan-btn").addEventListener("click", () => {
        showScanning();
        // Fire-and-forget — no response callback needed = no port error
        chrome.runtime.sendMessage({ type: "TRIGGER_ANALYZE" }).catch(() => {});
        // Poll storage every 500ms for up to 15s waiting for fresh result
        pollForResult(15000);
    });

    document.getElementById("open-dash-btn").addEventListener("click", () => {
        chrome.tabs.create({ url: "http://localhost:5000" });
    });
}

// ── Load from chrome.storage.local (no message port) ─────────────────────────
async function loadAndRender() {
    const tab = await getActiveTab();
    if (!tab) { renderError("Cannot get active tab."); return; }

    chrome.storage.local.get([`tab_${tab.id}`], result => {
        const data = result[`tab_${tab.id}`];
        if (data) {
            render(data, tab.url);
        } else {
            // No data yet — trigger analysis and poll
            showScanning();
            chrome.runtime.sendMessage({ type: "TRIGGER_ANALYZE" }).catch(() => {});
            pollForResult(20000, tab.id);
        }
    });
}

// ── Poll storage until result appears ────────────────────────────────────────
async function pollForResult(timeoutMs, knownTabId) {
    const start = Date.now();
    const INTERVAL = 600;

    const tab = knownTabId
        ? { id: knownTabId }
        : await getActiveTab();

    if (!tab) { renderError("Cannot get active tab."); return; }

    const poll = setInterval(() => {
        chrome.storage.local.get([`tab_${tab.id}`], result => {
            const data = result[`tab_${tab.id}`];
            if (data) {
                // Only accept if timestamp is fresh (within last 20s)
                if (Date.now() - data.timestamp < 20000) {
                    clearInterval(poll);
                    chrome.tabs.get(tab.id, t => {
                        render(data, t?.url || data.url || "");
                    });
                    return;
                }
            }
            if (Date.now() - start > timeoutMs) {
                clearInterval(poll);
                renderError("Analysis timed out. Is the Flask server running on port 5000?");
            }
        });
    }, INTERVAL);
}

// ── Helper: get active tab ────────────────────────────────────────────────────
function getActiveTab() {
    return new Promise(resolve => {
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            resolve(tabs[0] || null);
        });
    });
}

// ── UI states ─────────────────────────────────────────────────────────────────
function showScanning() {
    const main = document.getElementById("main-content");
    main.innerHTML = `
        <div class="scanning-wrap">
            <div class="spinner"></div>
            <p class="scan-text">Scanning page…</p>
            <p class="scan-sub">Collecting cookies + URL data</p>
        </div>`;
}

function renderError(msg) {
    const main = document.getElementById("main-content");
    main.innerHTML = `<div class="error-box">${msg}</div>`;
}

// ── Main render ───────────────────────────────────────────────────────────────
function render(data, tabUrl) {
    const verdict = (data.verdict || "SAFE").toUpperCase();
    const score   = Math.round((data.risk_score || 0) * 100);
    const ml      = data.ml      || {};
    const ck      = data.cookies || {};
    const enc     = data.encoding || {};

    const cls   = verdict === "DANGEROUS" ? "danger" : verdict === "SUSPICIOUS" ? "warn" : "safe";
    const icon  = verdict === "DANGEROUS" ? "🚨" : verdict === "SUSPICIOUS" ? "⚠️" : "✅";
    const label = verdict === "DANGEROUS" ? "Phishing Risk" : verdict === "SUSPICIOUS" ? "Suspicious" : "Safe";

    let hostname = tabUrl || data.url || "—";
    try { hostname = new URL(hostname).hostname; } catch {}

    // Bar color
    const barColor = verdict === "DANGEROUS" ? "#ef4444" : verdict === "SUSPICIOUS" ? "#f59e0b" : "#10b981";

    const reasons = data.reasons || [];

    const main = document.getElementById("main-content");
    main.innerHTML = `
        <!-- Verdict row -->
        <div class="verdict-row verdict-${cls}">
            <span class="verdict-icon">${icon}</span>
            <div class="verdict-text">
                <div class="verdict-label">${label}</div>
                <div class="verdict-host">${esc(hostname)}</div>
            </div>
            <div class="verdict-score">${score}%</div>
        </div>

        <!-- Score bar -->
        <div class="score-track">
            <div class="score-fill" style="width:${score}%;background:${barColor}"></div>
        </div>

        <!-- Stats grid -->
        <div class="stats-grid">
            <div class="stat-cell">
                <div class="stat-val ${mlColor(ml.label)}">${mlShort(ml.label)}</div>
                <div class="stat-key">AI Model</div>
            </div>
            <div class="stat-cell">
                <div class="stat-val">${ck.total || 0}</div>
                <div class="stat-key">Cookies</div>
            </div>
            <div class="stat-cell">
                <div class="stat-val ${ck.insecureCount > 0 ? 'col-danger' : 'col-safe'}">${ck.insecureCount || 0}</div>
                <div class="stat-key">Insecure</div>
            </div>
            <div class="stat-cell">
                <div class="stat-val ${ck.noHttpOnly > 0 ? 'col-warn' : 'col-safe'}">${ck.noHttpOnly || 0}</div>
                <div class="stat-key">No HttpOnly</div>
            </div>
        </div>

        <!-- Reasons -->
        ${reasons.length > 0 ? `
        <div class="section-head">Risk Signals</div>
        <div class="reasons-list">
            ${reasons.slice(0, 4).map(r => `<div class="reason-row">● ${esc(r)}</div>`).join('')}
        </div>` : `<div class="all-clear">✅ No significant risk signals detected</div>`}

        <!-- Cookie issues -->
        ${ck.issues?.length > 0 ? `
        <div class="section-head">Cookie Issues</div>
        <div class="issues-list">
            ${ck.issues.slice(0, 4).map(i => `<div class="issue-row">🍪 ${esc(i)}</div>`).join('')}
        </div>` : ''}

        <!-- ML summary -->
        ${ml.summary ? `
        <div class="section-head">AI Summary</div>
        <div class="ml-summary">${esc(ml.summary)}</div>` : ''}

        <!-- Source + time -->
        <div class="footer-row">
            <span>${data.source === 'backend' ? '🔗 Backend API' : '⚡ Local Analysis'}</span>
            <span>${formatAge(data.timestamp)}</span>
        </div>
    `;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function mlShort(label) {
    if (label === "phishing")   return "Phish";
    if (label === "suspicious") return "Susp.";
    return "Clean";
}

function mlColor(label) {
    if (label === "phishing")   return "col-danger";
    if (label === "suspicious") return "col-warn";
    return "col-safe";
}

function formatAge(ts) {
    if (!ts) return "";
    const s = Math.round((Date.now() - ts) / 1000);
    return s < 60 ? `${s}s ago` : `${Math.round(s / 60)}m ago`;
}

function esc(s) {
    return String(s || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}
