/**
 * background.js – PhishGuard v3
 *
 * FIXED FLOW:
 *   1. Tab loads → grab URL + real browser cookies
 *   2. POST both to Flask /analyze/fast
 *   3. Save result to chrome.storage.local (keyed by tabId)
 *   4. Popup reads from storage directly — NO message-port issue!
 *
 * KEY FIX for "message port closed" error:
 *   → Popup NO LONGER waits for a response from background.
 *   → All data flows through chrome.storage.local (reliable, no async port issues).
 */

const API_FAST   = "http://127.0.0.1:5000/analyze/fast";
const API_FULL   = "http://127.0.0.1:5000/analyze";
const CACHE_TTL  = 5 * 60 * 1000; // 5 minutes

// ── Skip internal Chrome pages ────────────────────────────────────────────────
const SKIP = ["chrome://", "chrome-extension://", "edge://", "about:", "data:", "moz-extension://"];
function shouldSkip(url) {
    return !url || SKIP.some(p => url.startsWith(p));
}

// ── Get real browser cookies for a URL ────────────────────────────────────────
function getCookies(url) {
    return new Promise(resolve => {
        chrome.cookies.getAll({ url }, cookies => {
            resolve((cookies || []).map(c => ({
                name:           c.name,
                value:          c.value,
                secure:         c.secure,
                httpOnly:       c.httpOnly,       // real value from browser
                sameSite:       c.sameSite || "unspecified",
                expirationDate: c.expirationDate || null,
                session:        !c.expirationDate, // true = session cookie
                domain:         c.domain
            })));
        });
    });
}

// ── Read cached result for a tab ──────────────────────────────────────────────
async function getCached(tabId) {
    return new Promise(resolve => {
        chrome.storage.local.get([`tab_${tabId}`], result => {
            const entry = result[`tab_${tabId}`];
            if (entry && (Date.now() - entry.timestamp) < CACHE_TTL) {
                resolve(entry);
            } else {
                resolve(null);
            }
        });
    });
}

// ── Save result to storage ────────────────────────────────────────────────────
async function saveResult(tabId, data) {
    const key = `tab_${tabId}`;
    return new Promise(resolve => {
        chrome.storage.local.set({ [key]: data }, resolve);
    });
}

// ── Main: analyze a tab ───────────────────────────────────────────────────────
async function analyzeTab(tabId, url, force = false) {
    if (shouldSkip(url)) {
        const skipResult = {
            url: url || "New Tab", verdict: "SAFE", risk_score: 0, source: "system",
            topReason: "System or internal browser page", reasons: ["System extension/browser page (not scannable)"],
            ml: { label: "legitimate", probability: 0, summary: "Not applicable for system pages." },
            cookies: { total: 0 }, encoding: {},
            tabId, timestamp: Date.now()
        };
        await saveResult(tabId, skipResult);
        updateBadge(tabId, "SAFE", 0);
        return;
    }

    // Use cache unless forced
    if (!force) {
        const cached = await getCached(tabId);
        if (cached) {
            updateBadge(tabId, cached.verdict, cached.risk_score);
            return;
        }
    }

    // Update badge to scanning state
    chrome.action.setBadgeText({ text: "...", tabId }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color: "#6b7280", tabId }).catch(() => {});

    // 1. Collect real browser cookies
    const cookies = await getCookies(url);

    // 2. Hit backend
    let result = null;
    try {
        const resp = await fetch(API_FAST, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, cookies }),
            signal: AbortSignal.timeout(10000)
        });

        if (resp.ok) {
            const raw = await resp.json();
            result = buildResult(url, cookies, raw, "backend");
        }
    } catch (err) {
        console.warn("PhishGuard backend unreachable:", err.message);
    }

    // 3. Local fallback if backend is down
    if (!result) {
        result = localAnalyze(url, cookies);
    }

    // 4. Save to storage (popup will read from here)
    result.tabId    = tabId;
    result.timestamp = Date.now();
    await saveResult(tabId, result);

    // 5. Update badge
    updateBadge(tabId, result.verdict, result.risk_score);

    // 6. Notify if dangerous
    if (result.verdict === "DANGEROUS") {
        showNotification(url, result.topReason || "High phishing risk detected");
    }
}

// ── Parse backend /analyze/fast response ─────────────────────────────────────
function buildResult(url, cookies, raw, source) {
    const ml      = raw.details?.ml_model  || {};
    const ck      = raw.details?.cookies   || {};
    const enc     = raw.details?.encoding  || {};

    // Compute real cookie stats from the browser cookies we sent
    const cookieStats = analyzeCookiesLocally(url, cookies);

    const reasons = [];
    if (ml.label === "phishing")      reasons.push("AI model: phishing pattern detected");
    if (ml.label === "suspicious")    reasons.push("AI model: URL looks suspicious");
    if (cookieStats.insecureCount > 0) reasons.push(`${cookieStats.insecureCount} cookie(s) missing Secure flag`);
    if (cookieStats.noHttpOnly > 0)   reasons.push(`${cookieStats.noHttpOnly} session cookie(s) missing HttpOnly`);
    if (enc.is_double_encoded)        reasons.push("Double URL-encoding detected (obfuscation)");

    // Merge ML risk factors
    if (ml.risk_factors?.length) reasons.push(...ml.risk_factors.slice(0, 2));

    return {
        url,
        verdict:    raw.verdict  || "SAFE",
        risk_score: raw.risk_score || 0,
        source,
        topReason:  reasons[0] || "",
        reasons,
        ml: {
            label:       ml.label      || "legitimate",
            probability: ml.probability || 0,
            risk_factors:  ml.risk_factors  || [],
            safe_factors:  ml.safe_factors  || [],
            summary:     ml.summary    || ""
        },
        cookies: {
            total:          cookies.length,
            insecureCount:  cookieStats.insecureCount,
            noHttpOnly:     cookieStats.noHttpOnly,
            sessionCookies: cookieStats.sessionCookies,
            issues:         cookieStats.issues,
            anomalyScore:   ck.anomaly_score || cookieStats.anomalyScore
        },
        encoding: {
            isEncoded:       enc.is_encoded       || false,
            isDoubleEncoded: enc.is_double_encoded || false,
            issues:          enc.issues            || []
        }
    };
}

// ── Local cookie analysis (real browser cookie data) ─────────────────────────
function analyzeCookiesLocally(url, cookies) {
    const isHttps = url.startsWith("https://");
    const issues  = [];
    let insecureCount = 0, noHttpOnly = 0, sessionCookies = 0;

    cookies.forEach(c => {
        const name = (c.name || "").toLowerCase();
        const isSess = c.session || ["session","auth","token","sid","_id","jwt","csrf"].some(k => name.includes(k));
        if (isSess) sessionCookies++;

        if (isHttps && !c.secure) {
            insecureCount++;
            issues.push(`"${c.name}" missing Secure flag`);
        }
        if (isSess && !c.httpOnly) {
            noHttpOnly++;
            issues.push(`"${c.name}" session cookie missing HttpOnly`);
        }
        if ((c.value || "").startsWith("eyJ") && (c.value || "").length > 30) {
            issues.push(`"${c.name}" JWT token exposed in cookie`);
        }
    });

    const anomalyScore = Math.min((insecureCount * 0.3 + noHttpOnly * 0.35), 1.0);
    return { insecureCount, noHttpOnly, sessionCookies, issues, anomalyScore };
}

// ── Local URL heuristics (fallback) ──────────────────────────────────────────
const TRUSTED = new Set([
    "google.com","youtube.com","wikipedia.org","microsoft.com","apple.com",
    "facebook.com","amazon.com","netflix.com","paypal.com","ebay.com",
    "github.com","linkedin.com","twitter.com","instagram.com","barclays.co.uk",
    "barclays.com","live.com","outlook.com","yahoo.com","bbc.co.uk","bbc.com",
    "office.com","windows.com"
]);

function getRootDomain(hostname) {
    const parts = hostname.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
}

function localAnalyze(url, cookies) {
    try {
        const parsed   = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        const root     = getRootDomain(hostname);

        if (TRUSTED.has(root)) {
            const cookieStats = analyzeCookiesLocally(url, cookies);
            return {
                url, verdict: "SAFE", risk_score: 0.02, source: "local_whitelist",
                topReason: "", reasons: [],
                ml: { label: "legitimate", probability: 2, risk_factors: [], safe_factors: ["Trusted domain"], summary: `${hostname} is a verified trusted domain.` },
                cookies: { total: cookies.length, ...cookieStats },
                encoding: { isEncoded: false, isDoubleEncoded: false, issues: [] }
            };
        }

        let score = 0; const reasons = [];
        if (parsed.protocol !== "https:") { score += 0.15; reasons.push("No HTTPS encryption"); }
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) { score += 0.40; reasons.push("IP address used as domain"); }
        const PHISH_KEYS = ["login","secure","verify","update","confirm","account","banking","paypal","signin","password","credential","suspended","urgent","invoice"];
        const found = PHISH_KEYS.filter(k => url.toLowerCase().includes(k));
        if (found.length) { score += Math.min(found.length * 0.12, 0.35); reasons.push(`Suspicious keywords: ${found.slice(0,3).join(", ")}`); }
        if ([".tk",".ml",".ga",".cf",".gq",".xyz",".top"].some(t => hostname.endsWith(t))) { score += 0.30; reasons.push("High-risk TLD"); }
        if (hostname.split(".").length > 4) { score += 0.20; reasons.push("Excessive subdomains"); }
        if (url.includes("@")) { score += 0.40; reasons.push("@ symbol in URL"); }
        if (url.length > 100) { score += 0.10; reasons.push("Excessively long URL"); }
        ["paypal","google","microsoft","apple","amazon","barclays"].forEach(brand => {
            if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.co.uk`)) {
                score += 0.25; reasons.push(`Brand mimicry: "${brand}"`);
            }
        });

        const cookieStats = analyzeCookiesLocally(url, cookies);
        score = Math.min(score + cookieStats.anomalyScore * 0.3, 1.0);

        const verdict = score >= 0.60 ? "DANGEROUS" : score >= 0.30 ? "SUSPICIOUS" : "SAFE";
        return {
            url, verdict, risk_score: Math.round(score * 1000) / 1000, source: "local_heuristics",
            topReason: reasons[0] || "", reasons,
            ml: { label: verdict === "DANGEROUS" ? "phishing" : "legitimate", probability: Math.round(score * 100), risk_factors: reasons.slice(0,3), safe_factors: [], summary: `Local heuristics: ${verdict}. ${reasons.length} signals found.` },
            cookies: { total: cookies.length, ...cookieStats },
            encoding: { isEncoded: false, isDoubleEncoded: false, issues: [] }
        };
    } catch {
        return {
            url, verdict: "SUSPICIOUS", risk_score: 0.5, source: "local_heuristics",
            topReason: "URL parsing error", reasons: ["URL parsing error"],
            ml: { label: "suspicious", probability: 50, risk_factors: [], safe_factors: [], summary: "Could not parse URL." },
            cookies: { total: 0, insecureCount: 0, noHttpOnly: 0, sessionCookies: 0, issues: [], anomalyScore: 0 },
            encoding: { isEncoded: false, isDoubleEncoded: false, issues: [] }
        };
    }
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function updateBadge(tabId, verdict, score) {
    const MAP = {
        DANGEROUS:  { color: "#ef4444", text: "RISK" },
        SUSPICIOUS: { color: "#f59e0b", text: "WARN" },
        SAFE:       { color: "#10b981", text: "SAFE" }
    };
    const cfg = MAP[verdict] || MAP.SAFE;
    chrome.action.setBadgeBackgroundColor({ color: cfg.color, tabId }).catch(() => {});
    chrome.action.setBadgeText({ text: cfg.text, tabId }).catch(() => {});
    chrome.action.setBadgeTextColor({ color: "#ffffff", tabId }).catch(() => {});
}

// ── Notification ──────────────────────────────────────────────────────────────
function showNotification(url, reason) {
    let host = url;
    try { host = new URL(url).hostname; } catch {}
    chrome.notifications.create(`pg-${Date.now()}`, {
        type: "basic", iconUrl: "logo.png",
        title: "⚠️ PhishGuard: Risk Detected!",
        message: `${host}\n${reason}`,
        priority: 2
    });
}

// ── Event Listeners ───────────────────────────────────────────────────────────

// Tab fully loaded → analyze
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        analyzeTab(tabId, tab.url);
    }
});

// Tab switched → update badge from cache OR re-analyze if stale
chrome.tabs.onActivated.addListener(({ tabId }) => {
    chrome.tabs.get(tabId, tab => {
        if (tab?.url && !shouldSkip(tab.url)) {
            analyzeTab(tabId, tab.url); // will use cache if fresh
        }
    });
});

// Cookie changed → re-analyze active tab
chrome.cookies.onChanged.addListener(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        const tab = tabs[0];
        if (tab?.url && !shouldSkip(tab.url)) {
            analyzeTab(tab.id, tab.url, true); // force re-analyze
        }
    });
});

// ── Message Handler ───────────────────────────────────────────────────────────
// IMPORTANT: popup.js reads from chrome.storage.local DIRECTLY.
// Messages here are only used for "TRIGGER_ANALYZE" (fire-and-forget).
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "TRIGGER_ANALYZE") {
        // Popup asked us to re-analyze current tab — do it async
        chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
            const tab = tabs[0];
            if (tab?.url && !shouldSkip(tab.url)) {
                analyzeTab(tab.id, tab.url, true); // force = true
            }
        });
        // Respond immediately so port doesn't error
        sendResponse({ ok: true });
        return false; // synchronous response — no keepalive needed
    }

    if (msg.type === "PING") {
        sendResponse({ ok: true });
        return false;
    }
});
