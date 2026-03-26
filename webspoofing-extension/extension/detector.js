/**
 * detector.js - Shared security logic for PhishGuard.
 * Translates the Python cookie_detector.py logic to JavaScript.
 */

const Detector = {
  // Severity Weights
  SEVERITY_WEIGHTS: {
    high: 0.35,
    medium: 0.15,
    low: 0.05,
  },

  /**
   * Analyse cookies and return anomaly data.
   * @param {string} url - Current tab URL
   * @param {Array} cookies - Array of cookie objects from chrome.cookies.get
   */
  analyseCookies(url, cookies) {
    const anomalies = [];
    let score = 0.0;

    const missingHttpOnly = [];
    const missingSecure = [];
    const jwtPayloads = [];
    const picklePayloads = [];
    const excessiveLifetime = [];

    const now = Date.now();
    const isHttps = url.startsWith("https");

    cookies.forEach((cookie) => {
      const name = (cookie.name || "").toLowerCase();
      const value = String(cookie.value || "");

      // Rule 1: Missing HttpOnly flag on session/auth cookies
      const isSession =
        name.includes("session") ||
        name.includes("auth") ||
        name.includes("id") ||
        name.includes("_id");

      if (isSession && !cookie.httpOnly) {
        missingHttpOnly.push(cookie.name);
      }

      // Rule 2: Missing Secure flag over HTTPS
      if (isHttps && !cookie.secure) {
        missingSecure.push(cookie.name);
      }

      // Rule 3: JWT in plain cookie (Starts with eyJ)
      if (value.startsWith("eyJ") && value.length > 30) {
        jwtPayloads.push(cookie.name);
      }

      // Rule 4: Python pickle payloads (Base64 'gASV')
      if (value.includes("gASV") || value.includes("c__main__")) {
        picklePayloads.push(cookie.name);
      }

      // Rule 5: Excessive cookie lifetime (> 90 days)
      if (cookie.expirationDate) {
        const expiryMs = cookie.expirationDate * 1000;
        const daysDiff = (expiryMs - now) / (1000 * 60 * 60 * 24);
        if (daysDiff > 90) {
          excessiveLifetime.push(cookie.name);
        }
      }
    });

    // Score calculations
    if (missingHttpOnly.length > 0) {
      anomalies.push({
        type: "missing_httponly",
        severity: "high",
        description: "Session cookies lack the HttpOnly flag, making them vulnerable to XSS attacks.",
        affected: missingHttpOnly,
      });
      score += this.SEVERITY_WEIGHTS.high;
    }

    if (missingSecure.length > 0) {
      anomalies.push({
        type: "missing_secure",
        severity: "high",
        description: "Secure flag is missing over an HTTPS connection, risking interception.",
        affected: missingSecure,
      });
      score += this.SEVERITY_WEIGHTS.high;
    }

    if (jwtPayloads.length > 0) {
      anomalies.push({
        type: "jwt_in_plain_cookie",
        severity: "high",
        description: "A potential JWT was found. If not HttpOnly, it can be easily stolen via XSS.",
        affected: jwtPayloads,
      });
      score += this.SEVERITY_WEIGHTS.high;
    }

    if (picklePayloads.length > 0) {
      anomalies.push({
        type: "potential_pickle_payload",
        severity: "high",
        description: "A potential serialized Python object (pickle) was found. Extremely risky for RCE.",
        affected: picklePayloads,
      });
      score += this.SEVERITY_WEIGHTS.high;
    }

    if (excessiveLifetime.length > 0) {
      anomalies.push({
        type: "excessive_lifetime",
        severity: "low",
        description: "Cookies have an excessively long expiration time (>90 days).",
        affected: excessiveLifetime,
      });
      score += this.SEVERITY_WEIGHTS.low;
    }

    score = Math.min(score, 1.0);
    let riskLevel = "low";
    if (score >= 0.65) riskLevel = "high";
    else if (score >= 0.3) riskLevel = "medium";

    return {
      score,
      riskLevel,
      anomalies,
      totalCookies: cookies.length,
    };
  },

  /**
   * Basic URL heuristic scan for phishing.
   */
  analyseUrl(url) {
    const domain = new URL(url).hostname;
    const parts = domain.split(".");
    
    // Heuristic 1: Suspicious keywords
    const keywords = ["login", "secure", "verify", "update", "bank", "barclays", "payment"];
    let suspiciousKeywords = keywords.filter(k => domain.includes(k) && !domain.includes("barclays.co.uk") && !domain.includes("barclays.com"));
    
    // Heuristic 2: Too many subdomains
    let risk = 0.0;
    if (parts.length > 4) risk += 0.4;
    
    // Heuristic 3: Punycode or special chars
    if (domain.includes("xn--") || domain.includes("--")) risk += 0.5;

    if (suspiciousKeywords.length > 0) risk += 0.4;

    return {
      score: Math.min(risk, 1.0),
      isPhishing: risk >= 0.5,
      reason: suspiciousKeywords.length > 0 ? `Contains keywords: ${suspiciousKeywords.join(", ")}` : "Suspicious URL structure",
    };
  }
};
