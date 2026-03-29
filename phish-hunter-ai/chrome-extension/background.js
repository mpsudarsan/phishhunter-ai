/**
 * background.js
 * PhishHunter AI — Chrome Extension Service Worker
 * PS ID    : TUAH4818S
 * Version  : 1.3.0  (FULLY FIXED)
 *
 * FIX SUMMARY:
 *  1. Score field fallback: reads final_score OR score OR phishing_score
 *  2. Unified thresholds: THRESHOLD_BLOCK = 70, THRESHOLD_WARN = 40
 *  3. Warning redirect only fires from background (no double-redirect)
 *  4. scanPage called directly from onUpdated (no dependency on content msg)
 *  5. EMAIL scan returns proper response via sendResponse
 *  6. WhatsApp badge update unified
 */

const FLASK_API       = "http://localhost:5000/scan";
const THRESHOLD_BLOCK = 70;
const THRESHOLD_WARN  = 40;

const scanning = new Set();

// ── Normalize score from any field Flask might return ────────────
function extractScore(result) {
  const raw =
    result.final_score    ??
    result.score          ??
    result.phishing_score ??
    result.risk_score     ??
    0;
  if (typeof raw === 'number' && raw > 0 && raw <= 1) return Math.round(raw * 100);
  return Math.round(raw) || 0;
}

// ── Page/URL scan ────────────────────────────────────────────────
async function scanPage(tabId, url, text) {
  if (!tabId || !url) return;

  if (
    url.startsWith("chrome://")           ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://")             ||
    url.includes("warning.html")          ||
    url === "about:blank"
  ) return;

  if (scanning.has(tabId)) return;
  scanning.add(tabId);

  console.log("[PhishHunter] Scanning page:", url);
  setBadge(tabId, "...", "#2196F3");

  try {
    const res = await fetch(FLASK_API, {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify({ text: text || url, url, source: "browser" })
    });
    if (!res.ok) throw new Error(`HTTP_${res.status}`);

    const result      = await res.json();
    const finalScore  = extractScore(result);
    const action      = result.action      || "SAFE";
    const explanation = result.explanation || "No explanation available.";
    const riskLabel   = result.risk_label  || (finalScore >= THRESHOLD_BLOCK ? "DANGER" : finalScore >= THRESHOLD_WARN ? "SUSPICIOUS" : "SAFE");
    const badgeColor  = result.badge_color || "GREEN";
    const category    = result.category    || "unknown";

    console.log("[PhishHunter] Score:", finalScore, "| Action:", action);

    if      (finalScore >= THRESHOLD_BLOCK) setBadge(tabId, "!", "#F44336");
    else if (finalScore >= THRESHOLD_WARN)  setBadge(tabId, "!", "#FF9800");
    else                                    setBadge(tabId, "\u2713", "#4CAF50");

    const stored = {
      url,
      final_score     : finalScore,
      action,
      risk_label      : riskLabel,
      badge_color     : badgeColor,
      category,
      explanation,
      source          : "browser",
      urls_found      : result.urls_found       || [],
      trigger_words   : result.trigger_words    || [],
      tricks_detected : result.tricks_detected  || [],
      score_breakdown : result.score_breakdown  || {},
      tools_called    : result.tools_called     || [],
      scanned_at      : new Date().toISOString()
    };

    await chrome.storage.local.set({ [`result_${tabId}`]: stored });

    // Redirect to warning.html if score >= THRESHOLD_BLOCK
    if (finalScore >= THRESHOLD_BLOCK) {
      const warningPage = chrome.runtime.getURL("warning.html");
      chrome.tabs.update(tabId, {
        url: `${warningPage}?url=${encodeURIComponent(url)}&score=${finalScore}`
           + `&action=${encodeURIComponent(action)}&reason=${encodeURIComponent(explanation)}`
           + `&category=${encodeURIComponent(category)}&risk_label=${encodeURIComponent(riskLabel)}`
      });
    }

  } catch (error) {
    const isOffline =
      error.message === "Failed to fetch" ||
      error.message.includes("ERR_CONNECTION_REFUSED");

    if (isOffline) console.log("[PhishHunter] API offline.");
    else           console.warn("[PhishHunter] Scan error:", error.message);

    setBadge(tabId, "?", "#9E9E9E");
    await chrome.storage.local.set({
      [`result_${tabId}`]: {
        url,
        final_score : 0,
        action      : isOffline ? "OFFLINE" : "ERROR",
        risk_label  : isOffline ? "API Offline" : "Scan Error",
        badge_color : "GREY",
        explanation : isOffline
          ? "Phish Hunter AI backend is offline. Run: python agent/agent_api.py"
          : `Scan failed: ${error.message}`,
        scanned_at: new Date().toISOString(),
        error: error.message
      }
    });
  } finally {
    scanning.delete(tabId);
  }
}

// ── EMAIL scan ───────────────────────────────────────────────────
async function scanEmailContent(tabId, emailData, sendResponse) {
  if (!tabId) {
    if (sendResponse) sendResponse({ error: "No tabId" });
    return;
  }

  const sender  = emailData.metadata?.sender  || emailData.sender  || "";
  const subject = emailData.metadata?.subject || emailData.subject || "";
  const body    = emailData.text || emailData.body || "";

  console.log("[PhishHunter] Scanning email:", subject || "(no subject)");
  setBadge(tabId, "...", "#2196F3");

  const fullText = `From: ${sender}\nSubject: ${subject}\n\n${body}`;

  try {
    const res = await fetch(FLASK_API, {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify({
        text    : fullText,
        url     : `email:${subject}`,
        source  : "email",
        metadata: {
          sender,
          subject,
          urls_in_email: (emailData.urls || []).map(u =>
            typeof u === "string" ? u : (u.full || String(u))
          )
        }
      })
    });
    if (!res.ok) throw new Error(`HTTP_${res.status}`);

    const result      = await res.json();
    const finalScore  = extractScore(result);
    const action      = result.action      || "SAFE";
    const explanation = result.explanation || "No explanation available.";

    if      (finalScore >= THRESHOLD_BLOCK) setBadge(tabId, "!", "#F44336");
    else if (finalScore >= THRESHOLD_WARN)  setBadge(tabId, "!", "#FF9800");
    else                                    setBadge(tabId, "\u2713", "#4CAF50");

    const stored = {
      url             : `email:${subject}`,
      final_score     : finalScore,
      action,
      risk_label      : result.risk_label || (finalScore >= 70 ? "DANGER" : finalScore >= 40 ? "SUSPICIOUS" : "SAFE"),
      badge_color     : result.badge_color || "GREEN",
      category        : result.category   || "email",
      explanation,
      source          : "email",
      sender,
      subject,
      urls_found      : result.urls_found      || [],
      trigger_words   : result.trigger_words   || [],
      tricks_detected : result.tricks_detected || [],
      score_breakdown : result.score_breakdown || {},
      tools_called    : result.tools_called    || [],
      scanned_at      : new Date().toISOString()
    };

    await chrome.storage.local.set({ [`result_${tabId}`]: stored });

    // Save to history
    chrome.storage.local.get(["emailScanHistory"], (data) => {
      const history = data.emailScanHistory || [];
      history.unshift({
        timestamp: Date.now(), score: finalScore, action,
        sender, subject,
        platform: emailData.metadata?.platform || emailData.platform || "Gmail"
      });
      if (history.length > 100) history.pop();
      chrome.storage.local.set({ emailScanHistory: history });
    });

    if (sendResponse) sendResponse(stored);

  } catch (error) {
    const isOffline =
      error.message === "Failed to fetch" ||
      error.message.includes("ERR_CONNECTION_REFUSED");

    console.warn("[PhishHunter] Email scan error:", error.message);
    setBadge(tabId, "?", "#9E9E9E");

    const errResult = {
      final_score : 0,
      action      : isOffline ? "OFFLINE" : "ERROR",
      risk_label  : isOffline ? "API Offline" : "Scan Error",
      explanation : isOffline
        ? "Backend offline. Run: python agent/agent_api.py"
        : `Scan failed: ${error.message}`,
      source    : "email",
      sender,
      subject,
      scanned_at: new Date().toISOString()
    };
    await chrome.storage.local.set({ [`result_${tabId}`]: errResult });
    if (sendResponse) sendResponse(errResult);
  }
}

// ── Message listener ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "PAGE_DATA") {
    const tabId = sender.tab?.id;
    const url   = message.url || sender.tab?.url || "";
    if (tabId && url) scanPage(tabId, url, message.text || "");
    sendResponse({ status: "scan_started" });
    return true;
  }

  if (message.type === "SCAN_EMAIL_CONTENT") {
    const tabId = sender.tab?.id;
    if (tabId && message.data) {
      // FIXED: must return true BEFORE the async call so the channel stays open
      scanEmailContent(tabId, message.data, sendResponse);
      return true;
    }
    sendResponse({ error: "Missing tabId or data" });
    return true;
  }

  if (message.type === "GET_RESULT") {
    const tabId = message.tabId;
    if (!tabId) {
      sendResponse(null);
      return true;
    }
    chrome.storage.local.get([`result_${tabId}`], (data) => {
      sendResponse(data[`result_${tabId}`] || null);
    });
    return true;
  }

  if (message.type === "RESCAN") {
    scanning.delete(message.tabId);
    chrome.tabs.reload(message.tabId);
    sendResponse({ status: "rescanning" });
    return true;
  }

  if (message.type === "UPDATE_BADGE") {
    const tabId = sender.tab?.id;
    if (tabId) setBadge(tabId, message.text || "", message.color || "#9E9E9E");
    sendResponse({ status: "ok" });
    return true;
  }
});

// ── Tab load: scan immediately when page completes ───────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab?.url) {
    // Always scan on fresh page load (clear old result first)
    chrome.storage.local.remove([`result_${tabId}`], () => {
      scanPage(tabId, tab.url, "");
    });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove([`result_${tabId}`]);
  scanning.delete(tabId);
});

// ── WhatsApp scan result → update badge ──────────────────────────
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "whatsapp_scan_result" || msg.type === "WHATSAPP_RESULT") {
    const score = extractScore({
      final_score  : msg.score ?? msg.phishing_score ?? msg.final_score ?? 0
    });
    chrome.storage.local.set({
      whatsapp_last_result: {
        phishing_score : score,
        score          : score,
        final_score    : score,
        category       : msg.category    || null,
        explanation    : msg.explanation || msg.reason || null,
        tools_called   : msg.tools_called || [],
        text           : msg.text || "",
        source         : "whatsapp_web",
        timestamp      : Date.now()
      }
    });

    const color =
      score >= THRESHOLD_BLOCK ? "#e53935" :
      score >= THRESHOLD_WARN  ? "#FB8C00" : "#43A047";
    const text = score >= THRESHOLD_WARN ? "!" : "\u2713";

    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
  }
});

// ── Badge helper ─────────────────────────────────────────────────
function setBadge(tabId, text, color) {
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}