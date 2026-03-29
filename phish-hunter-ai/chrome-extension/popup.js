/**
 * popup.js
 * PhishHunter AI — Popup Controller
 * PS ID   : TUAH4818S
 * Version : 3.0.0
 *
 * THRESHOLDS (v3):
 *   0  – 29  → GREEN  (Safe)
 *   30 – 59  → ORANGE (Suspicious / Warn)
 *   60 – 100 → RED    (Danger / Block → redirects to warning.html)
 */

const THRESHOLD_BLOCK = 60;   // ≥ 60  → RED / Block
const THRESHOLD_WARN  = 30;   // ≥ 30  → ORANGE / Suspicious

// ── Normalize score ──────────────────────────────────────────────
function getDisplayScore(result) {
  if (!result) return 0;
  let score = result.final_score ?? result.score ?? result.phishing_score ?? result.risk_score ?? 0;
  if (typeof score === 'number' && score > 0 && score <= 1) score = Math.round(score * 100);
  score = Math.round(score) || 0;
  if (score === 0) {
    const lbl = (result.risk_label || result.action || '').toUpperCase();
    if (lbl.includes('DANGER') || lbl.includes('BLOCK'))    return 85;
    if (lbl.includes('SUSPICIOUS') || lbl.includes('WARN')) return 55;
  }
  return Math.max(0, Math.min(100, score));
}

// ── Context guard ────────────────────────────────────────────────
function isContextValid() {
  try { return !!(chrome && chrome.runtime && chrome.runtime.id); }
  catch (e) { return false; }
}

// ── Theme lookup ─────────────────────────────────────────────────
function getTheme(score) {
  if (score >= THRESHOLD_BLOCK) return {
    ribbonClass : 'ribbon r-danger',
    ribbonIcon  : '🚨',
    hex         : '#dc2626',
    label       : 'DANGER',
    verdict     : 'DANGER'
  };
  if (score >= THRESHOLD_WARN) return {
    ribbonClass : 'ribbon r-warn',
    ribbonIcon  : '⚠️',
    hex         : '#d97706',
    label       : 'SUSPICIOUS',
    verdict     : 'WARN'
  };
  return {
    ribbonClass : 'ribbon r-safe',
    ribbonIcon  : '✅',
    hex         : '#16a34a',
    label       : 'SAFE',
    verdict     : 'SAFE'
  };
}

// ── Apply theme to popup UI ──────────────────────────────────────
function applyTheme(score, isEmail) {
  const t = getTheme(score);

  // Ribbon
  const ribbon = document.getElementById('statusBar');
  if (ribbon) {
    ribbon.className = t.ribbonClass;
    const icon = ribbon.querySelector('.ribbon-icon');
    const text = ribbon.querySelector('.ribbon-text');
    if (icon) icon.textContent = t.ribbonIcon;
    if (text) {
      text.textContent =
        score >= THRESHOLD_BLOCK ? (isEmail ? 'PHISHING EMAIL DETECTED'  : 'DANGEROUS PAGE DETECTED')  :
        score >= THRESHOLD_WARN  ? (isEmail ? 'SUSPICIOUS EMAIL'         : 'SUSPICIOUS PAGE')          :
                                   (isEmail ? 'EMAIL LOOKS SAFE'         : 'PAGE IS SAFE');
    }
  }

  // Score circle background
  const circle = document.getElementById('scoreCircle');
  if (circle) circle.style.background = t.hex;

  // Big number inside circle
  const scoreNum = document.getElementById('scoreNum');
  if (scoreNum) scoreNum.textContent = String(score);

  // Verdict label inside circle
  const scoreVerdict = document.getElementById('scoreVerdict');
  if (scoreVerdict) scoreVerdict.textContent = t.verdict;

  // Score ring bar
  const ring = document.getElementById('scoreRing');
  if (ring) {
    ring.style.background = t.hex;
    setTimeout(() => { ring.style.width = Math.max(0, Math.min(100, score)) + '%'; }, 80);
  }

  // Risk percentage label
  const riskPct = document.getElementById('riskPct');
  if (riskPct) riskPct.textContent = score + ' / 100';
}

// ── Redirect to warning page ─────────────────────────────────────
// Called when a DANGEROUS page (score ≥ 60) is still open (e.g. not yet blocked).
function redirectToWarning(result, score, currentUrl) {
  const warningUrl = chrome.runtime.getURL('warning.html') +
    '?score='  + encodeURIComponent(score) +
    '&action=' + encodeURIComponent(result.action || 'BLOCK') +
    '&reason=' + encodeURIComponent(result.explanation || result.reason || '') +
    '&url='    + encodeURIComponent(currentUrl || '') +
    '&type='   + encodeURIComponent(result.source === 'email' ? 'email' : 'page');
  chrome.tabs.update({ url: warningUrl });
}

// ── Main ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {

  // Rescan button
  const rescanBtn = document.getElementById('rescanBtn');
  if (rescanBtn) {
    rescanBtn.addEventListener('click', async () => {
      if (!isContextValid()) { window.close(); return; }
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) chrome.tabs.reload(tab.id);
      } catch (e) {}
      window.close();
    });
  }

  // Report button
  const reportBtn = document.getElementById('reportBtn');
  if (reportBtn) {
    reportBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: 'https://safebrowsing.google.com/safebrowsing/report_phish/' });
    });
  }

  if (!isContextValid()) {
    showError('Extension was reloaded. Please close and reopen this popup.');
    return;
  }

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) { showError('Could not read current tab.'); return; }

    const tabId      = tab.id;
    const currentUrl = tab.url || '';
    const isWhatsApp = currentUrl.includes('web.whatsapp.com');

    // ── WhatsApp mode ───────────────────────────────────────────
    if (isWhatsApp) {
      chrome.storage.local.get(['whatsapp_last_result'], (data) => {
        if (chrome.runtime.lastError) { showWhatsAppIdle(); return; }
        data.whatsapp_last_result
          ? displayWhatsAppResult(data.whatsapp_last_result)
          : showWhatsAppIdle();
      });
      return;
    }

    // ── Normal page / email ─────────────────────────────────────
    chrome.runtime.sendMessage({ type: 'GET_RESULT', tabId }, (result) => {
      if (chrome.runtime.lastError) {
        showError('Extension error: ' + chrome.runtime.lastError.message);
        return;
      }
      if (!result) {
        showError('No scan result yet.\n\nVisit a webpage or open an email, then click Rescan.');
        return;
      }
      if (result.action === 'ERROR' || result.action === 'OFFLINE') {
        showError(result.explanation || 'AI server offline.\nRun: python agent/agent_api.py');
        return;
      }

      const displayScore = getDisplayScore(result);

      // ── BLOCK: score ≥ 60 → show warning.html ────────────────
      if (result.source !== 'email' && displayScore >= THRESHOLD_BLOCK) {
        // If background.js already redirected, the tab IS warning.html — just close.
        if (currentUrl.includes(chrome.runtime.getURL('warning.html'))) {
          window.close();
          return;
        }
        // Otherwise push the warning page ourselves (graceful fallback)
        redirectToWarning(result, displayScore, currentUrl);
        window.close();
        return;
      }

      displayResult(result);
    });

  } catch (err) {
    showError('Extension error: ' + err.message);
  }
});

// ── Display normal result (URL or Email) ─────────────────────────
function displayResult(result) {
  show('content'); hide('errorBox');

  const score   = getDisplayScore(result);
  const isEmail = result.source === 'email';

  applyTheme(score, isEmail);

  setText('riskLabel',
    result.risk_label ||
    (score >= THRESHOLD_BLOCK ? 'DANGER' : score >= THRESHOLD_WARN ? 'SUSPICIOUS' : 'SAFE')
  );

  // Category — show sender if email
  const catEl  = document.getElementById('category');
  const catLbl = document.getElementById('categoryLabel');
  if (catEl) {
    if (isEmail && result.sender) {
      const short = result.sender.length > 28 ? result.sender.substring(0, 25) + '…' : result.sender;
      catEl.textContent = short;
      if (catLbl) catLbl.textContent = 'From';
    } else {
      catEl.textContent = formatCategory(result.category);
      if (catLbl) catLbl.textContent = 'Category';
    }
  }

  setText('action',
    result.action ||
    (score >= THRESHOLD_BLOCK ? 'BLOCK' : score >= THRESHOLD_WARN ? 'WARN' : 'ALLOW')
  );

  let expl = result.explanation || 'No explanation available.';
  if (isEmail && result.subject) expl = `Subject: "${result.subject}"\n\n${expl}`;
  setText('explanationBox', expl);

  renderTools(result.tools_called || ['NLP Engine', 'URL Checker', 'Gemini AI']);
}

// ── WhatsApp idle ────────────────────────────────────────────────
function showWhatsAppIdle() {
  show('content'); hide('errorBox');

  const ribbon = document.getElementById('statusBar');
  if (ribbon) {
    ribbon.className = 'ribbon r-loading';
    const icon = ribbon.querySelector('.ribbon-icon');
    const text = ribbon.querySelector('.ribbon-text');
    if (icon) icon.textContent = '💬';
    if (text) text.textContent = 'WHATSAPP WEB DETECTED';
  }

  const circle = document.getElementById('scoreCircle');
  if (circle) circle.style.background = '#128C7E';

  setText('scoreNum',     '?');
  setText('scoreVerdict', 'IDLE');
  setText('riskLabel',    'No Scan Yet');
  setText('category',     'WhatsApp');
  setText('action',       'Select Text');
  setText('explanationBox', 'Select any message text on WhatsApp Web, then click the 🔍 Scan button that appears.');

  const ring = document.getElementById('scoreRing');
  if (ring) { ring.style.width = '0%'; ring.style.background = '#128C7E'; }

  const riskPct = document.getElementById('riskPct');
  if (riskPct) riskPct.textContent = '? / 100';

  const catLbl = document.getElementById('categoryLabel');
  if (catLbl) catLbl.textContent = 'Platform';

  renderTools(['WhatsApp Selector', 'NLP Engine', 'Gemini AI']);

  const btn = document.getElementById('rescanBtn');
  if (btn) btn.textContent = '↺ Refresh';
}

// ── WhatsApp result ──────────────────────────────────────────────
function displayWhatsAppResult(result) {
  show('content'); hide('errorBox');

  const raw   = result.phishing_score ?? result.score ?? result.final_score ?? 0;
  const score = raw <= 1 ? Math.round(raw * 100) : Math.round(raw);

  applyTheme(score, false);

  const textEl = document.querySelector('#statusBar .ribbon-text');
  if (textEl) {
    textEl.textContent =
      score >= THRESHOLD_BLOCK ? 'PHISHING SMS DETECTED'     :
      score >= THRESHOLD_WARN  ? 'SUSPICIOUS WHATSAPP MSG'   :
                                 'WHATSAPP MESSAGE IS SAFE';
  }

  const catLbl = document.getElementById('categoryLabel');
  if (catLbl) catLbl.textContent = 'Category';

  setText('riskLabel', getTheme(score).label);
  setText('category',  result.category || (score >= THRESHOLD_BLOCK ? 'Phishing' : score >= THRESHOLD_WARN ? 'Suspicious' : 'Safe'));
  setText('action',    score >= THRESHOLD_BLOCK ? 'BLOCK' : score >= THRESHOLD_WARN ? 'WARN' : 'ALLOW');

  let expl = result.explanation || result.reason || 'No explanation available.';
  if (result.text) {
    const preview = result.text.length > 80 ? result.text.substring(0, 80) + '…' : result.text;
    expl = `Message: "${preview}"\n\n${expl}`;
  }
  setText('explanationBox', expl);
  renderTools(result.tools_called || ['WhatsApp Selector', 'NLP Engine', 'Gemini AI']);

  const btn = document.getElementById('rescanBtn');
  if (btn) {
    btn.textContent = '✕ Clear';
    btn.onclick = () => {
      chrome.storage.local.remove('whatsapp_last_result');
      showWhatsAppIdle();
    };
  }
}

// ── Error state ──────────────────────────────────────────────────
function showError(message) {
  const ribbon = document.getElementById('statusBar');
  if (ribbon) {
    ribbon.className = 'ribbon r-loading';
    const icon = ribbon.querySelector('.ribbon-icon');
    const text = ribbon.querySelector('.ribbon-text');
    if (icon) icon.textContent = '⚠️';
    if (text) text.textContent = 'SCANNER OFFLINE / ERROR';
  }
  hide('content');
  show('errorBox');
  setText('errorText', message);
}

// ── Helpers ──────────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function show(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'block';
}
function hide(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = 'none';
}
function renderTools(tools) {
  const list = document.getElementById('toolsList');
  if (!list) return;
  list.innerHTML = '';
  (tools || []).forEach(t => {
    const s = document.createElement('span');
    s.className   = 'tool-chip';
    s.textContent = t;
    list.appendChild(s);
  });
}
function formatCategory(cat) {
  if (!cat) return 'Unknown';
  return cat.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}