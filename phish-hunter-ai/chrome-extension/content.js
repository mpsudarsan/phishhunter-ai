/**
 * content.js
 * PhishHunter AI — Content Script
 * PS ID : TUAH4818S
 * Version: 2.0.1 (SHADOW DOM FIX)
 *
 * FIX v2.0.1:
 *  - Side panel + scanning bar now rendered inside a Shadow DOM host element.
 *  - This fully isolates PhishHunter styles from the host page, preventing
 *    any layout shift, overflow bleed, or div-covering-the-page issues.
 *  - Zero other logic changes.
 */

console.log('[PhishHunter] content.js loaded on:', window.location.href);

// Skip warning page entirely
if (window.location.href.includes('warning.html')) {
  console.log('[PhishHunter] Skipping — warning page');
} else {

  // ── Detect email platforms ──────────────────────────────────────
  const isEmailPlatform = () => {
    const h = window.location.hostname;
    return h.includes('mail.google.com') ||
           h.includes('outlook.live.com') ||
           h.includes('outlook.office.com') ||
           h.includes('mail.yahoo.com')   ||
           h.includes('protonmail.com')   ||
           h.includes('icloud.com');
  };

  // ═══════════════════════════════════════════════════
  //  REGULAR WEBSITE MODE
  // ═══════════════════════════════════════════════════
  if (!isEmailPlatform()) {
    console.log('[PhishHunter] Regular website mode');

    window.addEventListener('load', () => {
      const pageText = document.body
        ? document.body.innerText.trim().substring(0, 3000)
        : '';

      chrome.runtime.sendMessage({
        type : 'PAGE_DATA',
        url  : window.location.href,
        text : pageText,
        title: document.title || ''
      }, () => { /* ack */ });

      highlightSuspiciousLinks();
      listenForPageResult();
    });

    function listenForPageResult() {
      let fired = false;

      const handler = (changes, area) => {
        if (area !== 'local' || fired) return;

        const key = Object.keys(changes).find(k => /^result_\d+$/.test(k));
        if (!key) return;

        const result = changes[key]?.newValue;
        if (!result) return;
        if (result.source && result.source !== 'browser') return;

        fired = true;
        chrome.storage.onChanged.removeListener(handler);
        showSidePanelResult(result, null);
      };

      chrome.storage.onChanged.addListener(handler);

      setTimeout(() => {
        if (!fired) chrome.storage.onChanged.removeListener(handler);
      }, 15000);
    }

    function highlightSuspiciousLinks() {
      const keywords = ['verify','confirm','update','login','secure','account','bank','password','urgent'];
      document.querySelectorAll('a[href]').forEach(link => {
        const href = (link.href || '').toLowerCase();
        if (keywords.some(kw => href.includes(kw))) {
          link.style.backgroundColor = '#ffcccc';
          link.style.border = '2px solid red';
          link.title = '⚠️ Suspicious link — PhishHunter AI flagged';
        }
      });
    }

  // ═══════════════════════════════════════════════════
  //  EMAIL PLATFORM MODE
  // ═══════════════════════════════════════════════════
  } else {
    console.log('[PhishHunter] Email platform detected');

    function extractEmailContent() {
      try {
        const bodySelectors = [
          '.ii.gt .a3s', '.adn .a3s', '[role="main"] .a3s', '.a3s',
          '.mail-msg-body', '[aria-label="Message body"]',
          '.email-body', '.message-body', '.msg-body',
          '.message-content'
        ];
        let body = '';
        for (const sel of bodySelectors) {
          const el = document.querySelector(sel);
          if (el && el.innerText && el.innerText.trim().length > 20) {
            body = el.innerText.trim();
            break;
          }
        }
        if (!body) {
          const main = document.querySelector('main, [role="main"], .email-view');
          if (main && main.innerText.length > 100) body = main.innerText.trim();
        }
        if (!body) return null;

        let subject = '';
        const subjectSels = ['.hP','input[name="subjectbox"]','[aria-label="Subject"]','[data-test-id="message-subject"]','.message-subject'];
        for (const sel of subjectSels) {
          const el = document.querySelector(sel);
          if (el) { subject = el.innerText || el.value || ''; if (subject) break; }
        }

        let sender = '';
        const senderSels = ['.gD','.go','[email]','[aria-label="From"]','[data-test-id="message-from"]','.message-sender','.ms-Persona-primaryText'];
        for (const sel of senderSels) {
          const el = document.querySelector(sel);
          if (el) { sender = el.innerText || el.getAttribute('email') || ''; if (sender) break; }
        }

        const urlRegex = /(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+\.[a-z]{2,}[^\s<>"']*)/gi;
        const urls = (body + ' ' + subject).match(urlRegex) || [];

        return { body, subject, sender, urls, timestamp: Date.now() };
      } catch (err) {
        console.error('[PhishHunter] extractEmailContent error:', err);
        return null;
      }
    }

    async function scanEmailContent(emailContent) {
      if (!emailContent || !emailContent.body) return;
      console.log('[PhishHunter] Scanning email:', emailContent.subject || '(no subject)');
      showScanningIndicator();

      try {
        const response = await chrome.runtime.sendMessage({
          type: 'SCAN_EMAIL_CONTENT',
          data: {
            text    : emailContent.body,
            body    : emailContent.body,
            type    : 'email',
            urls    : emailContent.urls,
            sender  : emailContent.sender,
            subject : emailContent.subject,
            metadata: {
              subject : emailContent.subject,
              sender  : emailContent.sender,
              platform: getPlatformName()
            }
          }
        });

        if (response && response.final_score !== undefined) {
          console.log('[PhishHunter] Email score:', response.final_score, 'Action:', response.action);
          showSidePanelResult(response, emailContent);
        }
      } catch (err) {
        console.error('[PhishHunter] Email scan error:', err);
      } finally {
        hideScanningIndicator();
      }
    }

    function getPlatformName() {
      const h = window.location.hostname;
      if (h.includes('gmail'))   return 'Gmail';
      if (h.includes('outlook')) return 'Outlook';
      if (h.includes('yahoo'))   return 'Yahoo Mail';
      if (h.includes('proton'))  return 'ProtonMail';
      return 'Email';
    }

    let lastHash = null;
    function getEmailHash(ec) {
      return ec ? (ec.subject + '|' + ec.body.substring(0, 200)) : null;
    }

    function tryEmailScan() {
      const ec = extractEmailContent();
      if (!ec) return;
      const h = getEmailHash(ec);
      if (h !== lastHash) {
        lastHash = h;
        scanEmailContent(ec);
      }
    }

    let scanTimer = null;
    const observer = new MutationObserver(() => {
      clearTimeout(scanTimer);
      scanTimer = setTimeout(tryEmailScan, 800);
    });
    observer.observe(document.body, { childList: true, subtree: true });

    let lastUrl = window.location.href;
    setInterval(() => {
      if (window.location.href !== lastUrl) {
        lastUrl = window.location.href;
        lastHash = null;
        setTimeout(tryEmailScan, 1200);
      }
    }, 1000);

    document.addEventListener('click', (e) => {
      const row = e.target.closest('[role="row"], .zA, .yW');
      if (row) setTimeout(tryEmailScan, 1200);
    });

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => setTimeout(tryEmailScan, 2000));
    } else {
      setTimeout(tryEmailScan, 2000);
    }
  }

  // ═══════════════════════════════════════════════════
  //  SHADOW DOM HOST — shared singleton
  //  All PhishHunter UI lives inside this shadow root.
  //  It is COMPLETELY invisible to the host page's CSS
  //  and cannot affect any host-page layout.
  // ═══════════════════════════════════════════════════
  let _shadowHost = null;
  let _shadowRoot = null;

  function getShadowRoot() {
    if (_shadowRoot) return _shadowRoot;

    // Create a host element that has NO layout impact on the page
    _shadowHost = document.createElement('div');
    _shadowHost.id = 'phish-hunter-shadow-host';

    // ── CRITICAL: these styles ensure the host div itself
    //    does NOT affect the page layout at all ──────────
    _shadowHost.style.cssText = [
      'all: initial',
      'position: fixed',
      'top: 0',
      'left: 0',
      'width: 0',
      'height: 0',
      'overflow: visible',
      'pointer-events: none',   // host itself is click-through
      'z-index: 2147483647',
      'display: block'
    ].join(' !important; ') + ' !important';

    document.documentElement.appendChild(_shadowHost); // attach to <html>, not <body>

    _shadowRoot = _shadowHost.attachShadow({ mode: 'open' });

    // Inject all PhishHunter styles inside the shadow root
    const style = document.createElement('style');
    style.textContent = `
      :host { all: initial; }

      #phish-side-panel {
        position: fixed !important;
        top: 0 !important;
        right: 0 !important;
        width: 360px !important;
        height: 100vh !important;
        background: #0d1117 !important;
        border-left: 1px solid #21262d !important;
        z-index: 2147483647 !important;
        display: flex !important;
        flex-direction: column !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
        box-shadow: -8px 0 40px rgba(0,0,0,.7) !important;
        overflow: hidden !important;
        transform: translateX(0);
        transition: transform .35s cubic-bezier(.4,0,.2,1) !important;
        pointer-events: all !important;
      }
      #phish-side-panel.collapsed { transform: translateX(100%) !important; }

      #phish-toggle-btn {
        position: fixed !important;
        top: 50% !important;
        right: 0 !important;
        transform: translateY(-50%) !important;
        z-index: 2147483647 !important;
        background: #0d1117 !important;
        border: 1px solid #21262d !important;
        border-right: none !important;
        color: #e6edf3 !important;
        padding: 14px 8px !important;
        cursor: pointer !important;
        border-radius: 8px 0 0 8px !important;
        font-size: 16px !important;
        writing-mode: vertical-rl !important;
        letter-spacing: 1px !important;
        box-shadow: -4px 0 15px rgba(0,0,0,.5) !important;
        pointer-events: all !important;
      }
      #phish-toggle-btn:hover { background: #161b22 !important; }

      .phish-scanning-bar {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        height: 3px !important;
        background: linear-gradient(90deg, #4f46e5, #818cf8, #4f46e5) !important;
        background-size: 200% !important;
        animation: phish-shimmer 1.5s linear infinite !important;
        z-index: 2147483646 !important;
        pointer-events: none !important;
      }

      @keyframes phish-shimmer {
        0%   { background-position: 200% 0; }
        100% { background-position: -200% 0; }
      }
      @keyframes phish-slide-in {
        from { transform: translateX(100%); }
        to   { transform: translateX(0); }
      }

      .phish-panel-header {
        padding: 14px 16px !important;
        border-bottom: 1px solid #21262d !important;
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
        background: #161b22 !important;
        flex-shrink: 0 !important;
      }
      .phish-panel-title { color: #e6edf3 !important; font-weight: 700 !important; font-size: 14px !important; }
      .phish-panel-psid  { color: #6e7681 !important; font-size: 10px !important; margin-top: 2px !important; }
      .phish-panel-close {
        background: none !important; border: none !important; color: #6e7681 !important;
        cursor: pointer !important; font-size: 20px !important; padding: 0 4px !important; line-height: 1 !important;
      }
      .phish-panel-close:hover { color: #e6edf3 !important; }

      .phish-score-row {
        display: flex !important; align-items: center !important; gap: 12px !important;
        padding: 16px !important; background: #0d1117 !important; flex-shrink: 0 !important;
      }
      .phish-score-ring {
        width: 64px !important; height: 64px !important; border-radius: 50% !important;
        display: flex !important; align-items: center !important; justify-content: center !important;
        font-size: 24px !important; font-weight: 800 !important; flex-shrink: 0 !important;
      }
      .phish-score-meta { flex: 1 !important; }
      .phish-status-badge {
        display: inline-block !important; padding: 3px 10px !important; border-radius: 12px !important;
        font-size: 11px !important; font-weight: 700 !important; letter-spacing: .05em !important;
        margin-bottom: 6px !important;
      }
      .phish-score-label { color: #6e7681 !important; font-size: 12px !important; }

      .phish-panel-body {
        flex: 1 !important; overflow-y: auto !important; padding: 14px 18px !important;
        color: #e6edf3 !important;
      }
      .phish-section-title {
        color: #8b949e !important; font-size: 11px !important; font-weight: 700 !important;
        letter-spacing: .06em !important; text-transform: uppercase !important; margin-bottom: 8px !important;
      }
      .phish-row {
        display: flex !important; justify-content: space-between !important; align-items: flex-start !important;
        padding: 6px 0 !important; border-bottom: 1px solid #21262d !important; font-size: 12px !important;
      }
      .phish-row-label  { color: #6e7681 !important; flex-shrink: 0 !important; margin-right: 8px !important; }
      .phish-row-value  { color: #e6edf3 !important; font-weight: 600 !important; text-align: right !important; word-break: break-all !important; }

      .phish-explanation {
        padding: 10px 12px !important; border-radius: 6px !important; border-left: 3px solid #444 !important;
        font-size: 12px !important; line-height: 1.55 !important; color: #8b949e !important;
        background: #161b22 !important; margin-bottom: 12px !important; white-space: pre-wrap !important;
      }
      .phish-tag {
        display: inline-block !important; padding: 3px 8px !important; border-radius: 10px !important;
        font-size: 11px !important; background: #21262d !important; color: #8b949e !important;
        border: 1px solid #30363d !important; margin: 2px !important;
      }
      .phish-url-item {
        font-size: 11px !important; color: #79c0ff !important; word-break: break-all !important;
        padding: 4px 0 !important; border-bottom: 1px solid #21262d !important;
      }
      .phish-panel-footer {
        padding: 12px 16px !important; border-top: 1px solid #21262d !important;
        display: flex !important; gap: 8px !important; flex-shrink: 0 !important;
        background: #161b22 !important;
      }
      .phish-btn {
        flex: 1 !important; padding: 9px !important; border-radius: 6px !important;
        font-size: 12px !important; font-weight: 600 !important; cursor: pointer !important;
        border: none !important; pointer-events: all !important;
      }
      .phish-btn-primary { background: #1f6feb !important; color: #fff !important; }
      .phish-btn-primary:hover { background: #388bfd !important; }
      .phish-btn-ghost   { background: #21262d !important; color: #8b949e !important; }
      .phish-btn-ghost:hover { background: #30363d !important; color: #e6edf3 !important; }

      * { box-sizing: border-box !important; }
    `;
    _shadowRoot.appendChild(style);

    return _shadowRoot;
  }

  // ═══════════════════════════════════════════════════
  //  SIDE PANEL (shared by both modes)
  // ═══════════════════════════════════════════════════
  function showSidePanelResult(result, emailContent) {
    const shadow = getShadowRoot();

    // Remove existing panel + toggle button from shadow root
    shadow.getElementById('phish-side-panel')?.remove();
    shadow.getElementById('phish-toggle-btn')?.remove();

    const isEmail = result.source === 'email';

    if (!isEmail && (result.final_score || 0) < 40) return;

    const score = result.final_score || 0;
    let accent, circleBg, icon, statusText;
    if      (score >= 60) { accent = '#dc2626'; circleBg = '#dc2626'; icon = '🔴'; statusText = 'DANGER';     }
    else if (score >= 30) { accent = '#d97706'; circleBg = '#d97706'; icon = '🟡'; statusText = 'SUSPICIOUS'; }
    else                  { accent = '#16a34a'; circleBg = '#16a34a'; icon = '🟢'; statusText = 'SAFE';       }

    const urlsFound = result.urls_found    || (emailContent?.urls) || [];
    const tools     = result.tools_called  || [];
    const triggers  = result.trigger_words || [];

    const panel = document.createElement('div');
    panel.id = 'phish-side-panel';
    panel.style.animation = 'phish-slide-in 0.35s cubic-bezier(0.4,0,0.2,1)';
    panel.innerHTML = `
      <div class="phish-panel-header">
        <div>
          <div class="phish-panel-title">🛡️ PhishHunter AI</div>
          <div class="phish-panel-psid">PS ID: TUAH4818S</div>
        </div>
        <button class="phish-panel-close" id="phish-close-btn" title="Collapse">×</button>
      </div>

      <div class="phish-score-row">
        <div class="phish-score-ring" style="background:${circleBg} !important;color:#ffffff !important;border:3px solid rgba(255,255,255,0.25) !important;box-shadow:0 0 0 6px ${circleBg}33 !important;">
          ${score}
        </div>
        <div class="phish-score-meta">
          <div class="phish-status-badge" style="background:${accent}22;color:${accent};border:1px solid ${accent}44;">
            ${icon} ${statusText}
          </div>
          <div class="phish-score-label">Risk Score: <strong style="color:#e6edf3">${score}/100</strong></div>
          <div class="phish-score-label" style="margin-top:2px;">Action: <strong style="color:#e6edf3">${result.action || '—'}</strong></div>
        </div>
      </div>

      <div class="phish-panel-body">
        ${isEmail ? `
        <div style="margin-bottom:12px">
          <div class="phish-section-title">📧 Email Details</div>
          <div class="phish-row">
            <span class="phish-row-label">From</span>
            <span class="phish-row-value">${escapeHtml(result.sender || emailContent?.sender || '—')}</span>
          </div>
          <div class="phish-row">
            <span class="phish-row-label">Subject</span>
            <span class="phish-row-value">${escapeHtml(result.subject || emailContent?.subject || '—')}</span>
          </div>
        </div>
        ` : ''}

        <div style="margin-bottom:12px">
          <div class="phish-section-title">📊 Scan Info</div>
          <div class="phish-row">
            <span class="phish-row-label">Category</span>
            <span class="phish-row-value">${result.category || '—'}</span>
          </div>
          <div class="phish-row">
            <span class="phish-row-label">Risk Label</span>
            <span class="phish-row-value">${result.risk_label || '—'}</span>
          </div>
          <div class="phish-row">
            <span class="phish-row-label">Source</span>
            <span class="phish-row-value">${result.source || 'browser'}</span>
          </div>
          <div class="phish-row">
            <span class="phish-row-label">Scanned</span>
            <span class="phish-row-value">${result.scanned_at ? new Date(result.scanned_at).toLocaleTimeString() : '—'}</span>
          </div>
        </div>

        ${result.explanation ? `
        <div class="phish-explanation" style="border-left-color:${accent}77;">
          ${escapeHtml(result.explanation)}
        </div>` : ''}

        ${triggers.length > 0 ? `
        <div style="margin-bottom:12px">
          <div class="phish-section-title">⚡ Trigger Words</div>
          <div>${triggers.map(t => `<span class="phish-tag" style="color:#ffa198;border-color:#da363344;">${escapeHtml(t)}</span>`).join('')}</div>
        </div>` : ''}

        ${tools.length > 0 ? `
        <div style="margin-bottom:12px">
          <div class="phish-section-title">🔧 Tools Used</div>
          <div>${tools.map(t => `<span class="phish-tag">${escapeHtml(t)}</span>`).join('')}</div>
        </div>` : ''}

        ${urlsFound.length > 0 ? `
        <div style="margin-bottom:12px">
          <div class="phish-section-title">🔗 URLs Found (${urlsFound.length})</div>
          ${urlsFound.slice(0,5).map(u => `<div class="phish-url-item">${escapeHtml(typeof u==='string'?u:(u.full||String(u)))}</div>`).join('')}
          ${urlsFound.length > 5 ? `<div style="color:#6e7681;font-size:11px;margin-top:4px;">+${urlsFound.length-5} more</div>` : ''}
        </div>` : ''}
      </div>

      <div class="phish-panel-footer">
        <button class="phish-btn phish-btn-primary" id="phish-dashboard-btn">📊 Dashboard</button>
        <button class="phish-btn phish-btn-ghost"   id="phish-dismiss-btn">Dismiss</button>
      </div>
    `;

    // Toggle button
    const toggleBtn = document.createElement('button');
    toggleBtn.id        = 'phish-toggle-btn';
    toggleBtn.title     = 'Toggle PhishHunter panel';
    toggleBtn.innerHTML = '🛡️';

    // Append BOTH into shadow root (NOT document.body)
    shadow.appendChild(panel);
    shadow.appendChild(toggleBtn);

    let collapsed = false;
    const collapse = () => { collapsed = true;  panel.classList.add('collapsed');    toggleBtn.title = 'Show PhishHunter'; };
    const expand   = () => { collapsed = false; panel.classList.remove('collapsed'); toggleBtn.title = 'Hide PhishHunter'; };

    shadow.getElementById('phish-close-btn').addEventListener('click', collapse);
    shadow.getElementById('phish-dismiss-btn').addEventListener('click', () => {
      panel.remove();
      toggleBtn.remove();
    });
    shadow.getElementById('phish-dashboard-btn').addEventListener('click', () => {
      window.open('http://localhost:5000/dashboard', '_blank');
    });
    toggleBtn.addEventListener('click', () => collapsed ? expand() : collapse());
  }

  // ── Scanning indicator (also inside shadow DOM) ───────────────
  function showScanningIndicator() {
    const shadow = getShadowRoot();
    if (shadow.getElementById('phish-scanning-bar-top')) return;
    const bar = document.createElement('div');
    bar.id        = 'phish-scanning-bar-top';
    bar.className = 'phish-scanning-bar';
    shadow.appendChild(bar);
  }

  function hideScanningIndicator() {
    getShadowRoot().getElementById('phish-scanning-bar-top')?.remove();
  }

  // ── HTML escape ───────────────────────────────────────────────
  function escapeHtml(str) {
    if (!str) return '';
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  // ── Message handler ───────────────────────────────────────────
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPageContent') {
      sendResponse({
        title: document.title,
        url  : window.location.href,
        text : document.body ? document.body.innerText.substring(0, 5000) : ''
      });
    }
  });
}