// ============================================================
//  PhishHunterAI — whatsapp-selector.js
//  Version: 4.0 (DARK THEME + FIXED THRESHOLDS)
//
//  THRESHOLDS:
//   0  – 29 → GREEN  (Safe)
//   30 – 59 → ORANGE (Suspicious)
//   60 – 100→ RED    (Danger / Block)
// ============================================================

(function () {
  'use strict';

  const BACKEND_URL     = 'http://localhost:5000/scan';
  const ICON_ID         = 'phishhunter-scan-icon';
  const POPUP_ID        = 'phishhunter-result-popup';
  const THRESHOLD_BLOCK = 60;
  const THRESHOLD_WARN  = 30;

  // ── INJECT STYLES ─────────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
    #${ICON_ID} {
      position: fixed;
      z-index: 999999;
      background: #128C7E;
      color: #fff;
      border: none;
      border-radius: 20px;
      padding: 7px 18px;
      font-size: 13px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      cursor: pointer;
      box-shadow: 0 4px 14px rgba(0,0,0,0.4);
      display: none;
      align-items: center;
      gap: 7px;
      user-select: none;
      font-weight: 600;
      letter-spacing: 0.2px;
      transition: background .2s, transform .15s;
    }
    #${ICON_ID}:hover  { background: #075E54; transform: translateY(-1px); }
    #${ICON_ID}:active { transform: scale(0.97); }

    #${POPUP_ID} {
      position: fixed;
      z-index: 999999;
      background: #0f0f1a;
      border-radius: 16px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      width: 305px;
      display: none;
      flex-direction: column;
      overflow: hidden;
      box-shadow: 0 20px 60px rgba(0,0,0,0.7), 0 4px 16px rgba(0,0,0,0.4);
    }

    .ph-topbar {
      padding: 10px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .ph-topbar-left { display: flex; align-items: center; gap: 7px; }
    .ph-topbar-name { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; font-family: monospace; }
    .ph-topbar-right { display: flex; align-items: center; gap: 10px; }
    .ph-psid { font-size: 9px; color: #333; font-family: monospace; }
    .ph-close {
      font-size: 15px; color: #444; cursor: pointer;
      padding: 3px 5px; border-radius: 50%; line-height: 1;
      transition: color .15s, background .15s;
    }
    .ph-close:hover { color: #aaa; background: #1e1e2e; }

    .ph-hero {
      padding: 18px 18px 14px;
      display: flex;
      align-items: center;
      gap: 15px;
    }
    .ph-ring-wrap { position: relative; flex-shrink: 0; width: 70px; height: 70px; }
    .ph-ring-num {
      position: absolute; inset: 0;
      display: flex; align-items: center; justify-content: center;
      font-size: 20px; font-weight: 700;
    }
    .ph-dot-label {
      font-size: 9px; font-family: monospace; letter-spacing: 0.1em;
      font-weight: 700; margin-bottom: 5px;
      display: flex; align-items: center; gap: 5px;
    }
    .ph-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
    .ph-verdict { font-size: 24px; font-weight: 700; color: #fff; line-height: 1.1; }
    .ph-sub { font-size: 11px; color: #555; margin-top: 4px; }
    .ph-sub b { font-weight: 700; }

    .ph-barzone { padding: 0 18px 14px; }
    .ph-bar-labels {
      display: flex; justify-content: space-between;
      font-size: 9px; font-family: monospace; margin-bottom: 5px;
    }
    .ph-bar-track { height: 5px; border-radius: 100px; overflow: hidden; display: flex; gap: 2px; }
    .ph-seg-g { width: 30%; background: #16a34a; border-radius: 2px; }
    .ph-seg-o { width: 30%; background: #d97706; border-radius: 2px; }
    .ph-seg-r { width: 40%; background: #dc2626; border-radius: 2px; }
    .ph-needle-row { position: relative; height: 12px; }
    .ph-needle {
      position: absolute; top: -13px;
      width: 2px; height: 16px; border-radius: 2px;
      background: #fff; transform: translateX(-50%);
      transition: left 0.85s cubic-bezier(0.22,1,0.36,1);
    }

    .ph-divider { height: 1px; background: #1e1e2e; margin: 0 18px; }

    .ph-preview { padding: 12px 18px; }
    .ph-preview-lbl {
      font-size: 9px; color: #333; font-family: monospace;
      letter-spacing: 0.08em; margin-bottom: 6px; text-transform: uppercase;
    }
    .ph-preview-bubble {
      font-size: 12px; color: #777; line-height: 1.55; font-style: italic;
      padding: 10px 12px; background: #0a0a14; border-radius: 8px;
      border-left: 2px solid #333; word-break: break-word;
    }

    .ph-details { padding: 0 18px 4px; }
    .ph-row {
      display: flex; justify-content: space-between; align-items: center;
      padding: 8px 0; border-bottom: 1px solid #1a1a28; font-size: 12px;
    }
    .ph-row:last-child { border-bottom: none; }
    .ph-row-lbl { color: #444; }
    .ph-row-val { font-weight: 600; color: #e0e0e0; }

    .ph-expl {
      margin: 6px 18px 14px; padding: 10px 12px;
      border-radius: 8px; font-size: 11px; color: #888;
      line-height: 1.65; border: 1px solid transparent;
    }

    .ph-btns { padding: 0 18px 18px; display: flex; gap: 8px; }
    .ph-btn-main {
      flex: 1; padding: 11px; border: none; border-radius: 9px;
      font-size: 12px; font-weight: 700; color: #fff; cursor: pointer;
      letter-spacing: 0.02em; transition: filter .15s, transform .15s;
    }
    .ph-btn-main:hover  { filter: brightness(1.15); }
    .ph-btn-main:active { transform: scale(0.97); }
    .ph-btn-ghost {
      flex: 1; padding: 11px; border: 1px solid #1e1e2e;
      border-radius: 9px; font-size: 12px; font-weight: 600;
      background: transparent; color: #444; cursor: pointer;
      transition: background .15s, color .15s, border-color .15s;
    }
    .ph-btn-ghost:hover { background: #1a1a2e; color: #aaa; border-color: #2a2a3e; }

    .ph-loading { padding: 24px 18px; text-align: center; font-size: 13px; color: #555; }

    .ph-error { padding: 16px 18px 20px; font-size: 12px; color: #dc2626; line-height: 1.65; }
    .ph-error code {
      display: inline-block; font-size: 10px; background: #1a1a2e;
      padding: 2px 7px; border-radius: 4px; color: #888; margin-top: 4px;
    }
    .ph-error-hint { font-size: 11px; color: #333; margin-top: 8px; }
  `;
  document.head.appendChild(style);

  // ── ELEMENTS ──────────────────────────────────────────────────
  const scanIcon = document.createElement('button');
  scanIcon.id        = ICON_ID;
  scanIcon.innerHTML = '🔍 Scan for Phishing';
  document.body.appendChild(scanIcon);

  const popup = document.createElement('div');
  popup.id = POPUP_ID;
  document.body.appendChild(popup);

  let selectedText = '';

  // ── SELECTION ─────────────────────────────────────────────────
  document.addEventListener('mouseup', (e) => {
    if (e.target.id === ICON_ID || popup.contains(e.target)) return;
    setTimeout(() => {
      const text = (window.getSelection()?.toString() || '').trim();
      if (text.length > 5) { selectedText = text; showIcon(e.clientX, e.clientY); }
      else hideIcon();
    }, 10);
  });

  document.addEventListener('mousedown', (e) => {
    if (e.target.id === ICON_ID || popup.contains(e.target)) return;
    hideIcon(); hidePopup();
  });

  function showIcon(x, y) {
    let l = x + 12, t = y - 46;
    if (l + 200 > window.innerWidth) l = window.innerWidth - 210;
    if (t < 4) t = y + 12;
    Object.assign(scanIcon.style, { left: l+'px', top: t+'px', display: 'flex' });
  }
  function hideIcon()  { scanIcon.style.display = 'none'; }
  function hidePopup() { popup.style.display = 'none'; }

  // ── THEME ─────────────────────────────────────────────────────
  function theme(score) {
    if (score >= THRESHOLD_BLOCK) return {
      c: '#dc2626', cDim: 'rgba(220,38,38,0.12)', cBorder: 'rgba(220,38,38,0.25)',
      topBg: '#1a0808 11', heroBg: 'linear-gradient(180deg,#1a0808 0%,#0f0f1a 100%)',
      label: 'PHISHING DETECTED', verdict: 'DANGER', action: 'BLOCK'
    };
    if (score >= THRESHOLD_WARN) return {
      c: '#d97706', cDim: 'rgba(217,119,6,0.12)', cBorder: 'rgba(217,119,6,0.25)',
      topBg: '#1a1000 11', heroBg: 'linear-gradient(180deg,#1a1000 0%,#0f0f1a 100%)',
      label: 'SUSPICIOUS MESSAGE', verdict: 'SUSPICIOUS', action: 'WARN'
    };
    return {
      c: '#16a34a', cDim: 'rgba(22,163,74,0.12)', cBorder: 'rgba(22,163,74,0.25)',
      topBg: '#0a1a0a 11', heroBg: 'linear-gradient(180deg,#0a1a0a 0%,#0f0f1a 100%)',
      label: 'ALL CLEAR', verdict: 'SAFE', action: 'ALLOW'
    };
  }

  // ── SVG RING ──────────────────────────────────────────────────
  function ring(score, color) {
    const r = 30, circ = 2 * Math.PI * r;
    const off = circ - (score / 100) * circ;
    return `<svg width="70" height="70" viewBox="0 0 70 70">
      <circle cx="35" cy="35" r="${r}" fill="none" stroke="#1a1a2e" stroke-width="6"/>
      <circle cx="35" cy="35" r="${r}" fill="none" stroke="${color}"
        stroke-width="6" stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"
        stroke-linecap="round" transform="rotate(-90 35 35)"/>
    </svg>`;
  }

  function topBarHtml(color, bg) {
    return `<div class="ph-topbar" style="background:${bg};border-bottom:1px solid ${color}22;">
      <div class="ph-topbar-left">
        <span style="font-size:14px;">🛡️</span>
        <span class="ph-topbar-name" style="color:${color};">PHISHHUNTER AI</span>
      </div>
      <div class="ph-topbar-right">
        <span class="ph-psid">TUAH4818S</span>
        <span class="ph-close" id="ph-x">✕</span>
      </div>
    </div>`;
  }

  // ── SCAN CLICK ────────────────────────────────────────────────
  scanIcon.addEventListener('click', async () => {
    if (!selectedText) return;
    const rect = scanIcon.getBoundingClientRect();
    hideIcon();
    showLoading(rect.left, rect.top);

    try {
      const res = await fetch(BACKEND_URL, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: selectedText, source: 'whatsapp_web', type: 'sms' })
      });
      if (!res.ok) throw new Error('Server error ' + res.status);
      const data = await res.json();

      let score = 0;
      const raw = data.phishing_score ?? data.score ?? data.final_score ?? data.risk_score ?? null;
      if (raw !== null) {
        score = parseFloat(raw);
        score = score <= 1.0 ? Math.round(score * 100) : Math.round(score);
      }
      score = Math.max(0, Math.min(100, score));

      const payload = {
        phishing_score: score, score, final_score: score,
        category: data.category || data.label || null,
        explanation: data.explanation || data.reason || null,
        tools_called: data.tools_called || [],
        text: selectedText, source: 'whatsapp_web', timestamp: Date.now()
      };

      try { chrome.storage.local.set({ whatsapp_last_result: payload }); } catch(e) {}
      try {
        chrome.runtime.sendMessage({
          type: 'WHATSAPP_RESULT', action: 'whatsapp_scan_result',
          score, phishing_score: score,
          category: payload.category, explanation: payload.explanation,
          tools_called: payload.tools_called, text: selectedText
        });
      } catch(e) {}

      showResult(data, score, rect.left, rect.top);
    } catch (err) {
      showError(err.message, scanIcon.getBoundingClientRect().left, scanIcon.getBoundingClientRect().top);
    }
  });

  // ── RENDER: LOADING ───────────────────────────────────────────
  function showLoading(x, y) {
    popup.innerHTML = `
      ${topBarHtml('#555', '#0a0a14')}
      <div class="ph-loading">⏳ Analysing message…</div>`;
    place(x, y); bindX();
  }

  // ── RENDER: RESULT ────────────────────────────────────────────
  function showResult(data, score, x, y) {
    const t   = theme(score);
    const cat = data.category || data.label ||
      (score >= THRESHOLD_BLOCK ? 'Phishing' : score >= THRESHOLD_WARN ? 'Suspicious' : 'Safe');
    const rsn = data.explanation || data.reason || '';
    const pre = selectedText.length > 72 ? selectedText.substring(0, 72) + '…' : selectedText;

    popup.innerHTML = `
      ${topBarHtml(t.c, t.c + '11')}

      <div class="ph-hero" style="background:${t.heroBg};">
        <div class="ph-ring-wrap">
          ${ring(score, t.c)}
          <div class="ph-ring-num" style="color:${t.c};">${score}</div>
        </div>
        <div>
          <div class="ph-dot-label" style="color:${t.c};">
            <span class="ph-dot" style="background:${t.c};"></span>${t.label}
          </div>
          <div class="ph-verdict">${t.verdict}</div>
          <div class="ph-sub">Score: <b style="color:${t.c};">${score}</b>/100 · ${t.action}</div>
        </div>
      </div>

      <div class="ph-barzone">
        <div class="ph-bar-labels">
          <span style="color:#16a34a;">0–29 safe</span>
          <span style="color:#d97706;">30–59 warn</span>
          <span style="color:#dc2626;">60–100 danger</span>
        </div>
        <div class="ph-bar-track">
          <div class="ph-seg-g"></div><div class="ph-seg-o"></div><div class="ph-seg-r"></div>
        </div>
        <div class="ph-needle-row">
          <div class="ph-needle" id="ph-ndl" style="left:0%;box-shadow:0 0 5px ${t.c}99;"></div>
        </div>
      </div>

      <div class="ph-divider"></div>

      <div class="ph-preview">
        <div class="ph-preview-lbl">Scanned message</div>
        <div class="ph-preview-bubble" style="border-left-color:${t.c}55;">"${esc(pre)}"</div>
      </div>

      <div class="ph-details">
        <div class="ph-row">
          <span class="ph-row-lbl">Category</span>
          <span class="ph-row-val">${esc(cat)}</span>
        </div>
        <div class="ph-row">
          <span class="ph-row-lbl">Action</span>
          <span class="ph-row-val" style="color:${t.c};letter-spacing:0.04em;">${t.action}</span>
        </div>
        <div class="ph-row">
          <span class="ph-row-lbl">Platform</span>
          <span class="ph-row-val">WhatsApp Web</span>
        </div>
      </div>

      ${rsn ? `<div class="ph-expl" style="background:${t.cDim};border-color:${t.cBorder};">${esc(rsn)}</div>` : ''}

      <div class="ph-btns">
        <button class="ph-btn-main" id="ph-dash" style="background:${t.c};">📊 Dashboard</button>
        <button class="ph-btn-ghost" id="ph-dismiss">Dismiss</button>
      </div>`;

    place(x, y); bindX();

    requestAnimationFrame(() => setTimeout(() => {
      const n = document.getElementById('ph-ndl');
      if (n) n.style.left = Math.min(99, score) + '%';
    }, 100));

    document.getElementById('ph-dash')?.addEventListener('click', () => {
      window.open('http://localhost:5000/dashboard', '_blank'); hidePopup();
    });
    document.getElementById('ph-dismiss')?.addEventListener('click', hidePopup);
  }

  // ── RENDER: ERROR ─────────────────────────────────────────────
  function showError(msg, x, y) {
    popup.innerHTML = `
      ${topBarHtml('#dc2626', '#1a0808')}
      <div class="ph-error">
        ⚠️ Could not reach backend.<br>
        Make sure Flask is running:<br>
        <code>python agent/agent_api.py</code>
        <div class="ph-error-hint">Details: ${esc(msg)}</div>
      </div>`;
    place(x, y); bindX();
  }

  // ── HELPERS ───────────────────────────────────────────────────
  function place(x, y) {
    let l = x, t = y - 420;
    if (l + 315 > window.innerWidth) l = window.innerWidth - 320;
    if (l < 4) l = 4;
    if (t < 4) t = y + 30;
    Object.assign(popup.style, { left: l+'px', top: t+'px', display: 'flex' });
  }
  function bindX() { document.getElementById('ph-x')?.addEventListener('click', hidePopup); }
  function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  console.log('[PhishHunterAI] whatsapp-selector.js v4.0 loaded ✅');
})();