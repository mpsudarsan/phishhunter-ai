/**
 * email-scanner.js
 * PhishHunter AI - Dedicated Email Scanner Module
 * PS ID: TUAH4818S
 *
 * THRESHOLD RULES (FIXED v2):
 * 0  – 29  → GREEN  (Safe)
 * 30 – 59  → ORANGE (Suspicious)
 * 60 – 100 → RED    (Danger / Block)
 */

const THRESHOLD_BLOCK = 60; // ≥ 60 → RED
const THRESHOLD_WARN  = 30; // ≥ 30 → ORANGE

class EmailScanner {
    constructor() {
        this.supportedPlatforms = {
            gmail: {
                name: 'Gmail',
                selectors: {
                    body: ['.ii.gt .a3s', '.adn .a3s', '[role="main"] .a3s', '.a3s'],
                    subject: ['.hP', 'input[name="subjectbox"]'],
                    sender: ['.gD', '.go', '[email]'],
                    recipient: ['.g2', '.gO']
                },
                urlPattern: 'mail.google.com'
            },
            outlook: {
                name: 'Outlook',
                selectors: {
                    body: ['.mail-msg-body', '[aria-label="Message body"]', '.ms-Fabric .rps_e63'],
                    subject: ['[aria-label="Subject"]', '.ms-TextField-field'],
                    sender: ['[aria-label="From"]', '.ms-Persona-primaryText'],
                    recipient: ['[aria-label="To"]']
                },
                urlPattern: 'outlook'
            },
            yahoo: {
                name: 'Yahoo Mail',
                selectors: {
                    body: ['.email-body', '.message-body', '.msg-body'],
                    subject: ['[data-test-id="message-subject"]', '.subject'],
                    sender: ['[data-test-id="message-from"]', '.from'],
                    recipient: ['[data-test-id="message-to"]']
                },
                urlPattern: 'mail.yahoo.com'
            },
            protonmail: {
                name: 'ProtonMail',
                selectors: {
                    body: ['.message-content', '.protonmail-msg-body'],
                    subject: ['.message-subject'],
                    sender: ['.message-sender']
                },
                urlPattern: 'protonmail.com'
            }
        };
        this.currentPlatform = null;
        this.lastScanHash = null;
        this.scanTimeout = null;
        this.warningElement = null;
    }

    // ── Colour helper — FIXED thresholds ───────────────────────────
    getTheme(score) {
        // ≥ 60 → RED (DANGER)
        if (score >= THRESHOLD_BLOCK) return {
            hex       : '#dc2626',
            hexLight  : '#fca5a5',
            hexBg     : 'rgba(220,38,38,0.12)',
            hexBorder : 'rgba(220,38,38,0.45)',
            hexGrad   : 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
            badge     : '#dc2626',
            badgeText : '!',
            label     : 'DANGER',
            pill      : '🚨 DANGER',
            icon      : '🚨',
            title     : 'Phishing Email Detected',
            subtitle  : 'This email is very likely a phishing attempt. Do NOT click any links or download attachments.'
        };
        // 30–59 → ORANGE (Suspicious)
        if (score >= THRESHOLD_WARN) return {
            hex       : '#d97706',
            hexLight  : '#fcd34d',
            hexBg     : 'rgba(217,119,6,0.12)',
            hexBorder : 'rgba(217,119,6,0.45)',
            hexGrad   : 'linear-gradient(135deg, #f97316 0%, #b45309 100%)',
            badge     : '#d97706',
            badgeText : '⚠',
            label     : 'SUSPICIOUS',
            pill      : '⚠️ SUSPICIOUS',
            icon      : '⚠️',
            title     : 'Suspicious Email Detected',
            subtitle  : 'This email shows signs of phishing. Review carefully before clicking any links.'
        };
        // 0–29 → GREEN (Safe)
        return {
            hex       : '#16a34a',
            hexLight  : '#86efac',
            hexBg     : 'rgba(22,163,74,0.12)',
            hexBorder : 'rgba(22,163,74,0.35)',
            hexGrad   : 'linear-gradient(135deg, #22c55e 0%, #15803d 100%)',
            badge     : '#16a34a',
            badgeText : '✓',
            label     : 'SAFE',
            pill      : '✅ SAFE',
            icon      : '✅',
            title     : 'Email Looks Safe',
            subtitle  : 'No phishing signals detected in this email.'
        };
    }

    // ── Warning UI ──────────────────────────────────────────────────
    showEmailWarning(score, result, emailContent) {
        this.removeWarning();
        const t = this.getTheme(score);

        // ── FIXED: Circle color is purely driven by getTheme()
        //    No CSS class interference — 100% inline style only ──────
        const circleColor = score >= THRESHOLD_BLOCK
            ? '#dc2626'   // RED   for 60–100
            : score >= THRESHOLD_WARN
                ? '#d97706'   // ORANGE for 30–59
                : '#16a34a';  // GREEN  for  0–29

        const warning = document.createElement('div');
        warning.id = 'phish-hunter-email-warning';
        warning.innerHTML = `
<div id="_phw_inner" style="
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 2147483647;
    background: #0d0d1a;
    border: 1.5px solid ${t.hex};
    border-radius: 14px;
    box-shadow: 0 12px 48px rgba(0,0,0,0.55), 0 0 40px ${t.hexBg};
    max-width: 390px;
    width: calc(100vw - 40px);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #e8e8f0;
    animation: phw-slide-in 0.3s cubic-bezier(0.22,1,0.36,1) both;
    overflow: hidden;
    all: initial;
    display: block;
">
<!-- Header bar -->
<div style="
    background: ${t.hexGrad};
    padding: 16px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
">
    <div style="display:flex;align-items:center;gap:16px;">

        <!-- ✅ FIXED SCORE CIRCLE — inline background only, no CSS class -->
        <div style="
            width: 62px !important;
            height: 62px !important;
            border-radius: 50% !important;
            background: ${circleColor} !important;
            background-image: none !important;
            color: #ffffff !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            font-size: 26px !important;
            font-weight: 800 !important;
            flex-shrink: 0 !important;
            box-shadow: 0 0 0 6px rgba(255,255,255,0.15) !important;
            border: 3px solid rgba(255,255,255,0.3) !important;
            line-height: 1 !important;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
        ">
            ${score}
        </div>

        <div>
            <div style="font-size:17px;font-weight:700;letter-spacing:0.01em;color:#ffffff;">${t.title}</div>
            <div style="font-size:12px;opacity:0.9;font-family:monospace;margin-top:3px;color:#ffffff;">
                Risk Score: <strong>${score}/100</strong> &nbsp;·&nbsp; ${t.label}
            </div>
        </div>
    </div>
    <button id="_phw_close" style="
        background:rgba(255,255,255,0.15); border:none; color:white;
        width:30px; height:30px; border-radius:50%;
        font-size:20px; cursor:pointer; line-height:1;
        display:flex; align-items:center; justify-content:center;
        flex-shrink:0;
    ">×</button>
</div>

<!-- Score bar -->
<div style="padding: 14px 20px 0;">
    <div style="display:flex;justify-content:space-between;font-size:10px;font-family:monospace;color:rgba(255,255,255,0.35);margin-bottom:4px;">
        <span>0–29 SAFE</span><span>30–59 WARN</span><span>60–100 DANGER</span>
    </div>
    <div style="position:relative;height:8px;border-radius:100px;overflow:hidden;display:flex;">
        <div style="width:30%;background:#16a34a;"></div>
        <div style="width:30%;background:#d97706;"></div>
        <div style="width:40%;background:#dc2626;"></div>
    </div>
    <div style="position:relative;height:0;">
        <div id="_phw_needle" style="
            position:absolute; top:-12px;
            width:3px; height:20px;
            background:white; border-radius:2px;
            transform:translateX(-50%);
            left:0%;
            transition:left 0.9s cubic-bezier(0.22,1,0.36,1);
            box-shadow:0 0 6px rgba(255,255,255,0.6);
        "></div>
    </div>
</div>

<!-- Email Details -->
<div style="padding: 14px 20px 0;">
    <div style="
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 10px;
        padding: 12px 14px;
        margin-bottom: 12px;
    ">
        <div style="font-size:10px;font-family:monospace;letter-spacing:0.08em;color:rgba(255,255,255,0.35);margin-bottom:8px;">📧 EMAIL DETAILS</div>
        <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px;">
            <span style="color:rgba(255,255,255,0.45);">From</span>
            <span style="font-weight:600;text-align:right;max-width:220px;word-break:break-all;color:#e8e8f0;">
                ${this.escapeHtml(emailContent.sender || 'Unknown')}
            </span>
        </div>
        <div style="display:flex;justify-content:space-between;font-size:13px;">
            <span style="color:rgba(255,255,255,0.45);">Subject</span>
            <span style="font-weight:600;text-align:right;max-width:220px;word-break:break-word;color:#e8e8f0;font-style:${emailContent.subject ? 'normal' : 'italic'};">
                ${this.escapeHtml(emailContent.subject || '(no subject)')}
            </span>
        </div>
    </div>

    <div style="
        font-size:13px; line-height:1.6; color:#b0b0c8;
        border-left: 3px solid ${t.hex};
        padding-left: 12px;
        margin-bottom: 12px;
    ">
        ${this.escapeHtml(result.explanation || t.subtitle)}
    </div>

    ${result.category ? `
    <div style="margin-bottom:10px;">
        <span style="background:${t.hexBg}; border:1px solid ${t.hexBorder}; color:${t.hexLight}; padding:3px 10px; border-radius:100px; font-size:11px; font-family:monospace; letter-spacing:0.06em;">
            Category: ${this.escapeHtml(result.category)}
        </span>
    </div>` : ''}

    ${emailContent.urls && emailContent.urls.length > 0 ? `
    <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.06); border-radius:8px; padding:10px 12px; margin-bottom:12px;">
        <div style="font-size:10px;font-family:monospace;letter-spacing:0.08em;color:rgba(255,255,255,0.35);margin-bottom:6px;">
            🔗 SUSPICIOUS LINKS (${emailContent.urls.length})
        </div>
        ${emailContent.urls.slice(0, 3).map(u => `
            <div style="font-size:11px; font-family:monospace; color:${t.hexLight}; word-break:break-all; padding:3px 0; border-bottom:1px solid rgba(255,255,255,0.05);">
                ${this.escapeHtml(typeof u === 'string' ? u : (u.domain || u.full || String(u)))}
            </div>
        `).join('')}
    </div>` : ''}
</div>

<!-- Buttons -->
<div style="padding:14px 20px 20px;display:flex;gap:10px;">
    <button id="_phw_dashboard" style="
        flex:1; padding:12px 0; background:${t.hex}; color:white; border:none; border-radius:8px;
        font-size:13px; font-weight:700; cursor:pointer; letter-spacing:0.02em;
    ">📊 Full Analysis</button>
    <button id="_phw_dismiss" style="
        flex:1; padding:12px 0; background:transparent; color:rgba(255,255,255,0.5);
        border:1px solid rgba(255,255,255,0.1); border-radius:8px;
        font-size:13px; cursor:pointer;
    ">Dismiss</button>
</div>
</div>

<style>
@keyframes phw-slide-in  { from { transform: translateX(calc(100% + 20px)); opacity:0; } to { transform: translateX(0); opacity:1; } }
@keyframes phw-slide-out { from { transform: translateX(0); opacity:1; } to { transform: translateX(calc(100% + 20px)); opacity:0; } }
#_phw_dashboard:hover { filter: brightness(1.15); }
#_phw_dismiss:hover   { color: #e8e8f0 !important; border-color: rgba(255,255,255,0.3) !important; }
</style>`;

        document.body.appendChild(warning);
        this.warningElement = warning;

        // Animate needle to correct position
        requestAnimationFrame(() => {
            setTimeout(() => {
                const needle = document.getElementById('_phw_needle');
                if (needle) needle.style.left = Math.min(99, score) + '%';
            }, 150);
        });

        // Event listeners
        document.getElementById('_phw_close')?.addEventListener('click', () => this.removeWarning());
        document.getElementById('_phw_dismiss')?.addEventListener('click', () => this.removeWarning());
        document.getElementById('_phw_dashboard')?.addEventListener('click', () => {
            chrome.runtime.sendMessage({ type: 'OPEN_DASHBOARD', data: { result, email: emailContent } });
            this.removeWarning();
        });

        // Auto dismiss — longer for dangerous emails
        const autoMs = score >= THRESHOLD_BLOCK ? 20000 : 10000;
        setTimeout(() => this.removeWarning(), autoMs);
    }

    // ── Badge update ────────────────────────────────────────────────
    updateExtensionBadge(score) {
        const t = this.getTheme(score);
        chrome.runtime.sendMessage({
            type : 'UPDATE_BADGE',
            color: t.badge,
            text : t.badgeText,
            score
        }).catch(() => {});
    }

    // ── Remove warning ──────────────────────────────────────────────
    removeWarning() {
        if (this.warningElement && this.warningElement.parentElement) {
            const inner = this.warningElement.querySelector('#_phw_inner');
            if (inner) {
                inner.style.animation = 'phw-slide-out 0.28s ease both';
                setTimeout(() => {
                    this.warningElement?.remove();
                    this.warningElement = null;
                }, 300);
            } else {
                this.warningElement.remove();
                this.warningElement = null;
            }
        }
    }

    // ── HTML escape ─────────────────────────────────────────────────
    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ── All other methods (unchanged from your original) ────────────
    // initialize(), detectPlatform(), extractEmailContent(),
    // scanCurrentEmail(), sendToBackground(), etc.
    // Paste your original implementations of these below here.
}

// ── Auto-initialise ────────────────────────────────────────────────
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.emailScanner = new EmailScanner();
        window.emailScanner.initialize();
    });
} else {
    window.emailScanner = new EmailScanner();
    window.emailScanner.initialize();
}

window.EmailScanner = EmailScanner;