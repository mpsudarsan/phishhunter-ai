// warning-helper.js
// Shared warning display functions for content scripts

window.PhishHunterWarning = {
    showEmailWarning: function(result, emailContent) {
        // Remove existing warning
        this.removeWarning();
        
        const warning = document.createElement('div');
        warning.id = 'phish-hunter-email-warning';
        warning.className = 'phish-hunter-warning';
        warning.innerHTML = `
            <div style="
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1000000;
                background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
                color: white;
                padding: 0;
                border-radius: 12px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                max-width: 400px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                animation: slideInRight 0.3s ease;
            ">
                <div style="padding: 16px 20px; border-bottom: 1px solid rgba(255,255,255,0.2);">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <span style="font-size: 28px;">🚨</span>
                            <div>
                                <strong style="font-size: 18px;">Phishing Alert!</strong>
                                <div style="font-size: 12px; opacity: 0.9;">Risk Score: ${result.final_score}/100</div>
                            </div>
                        </div>
                        <button class="phish-warning-close" style="
                            background: none;
                            border: none;
                            color: white;
                            font-size: 24px;
                            cursor: pointer;
                            padding: 0 8px;
                        ">×</button>
                    </div>
                </div>
                <div style="padding: 16px 20px;">
                    <div style="background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px; margin-bottom: 12px;">
                        <div style="font-size: 12px; margin-bottom: 8px;">⚠️ SUSPICIOUS EMAIL</div>
                        <div style="font-size: 14px; font-weight: 500; margin-bottom: 4px;">
                            From: ${this.escapeHtml(emailContent.sender || 'Unknown')}
                        </div>
                        <div style="font-size: 13px; opacity: 0.9;">
                            Subject: ${this.escapeHtml(emailContent.subject || 'No subject')}
                        </div>
                    </div>
                    <div style="font-size: 14px; line-height: 1.5; margin-bottom: 16px;">
                        ${this.escapeHtml(result.explanation || 'This email contains suspicious elements that may indicate a phishing attempt.')}
                    </div>
                    ${result.category ? `<div style="margin-bottom: 16px;">
                        <span style="background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 20px; font-size: 12px;">
                            Category: ${result.category}
                        </span>
                    </div>` : ''}
                    <div style="display: flex; gap: 12px; margin-top: 16px;">
                        <button class="phish-view-details" style="
                            background: white;
                            color: #cc0000;
                            border: none;
                            padding: 8px 16px;
                            border-radius: 6px;
                            cursor: pointer;
                            font-weight: 600;
                            flex: 1;
                        ">View Analysis</button>
                        <button class="phish-dismiss" style="
                            background: rgba(255,255,255,0.2);
                            color: white;
                            border: none;
                            padding: 8px 16px;
                            border-radius: 6px;
                            cursor: pointer;
                            flex: 1;
                        ">Dismiss</button>
                    </div>
                </div>
            </div>
            <style>
                @keyframes slideInRight {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes slideOutRight {
                    from { transform: translateX(0); opacity: 1; }
                    to { transform: translateX(100%); opacity: 0; }
                }
            </style>
        `;
        
        document.body.appendChild(warning);
        
        // Add event listeners
        warning.querySelector('.phish-warning-close')?.addEventListener('click', () => this.removeWarning());
        warning.querySelector('.phish-dismiss')?.addEventListener('click', () => this.removeWarning());
        warning.querySelector('.phish-view-details')?.addEventListener('click', () => {
            chrome.runtime.sendMessage({
                type: 'OPEN_DASHBOARD',
                data: { result: result, email: emailContent }
            });
            this.removeWarning();
        });
        
        // Auto-dismiss after 15 seconds
        setTimeout(() => this.removeWarning(), 15000);
    },
    
    removeWarning: function() {
        const warning = document.getElementById('phish-hunter-email-warning');
        if (warning) {
            warning.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => warning.remove(), 300);
        }
    },
    
    escapeHtml: function(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
};