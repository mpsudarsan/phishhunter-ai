// content.js - runs on every webpage automatically

console.log('🛡️ Phishing Detector loaded on:', window.location.href);

// 🚫 جلوگیری infinite loop (IMPORTANT)
if (window.location.href.includes("warning.html")) {
    console.log("Skipping detection on warning page");
} else {

    // 🔥 AUTO DETECT ON PAGE LOAD
    chrome.runtime.sendMessage({
        type: "CHECK_URL",
        url: window.location.href
    });

}

// 📩 LISTEN FOR POPUP REQUESTS (unchanged feature)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPageContent') {

        const content = {
            title: document.title,
            url: window.location.href,
            text: document.body.innerText.substring(0, 5000)
        };

        console.log('Sending page content:', content);
        sendResponse(content);
    }
});

// 🎯 HIGHLIGHT SUSPICIOUS LINKS (IMPROVED)
function highlightSuspiciousLinks() {
    const links = document.querySelectorAll('a');

    links.forEach(link => {
        const href = (link.href || '').toLowerCase();

        // 🚨 Basic phishing patterns
        const suspiciousPatterns = [
            'verify', 'confirm', 'update', 'login', 'secure',
            'account', 'bank', 'password', 'urgent'
        ];

        let isSuspicious = suspiciousPatterns.some(keyword => href.includes(keyword));

        if (isSuspicious) {
            link.style.backgroundColor = '#ffcccc';
            link.style.border = '2px solid red';
            link.title = "⚠️ Suspicious link detected";
        }
    });
}

// 🔄 Run after page loads
window.addEventListener('load', () => {
    highlightSuspiciousLinks();
});