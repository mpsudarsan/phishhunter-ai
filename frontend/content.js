// content.js - runs on every webpage the user visits
// Allows the extension to read and interact with page content

console.log('Phishing Detector content script loaded on:', window.location.href);

// Listen for messages from popup or background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPageContent') {
        // Get page title and URL
        const content = {
            title: document.title,
            url: window.location.href,
            text: document.body.innerText.substring(0, 5000) // First 5000 chars
        };
        
        console.log('Sending page content:', content);
        sendResponse(content);
    }
});

// Optional: Highlight suspicious links in the page
function highlightSuspiciousLinks() {
    const links = document.querySelectorAll('a');
    links.forEach(link => {
        const href = link.href || '';
        // Check if URL looks suspicious
        if (href.includes('verify') || href.includes('confirm') || href.includes('update')) {
            link.style.backgroundColor = '#ffcccc';
            link.style.border = '2px solid #ff6b6b';
        }
    });
}

// Call it when page loads
window.addEventListener('load', highlightSuspiciousLinks);