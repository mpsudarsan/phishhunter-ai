chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

    if (changeInfo.status === 'complete' && tab.url) {

        // 🚫 Skip internal pages
        if (
            tab.url.startsWith("chrome://") ||
            tab.url.includes("warning.html") ||
            tab.url.startsWith("chrome-extension://")
        ) return;

        console.log("🔍 Checking URL:", tab.url);

        try {
            // 🔹 STEP 1: NLP API
            const nlpRes = await fetch('http://localhost:5000/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ url: tab.url })
            });

            const nlpData = await nlpRes.json();
            const score = nlpData.score;

            console.log("NLP Score:", score);

            let reason = "";

            // 🔥 STEP 2: If dangerous → Agentic AI
            if (score > 60) {

                const agentRes = await fetch('http://localhost:5001/explain', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ url: tab.url })
                });

                const agentData = await agentRes.json();

                reason = agentData.reason || "High risk phishing URL detected.";

                // 🚫 REDIRECT
                const warningPage = chrome.runtime.getURL("warning.html");

                chrome.tabs.update(tabId, {
                    url: warningPage +
                        "?url=" + encodeURIComponent(tab.url) +
                        "&reason=" + encodeURIComponent(reason)
                });
            }

        } catch (error) {
            console.error("❌ API Error:", error);
        }
    }
});