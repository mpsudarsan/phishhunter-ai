document.getElementById('checkBtn').addEventListener('click', async () => {
    try {
        const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
        const url = tab.url;

        const btn = document.getElementById('checkBtn');
        btn.disabled = true;
        btn.textContent = '⏳ Analyzing...';

        // 🔥 STEP 1: Send URL to NLP model
        const nlpResponse = await fetch('http://localhost:5000/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const nlpData = await nlpResponse.json();
        const score = nlpData.score;

        let action, explanation = "";

        // 🔥 STEP 2: Decision logic
        if (score > 60) {
            action = "Block";

            // 🔥 STEP 3: Call Agentic AI for deep analysis
            const agentResponse = await fetch('http://localhost:5001/explain', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });

            const agentData = await agentResponse.json();
            explanation = agentData.reason || "High risk phishing URL detected.";

        } else if (score > 30) {
            action = "Warning";
            explanation = "This URL looks suspicious. Be cautious.";
        } else {
            action = "Safe";
            explanation = "This URL appears safe.";
        }

        // 🎯 UPDATE UI (NO SCORE SHOWN)
        const badge = document.getElementById('badge');

        if (action === 'Block') {
            badge.className = 'badge badge-danger';
            badge.textContent = '⛔ DANGEROUS';
        } else if (action === 'Warning') {
            badge.className = 'badge badge-warning';
            badge.textContent = '⚠️ SUSPICIOUS';
        } else {
            badge.className = 'badge badge-safe';
            badge.textContent = '✅ SAFE';
        }

        document.getElementById('explanation').textContent = explanation;
        document.getElementById('result').style.display = 'block';

        btn.disabled = false;
        btn.textContent = '🔍 Check Again';

    } catch (error) {
        console.error(error);

        document.getElementById('badge').textContent = '❌ ERROR';
        document.getElementById('explanation').textContent = 'Server error or API not running';
        document.getElementById('result').style.display = 'block';

        document.getElementById('checkBtn').disabled = false;
        document.getElementById('checkBtn').textContent = '🔍 Check Current URL';
    }
});