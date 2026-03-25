// api.js - Backend API to call Member 2's NLP model
// This file would be used by Node.js/Express backend

// Fake data for now - replace with real API calls later
const fakeResponses = {
    "sbi-verify": {
        score: 91,
        category: "Bank Fraud",
        explanation: "Impersonates SBI bank, domain is brand new (3 days old), uses urgency manipulation tactics",
        action: "Block"
    },
    "congratulations": {
        score: 87,
        category: "Phishing",
        explanation: "Generic congratulations message with suspicious 'claim' action, common phishing tactic",
        action: "Block"
    },
    "won": {
        score: 85,
        category: "Prize Scam",
        explanation: "Prize scam pattern detected with urgency words and claim buttons",
        action: "Block"
    },
    "default": {
        score: 35,
        category: "Legitimate",
        explanation: "No major phishing indicators detected. Content appears to be legitimate.",
        action: "Safe"
    }
};

/**
 * Main function to analyze text
 * @param {string} text - The text to analyze
 * @returns {object} - Analysis result with score, category, explanation
 */
async function analyzeText(text) {
    try {
        // TODO: Replace with real API call to Member 2's NLP model
        // const nlpResponse = await fetch('http://localhost:5000/detect', {
        //     method: 'POST',
        //     headers: { 'Content-Type': 'application/json' },
        //     body: JSON.stringify({ text: text })
        // });
        
        // For now, use fake data for demo
        const response = getFakeResponse(text);
        
        return {
            score: response.score,
            category: response.category,
            explanation: response.explanation,
            action: response.action
        };
        
    } catch (error) {
        console.error('Error analyzing text:', error);
        return {
            score: 50,
            category: "Error",
            explanation: "Could not analyze text. Please try again.",
            action: "Unknown"
        };
    }
}

/**
 * Get fake response based on keywords (for demo)
 */
function getFakeResponse(text) {
    const lowerText = text.toLowerCase();
    
    if (lowerText.includes('sbi') && lowerText.includes('verify')) {
        return fakeResponses["sbi-verify"];
    } else if (lowerText.includes('congratulations')) {
        return fakeResponses["congratulations"];
    } else if (lowerText.includes('won') || lowerText.includes('claim')) {
        return fakeResponses["won"];
    }
    
    return fakeResponses["default"];
}

/**
 * Call Member 1's agent controller (future integration)
 */
async function callAgentController(text) {
    try {
        // TODO: Call Member 1's agent at http://localhost:8000/agent/investigate
        // const agentResponse = await fetch('http://localhost:8000/agent/investigate', {
        //     method: 'POST',
        //     headers: { 'Content-Type': 'application/json' },
        //     body: JSON.stringify({ text: text })
        // });
        
        // return agentResponse.json();
        
        console.log('Agent controller not yet integrated');
        return null;
        
    } catch (error) {
        console.error('Error calling agent:', error);
        return null;
    }
}

/**
 * Call Member 2's NLP detector (future integration)
 */
async function callNLPDetector(text) {
    try {
        // TODO: Call Member 2's NLP model at http://localhost:5000/detect
        // const nlpResponse = await fetch('http://localhost:5000/detect', {
        //     method: 'POST',
        //     headers: { 'Content-Type': 'application/json' },
        //     body: JSON.stringify({ text: text })
        // });
        
        // return nlpResponse.json();
        
        console.log('NLP detector not yet integrated');
        return null;
        
    } catch (error) {
        console.error('Error calling NLP detector:', error);
        return null;
    }
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        analyzeText,
        callAgentController,
        callNLPDetector
    };
}