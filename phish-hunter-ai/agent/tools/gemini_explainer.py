"""
gemini_explainer.py
-------------------
Calls the free Google Gemini API with all findings
and returns a plain English threat explanation.
Part of PhishHunter AI — Agent Tools Layer
"""

import os
import json
import urllib.request
import urllib.error
import re

# ── Load .env with explicit absolute path ────────────────────────
# This file lives at: phish-hunter-ai/agent/tools/gemini_explainer.py
# Root .env lives at: phish-hunter-ai/.env  (2 levels up)
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))    # agent/tools/
_ROOT_DIR = os.path.dirname(os.path.dirname(_THIS_DIR))   # phish-hunter-ai/
_DOTENV   = os.path.join(_ROOT_DIR, ".env")               # phish-hunter-ai/.env

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=_DOTENV, override=True)
    print(f"[gemini] ✅ .env loaded from: {_DOTENV}")
except ImportError:
    print("[gemini] ⚠️  python-dotenv not installed — using system environment")
except Exception as e:
    print(f"[gemini] ⚠️  .env load warning: {e}")

# Current stable model (March 2026)
GEMINI_MODEL = "gemini-2.5-flash"


def build_prompt(scan_result: dict) -> str:
    """
    Build a structured prompt for Gemini based on all scan findings.
    """
    score         = scan_result.get("final_score", 0)
    action        = scan_result.get("action", "UNKNOWN")
    category      = scan_result.get("category", "unknown")
    breakdown     = scan_result.get("score_breakdown", {})
    text          = scan_result.get("original_text", scan_result.get("text", ""))
    urls          = scan_result.get("urls_found", [])
    tricks        = scan_result.get("tricks_detected", [])
    domain_flag   = scan_result.get("domain_flag", "")
    threat_flag   = scan_result.get("threat_flag", "")
    trigger_words = scan_result.get("trigger_words", [])

    context_parts = []
    if text:
        context_parts.append(f'Message: "{text[:300]}"')
    if urls:
        context_parts.append(f"URLs found: {', '.join(urls[:3])}")
    if tricks:
        context_parts.append(f"URL tricks: {'; '.join(tricks[:3])}")
    if domain_flag:
        context_parts.append(f"Domain check: {domain_flag}")
    if threat_flag:
        context_parts.append(f"Threat database: {threat_flag}")
    if trigger_words:
        context_parts.append(f"Suspicious words: {', '.join(trigger_words[:5])}")

    context = "\n".join(context_parts)

    prompt = f"""You are a friendly cybersecurity expert explaining a phishing detection result to a normal person.

SCAN RESULT:
- Final Risk Score: {score}/100
- Recommended Action: {action}
- Category: {category.replace('_', ' ').title()}
- NLP score: {breakdown.get('nlp_score', 0)}/100
- URL risk: {breakdown.get('url_risk_score', 0)}/40
- Domain age risk: {breakdown.get('domain_age_score', 0)}/30
- Threat database matches: {breakdown.get('threat_db_score', 0)}

EVIDENCE:
{context}

Write 2-3 short, clear sentences in simple everyday English that:
1. Clearly say if this is phishing or safe
2. Explain the main reasons why (mention specific evidence like suspicious link, new domain, urgent words, etc.)
3. Tell the user exactly what to do next

Use warm, helpful tone. No technical jargon. No bullet points — just flowing sentences."""

    return prompt


def call_gemini(prompt: str) -> tuple:
    """
    Call the Gemini API with the given prompt.
    Returns (explanation_text, source_label)
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    if not api_key or api_key == "YOUR_GEMINI_API_KEY_HERE":
        print("[gemini] ⚠️  No valid GEMINI_API_KEY found — using fallback")
        print(f"[gemini]    Expected .env at: {_DOTENV}")
        return _generate_fallback_explanation_from_prompt(prompt), "rule-based-fallback"

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={api_key}"

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 250,
            "topP": 0.85,
        }
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(response.read().decode("utf-8"))
            gemini_text = (
                result
                .get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
                .strip()
            )

            if gemini_text:
                print(f"[gemini] ✅ Real Gemini ({GEMINI_MODEL}) explanation generated")
                return gemini_text, f"gemini-{GEMINI_MODEL}"
            else:
                print("[gemini] ⚠️  Empty response from Gemini")
                return _generate_fallback_explanation_from_prompt(prompt), "rule-based-fallback"

    except urllib.error.HTTPError as e:
        try:
            error_body = e.read().decode("utf-8")[:300]
        except:
            error_body = str(e)
        print(f"[gemini] ❌ HTTP Error {e.code}: {error_body}")
        if e.code == 404:
            print(f"[gemini]    Model '{GEMINI_MODEL}' may be invalid. Check Google docs.")
        elif e.code == 403:
            print("[gemini]    API key invalid or Gemini API not enabled in Google AI Studio")
        elif e.code == 429:
            print("[gemini]    Rate limit reached (free tier ~60 req/min)")
        return _generate_fallback_explanation_from_prompt(prompt), "rule-based-fallback"

    except Exception as e:
        print(f"[gemini] ❌ Unexpected error calling Gemini: {e}")
        return _generate_fallback_explanation_from_prompt(prompt), "rule-based-fallback"


def _generate_fallback_explanation_from_prompt(prompt: str) -> str:
    score_match    = re.search(r"Final Risk Score: (\d+)/100", prompt)
    category_match = re.search(r"Category: (.+?)(?:\n|$)", prompt)
    action_match   = re.search(r"Recommended Action: (\w+)", prompt)

    score    = int(score_match.group(1)) if score_match else 50
    category = category_match.group(1).strip() if category_match else "General"
    action   = action_match.group(1).strip() if action_match else "WARN"

    return _rule_based_explanation(score, action, category)


def _rule_based_explanation(score: int, action: str, category: str) -> str:
    cat = category.lower()
    if action == "BLOCK":
        if "bank" in cat or "fraud" in cat:
            return f"This message is a high-risk bank fraud attempt with score {score}/100. It impersonates your bank and urges you to click a suspicious link — a very common phishing trick to steal login details. Do not click anything and delete the message immediately."
        elif "lottery" in cat or "winner" in cat:
            return f"This is a classic lottery scam (score {score}/100). Legitimate companies never ask you to claim big prizes through SMS or email links. Delete it and do not reply or click."
        else:
            return f"This message is confirmed as phishing with a risk score of {score}/100. Multiple red flags including suspicious links and urgent language were detected. Do not click any links or share information."
    elif action == "WARN":
        return f"This message looks suspicious with a risk score of {score}/100. It has some warning signs but we cannot be 100% sure. Be careful — never share OTPs, passwords, or click unknown links. Verify directly with the official app or website."
    else:
        return f"This message appears safe with a low risk score of {score}/100. No major phishing indicators were found. You can proceed, but always stay cautious with unexpected requests for personal information."


def generate_explanation(scan_result: dict) -> dict:
    """
    Main function called by agent_controller.
    """
    prompt = build_prompt(scan_result)
    explanation, source = call_gemini(prompt)

    return {
        "explanation": explanation,
        "source": source,
        "word_count": len(explanation.split()),
        "prompt_used": prompt[:250] + "..." if len(prompt) > 250 else prompt
    }


# ── Quick self-test ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("GEMINI EXPLAINER — SELF TEST (March 2026)")
    print("=" * 60)

    api_key = os.environ.get("GEMINI_API_KEY", "")
    print(f"API Key : {'✅ ' + api_key[:15] + '...' if api_key else '⚠️  NOT SET'}")
    print(f"Model   : {GEMINI_MODEL}")
    print(f".env    : {_DOTENV}")
    print()

    # Reuse your test cases
    test_cases = [ ... ]   # (keep your two test_cases from the original file here)

    for i, scan in enumerate(test_cases, 1):
        print(f"TEST {i}: Score={scan['final_score']}/100 | Action={scan['action']}")
        print(f"Input  : {scan.get('original_text', '')[:80]}...")
        result = generate_explanation(scan)
        print(f"Source : {result['source']}")
        print(f"Output : {result['explanation']}")
        print("-" * 60)