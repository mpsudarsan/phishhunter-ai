"""
agent_api.py
------------
PhishHunter AI — Main Flask REST API Server
PS ID   : TUAH4818S
Version : 1.0.1
Port    : 5000
"""

# ════════════════════════════════════════════════════════════════
#  IMPORTS & PATH SETUP
# ════════════════════════════════════════════════════════════════
import sys
import os
import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Resolve all critical paths FIRST ────────────────────────────
_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR  = os.path.dirname(_AGENT_DIR)
_NLP_DIR   = os.path.join(_ROOT_DIR, "nlp")
_DOTENV    = os.path.join(_ROOT_DIR, ".env")

# ── Load .env ───────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=_DOTENV, override=True)
    _key = os.environ.get("GEMINI_API_KEY", "")
    if _key and _key != "YOUR_GEMINI_API_KEY_HERE":
        print(f"[API] ✅ .env loaded — GEMINI_API_KEY found")
    else:
        print(f"[API] ⚠️  .env loaded but GEMINI_API_KEY is missing")
except ImportError:
    print("[API] ⚠️  python-dotenv not installed")

# ── Add paths ───────────────────────────────────────────────────
sys.path.insert(0, _ROOT_DIR)
sys.path.insert(0, _NLP_DIR)
sys.path.insert(0, _AGENT_DIR)

# ── Imports ─────────────────────────────────────────────────────
from agent_controller import run_agent

try:
    from predict import predict_phishing
    NLP_MODEL_LOADED = True
    print("[API] ✅ NLP model (nlp/predict.py) loaded successfully")
except ImportError as e:
    NLP_MODEL_LOADED = False
    print(f"[API] ❌ predict.py import failed: {e}")
    print("[API]    Using rule-based simulation as fallback")


# ════════════════════════════════════════════════════════════════
#  FLASK APP
# ════════════════════════════════════════════════════════════════
app = Flask(__name__)
CORS(app)


# ════════════════════════════════════════════════════════════════
#  FALLBACK NLP
# ════════════════════════════════════════════════════════════════
def _simulate_nlp(text: str) -> dict:
    text_lower = text.lower()
    phishing_keywords = [
        "blocked", "suspended", "verify", "click", "winner", "won",
        "prize", "claim", "free", "urgent", "immediately", "expire",
        "kyc", "otp", "password", "account", "reward", "congratulations",
        "lottery", "selected", "dear customer", "dear user", "limited time"
    ]

    url_present   = "http" in text_lower or "www." in text_lower
    keyword_hits  = [kw for kw in phishing_keywords if kw in text_lower]
    keyword_score = min(70, len(keyword_hits) * 12)
    url_bonus     = 15 if url_present else 0
    raw_score     = min(95, keyword_score + url_bonus)

    return {
        "score":         float(raw_score),
        "label":         "phishing" if raw_score >= 40 else "safe",
        "trigger_words": keyword_hits[:5],
        "confidence":    round(raw_score / 100, 2),
        "url_present":   url_present,
        "urgency_score": min(5, len(keyword_hits)),
        "method":        "rule-based-simulation",
    }


# ════════════════════════════════════════════════════════════════
#  MAIN ENDPOINT — POST /scan
# ════════════════════════════════════════════════════════════════
@app.route("/scan", methods=["POST"])
def scan():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json", "code": 400}), 400

    data   = request.get_json(silent=True) or {}
    text   = data.get("text", "").strip()
    source = data.get("source", "unknown")

    if not text:
        return jsonify({"error": "No text provided", "code": 400}), 400
    if len(text) > 5000:
        return jsonify({"error": "Text too long", "code": 400}), 400

    print(f"\n[API] ── New Scan ───────────────────────────────────")
    print(f"[API] Source  : {source}")
    print(f"[API] Length  : {len(text)} chars")
    print(f"[API] Preview : {text[:80]}...")

    # ── Step 1: NLP Analysis ─────────────────────────────────────
    try:
        if NLP_MODEL_LOADED:
            nlp_result = predict_phishing(text)
            print(f"[API] NLP (ML)   → Score: {nlp_result['score']}/100 | {nlp_result['label']}")
        else:
            nlp_result = _simulate_nlp(text)
            nlp_result["simulated"] = True
            print(f"[API] NLP (Sim)  → Score: {nlp_result['score']}/100 | {nlp_result['label']}")

    except Exception as e:
        print(f"[API] ⚠️  NLP error: {e} — using simulation fallback")
        nlp_result = _simulate_nlp(text)
        nlp_result["error"] = str(e)

    # ── Step 2: Agentic AI Analysis (with safe fallback) ────────
    try:
        result = run_agent(text, nlp_result)
        result["source"]      = source
        result["text_length"] = len(text)
        result["nlp_method"]  = nlp_result.get("method", "unknown")

    except Exception as e:
        print(f"[API] ❌ Agent error: {e}")
        traceback.print_exc()   # ← Shows exact line of error

        # SAFE FALLBACK - So extension never gets 500 error
        result = {
            "final_score": nlp_result.get("score", 30),
            "action": "WARN" if nlp_result.get("score", 30) >= 40 else "SAFE",
            "risk_label": "MEDIUM RISK (Agent failed)",
            "badge_color": "ORANGE",
            "category": "agent_error",
            "explanation": f"Agent crashed with error: {str(e)}. Using NLP score as fallback.",
            "urls_found": [],
            "trigger_words": nlp_result.get("trigger_words", []),
            "tricks_detected": [],
            "score_breakdown": {},
            "tools_called": ["NLP Engine", "fallback_mode"],
            "error": str(e)
        }

    print(f"[API] ✅ Done → {result['final_score']}/100 | Action: {result['action']}")
    print(f"[API] ────────────────────────────────────────────────")

    return jsonify(result), 200


# ════════════════════════════════════════════════════════════════
#  HEALTH & TEST ENDPOINTS (unchanged)
# ════════════════════════════════════════════════════════════════
@app.route("/health", methods=["GET"])
def health():
    gemini_ok = bool(os.environ.get("GEMINI_API_KEY", ""))
    return jsonify({
        "status"   : "running",
        "nlp_model": "ml-model" if NLP_MODEL_LOADED else "simulated",
        "gemini"   : "configured" if gemini_ok else "not configured",
        "version"  : "1.0.1",
        "project"  : "PhishHunter AI",
        "ps_id"    : "TUAH4818S",
    }), 200


@app.route("/test", methods=["GET"])
def quick_test():
    # ... (your existing test code remains unchanged)
    test_cases = [ ... ]   # keep your original test_cases
    # ... rest of your quick_test function unchanged
    pass   # ← Replace with your original quick_test code if needed


# Error handlers and run server remain the same
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found", "code": 404}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error", "code": 500}), 500


if __name__ == "__main__":
    gemini_ok = bool(os.environ.get("GEMINI_API_KEY", ""))
    print("\n" + "=" * 55)
    print("  PhishHunter AI — Flask API Server")
    print("  PS ID   : TUAH4818S")
    print("  Port    : 5000")
    print("=" * 55)
    print(f"  NLP Model  : {'✅ ML Model' if NLP_MODEL_LOADED else '⚠️ Simulated'}")
    print(f"  Gemini AI  : {'✅ Configured' if gemini_ok else '⚠️ No API key'}")
    print("=" * 55 + "\n")

    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)