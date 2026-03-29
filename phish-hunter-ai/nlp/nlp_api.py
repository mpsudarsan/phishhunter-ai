"""
nlp_api.py
----------
PhishHunter AI — Standalone NLP Flask API
PS ID   : TUAH4818S
Version : 1.0.0

A lightweight standalone Flask server that exposes the NLP model
as a REST API on port 5001.

This lets Member 2 test the NLP layer INDEPENDENTLY before full
integration with the agent layer (port 5000).

Endpoints:
  POST /predict      → Run phishing prediction on text
  POST /batch        → Predict on a list of texts
  GET  /health       → Server + model health check
  GET  /test         → Run quick self-test and return results
  GET  /model-info   → Show model metadata and feature info

Usage:
  python nlp/nlp_api.py
  curl -X POST http://localhost:5001/predict \
       -H "Content-Type: application/json" \
       -d '{"text": "Your account is blocked. Click here to verify."}'
"""

# ════════════════════════════════════════════════════════════════
#  IMPORTS
# ════════════════════════════════════════════════════════════════
import sys
import os
import time
import logging

from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Path fix: allow imports from project root ────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)
sys.path.insert(0, _HERE)

# ── Import the prediction engine ─────────────────────────────────
try:
    from predict import predict_phishing, _MODEL_READY, URGENCY_KEYWORDS
    NLP_MODULE_LOADED = True
except ImportError as e:
    NLP_MODULE_LOADED = False
    _MODEL_READY      = False
    print(f"[NLP API] ❌ Failed to import predict.py: {e}")
    print("[NLP API]    Make sure predict.py is in the nlp/ folder")

# ── Logger ───────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "[NLP API] %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════
#  FLASK APP SETUP
# ════════════════════════════════════════════════════════════════
app = Flask(__name__)
CORS(app)   # Allow cross-origin requests from dashboard + extension

# ── Request counter (lightweight usage tracking) ─────────────────
_request_count    = 0
_server_start_time = time.time()


# ════════════════════════════════════════════════════════════════
#  HELPER
# ════════════════════════════════════════════════════════════════

def _validate_text(text) -> tuple[bool, str]:
    """
    Validate incoming text field.
    Returns (is_valid: bool, error_message: str)
    """
    if text is None:
        return False, "Missing 'text' field in request body"
    if not isinstance(text, str):
        return False, "'text' must be a string"
    if not text.strip():
        return False, "'text' cannot be empty"
    if len(text) > 5000:
        return False, f"'text' too long ({len(text)} chars). Maximum is 5000."
    return True, ""


# ════════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════════

# ── POST /predict ────────────────────────────────────────────────
@app.route("/predict", methods=["POST"])
def predict():
    """
    Analyze a single text for phishing.

    Request Body (JSON):
    {
        "text"  : "Your SBI account is blocked. Click http://sbi-verify.xyz now",
        "source": "sms"   ← optional: "sms" | "email" | "url" | "browser"
    }

    Response (JSON):
    {
        "score"        : 87.4,
        "label"        : "phishing",
        "trigger_words": ["blocked", "click", "verify"],
        "confidence"   : 0.8742,
        "url_present"  : true,
        "urgency_score": 3,
        "method"       : "ml-model",
        "source"       : "sms",
        "processing_ms": 12
    }
    """
    global _request_count
    _request_count += 1
    start_time = time.time()

    # ── Parse JSON ───────────────────────────────────────────────
    if not request.is_json:
        return jsonify({
            "error": "Content-Type must be application/json",
            "code":  415
        }), 415

    data   = request.get_json(silent=True) or {}
    text   = data.get("text")
    source = data.get("source", "unknown")

    # ── Validate ─────────────────────────────────────────────────
    valid, error_msg = _validate_text(text)
    if not valid:
        return jsonify({"error": error_msg, "code": 400}), 400

    log.info(f"[#{_request_count}] source={source} | len={len(text)} | preview: {text[:60]}...")

    # ── Predict ──────────────────────────────────────────────────
    if not NLP_MODULE_LOADED:
        return jsonify({
            "error": "NLP module (predict.py) failed to load. Check server logs.",
            "code":  503
        }), 503

    try:
        result = predict_phishing(text)
    except Exception as e:
        log.error(f"Prediction error: {e}")
        return jsonify({
            "error":  f"Prediction failed: {str(e)}",
            "code":   500
        }), 500

    # ── Build response ───────────────────────────────────────────
    elapsed_ms = round((time.time() - start_time) * 1000, 1)

    response = {
        **result,
        "source"       : source,
        "text_length"  : len(text),
        "processing_ms": elapsed_ms,
    }

    log.info(f"[#{_request_count}] ✅ score={result['score']}/100 | label={result['label']} | {elapsed_ms}ms")
    return jsonify(response), 200


# ── POST /batch ──────────────────────────────────────────────────
@app.route("/batch", methods=["POST"])
def batch_predict():
    """
    Analyze a list of texts in one request.

    Request Body (JSON):
    {
        "texts": [
            "Your SBI account is blocked...",
            "Your Zomato OTP is 492810.",
            "Click here to claim your prize!"
        ]
    }

    Response (JSON):
    {
        "count"  : 3,
        "results": [
            {"index": 0, "score": 87.4, "label": "phishing", ...},
            {"index": 1, "score": 9.1,  "label": "safe",     ...},
            {"index": 2, "score": 72.0, "label": "phishing", ...}
        ],
        "summary": {
            "phishing_count": 2,
            "safe_count":     1,
            "average_score":  56.2,
            "max_score":      87.4
        }
    }
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json", "code": 415}), 415

    data  = request.get_json(silent=True) or {}
    texts = data.get("texts")

    if not isinstance(texts, list) or len(texts) == 0:
        return jsonify({"error": "'texts' must be a non-empty list", "code": 400}), 400

    if len(texts) > 50:
        return jsonify({"error": "Maximum 50 texts per batch request", "code": 400}), 400

    if not NLP_MODULE_LOADED:
        return jsonify({"error": "NLP module failed to load", "code": 503}), 503

    results = []
    for i, text in enumerate(texts):
        valid, error_msg = _validate_text(text)
        if not valid:
            results.append({"index": i, "error": error_msg})
            continue
        try:
            prediction = predict_phishing(text)
            results.append({"index": i, **prediction})
        except Exception as e:
            results.append({"index": i, "error": str(e)})

    # Summary statistics
    valid_results    = [r for r in results if "score" in r]
    scores           = [r["score"] for r in valid_results]
    phishing_count   = sum(1 for r in valid_results if r.get("label") == "phishing")
    safe_count       = sum(1 for r in valid_results if r.get("label") == "safe")

    summary = {
        "phishing_count": phishing_count,
        "safe_count"    : safe_count,
        "average_score" : round(sum(scores) / len(scores), 2) if scores else 0,
        "max_score"     : max(scores) if scores else 0,
        "min_score"     : min(scores) if scores else 0,
    }

    log.info(f"Batch: {len(texts)} texts → {phishing_count} phishing, {safe_count} safe")

    return jsonify({
        "count"  : len(texts),
        "results": results,
        "summary": summary,
    }), 200


# ── GET /health ───────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    """
    Health check endpoint.

    Response (JSON):
    {
        "status"         : "running",
        "model_loaded"   : true,
        "model_method"   : "ml-model" | "rule-based-fallback",
        "requests_served": 42,
        "uptime_seconds" : 300,
        "version"        : "1.0.0",
        "project"        : "PhishHunter AI",
        "ps_id"          : "TUAH4818S"
    }
    """
    uptime = round(time.time() - _server_start_time, 1)

    return jsonify({
        "status"          : "running",
        "nlp_module"      : "loaded" if NLP_MODULE_LOADED else "failed",
        "model_ready"     : _MODEL_READY,
        "model_method"    : "ml-model" if _MODEL_READY else "rule-based-fallback",
        "requests_served" : _request_count,
        "uptime_seconds"  : uptime,
        "version"         : "1.0.0",
        "project"         : "PhishHunter AI",
        "ps_id"           : "TUAH4818S",
        "endpoint"        : "POST /predict",
    }), 200


# ── GET /test ─────────────────────────────────────────────────────
@app.route("/test", methods=["GET"])
def quick_test():
    """
    Run built-in test cases and return all results.
    Useful for judges to verify the model works instantly.
    """
    if not NLP_MODULE_LOADED:
        return jsonify({"error": "NLP module not loaded", "code": 503}), 503

    test_cases = [
        {
            "label"    : "Bank phishing SMS",
            "expected" : "phishing",
            "text"     : "URGENT: Your SBI account is BLOCKED! Click http://sbi-secure-verify.xyz to update KYC immediately.",
        },
        {
            "label"    : "Lottery scam",
            "expected" : "phishing",
            "text"     : "Congratulations! You won Rs 1,00,000. Claim your prize at lucky-winner.top/claim now!",
        },
        {
            "label"    : "Government impersonation",
            "expected" : "phishing",
            "text"     : "TRAI NOTICE: Your SIM will be deactivated within 24hrs. Call 9876543210 to avoid legal action.",
        },
        {
            "label"    : "Legitimate OTP",
            "expected" : "safe",
            "text"     : "Your Zomato OTP is 492810. Valid for 10 minutes. Do not share.",
        },
        {
            "label"    : "Legitimate delivery notification",
            "expected" : "safe",
            "text"     : "Your Amazon order #405-1234567 has been shipped. Delivery by 27 March.",
        },
    ]

    results  = []
    passed   = 0
    for case in test_cases:
        prediction = predict_phishing(case["text"])
        is_correct = prediction["label"] == case["expected"]
        if is_correct:
            passed += 1
        results.append({
            "label"    : case["label"],
            "text"     : case["text"][:80] + "...",
            "expected" : case["expected"],
            "predicted": prediction["label"],
            "score"    : prediction["score"],
            "correct"  : is_correct,
            "triggers" : prediction["trigger_words"],
        })

    accuracy = round((passed / len(test_cases)) * 100, 1)
    status   = "PASS" if accuracy >= 80 else "PARTIAL" if accuracy >= 60 else "FAIL"

    return jsonify({
        "test_status"   : status,
        "accuracy"      : f"{accuracy}%",
        "passed"        : passed,
        "total"         : len(test_cases),
        "results"       : results,
    }), 200


# ── GET /model-info ───────────────────────────────────────────────
@app.route("/model-info", methods=["GET"])
def model_info():
    """
    Return model metadata and configuration details.
    Useful for judges reviewing the technical implementation.
    """
    return jsonify({
        "project"         : "PhishHunter AI",
        "ps_id"           : "TUAH4818S",
        "version"         : "1.0.0",
        "model_type"      : "Random Forest Classifier",
        "feature_method"  : "TF-IDF (Term Frequency-Inverse Document Frequency)",
        "training_dataset": "SMS Spam Collection — UCI ML Repository",
        "model_loaded"    : _MODEL_READY,
        "score_range"     : "0–100 (higher = more dangerous)",
        "thresholds"      : {
            "SAFE"    : "score < 40",
            "WARN"    : "score 40–69",
            "BLOCK"   : "score >= 70",
        },
        "trigger_keywords_count" : len(URGENCY_KEYWORDS) if NLP_MODULE_LOADED else 0,
        "api_endpoints"   : {
            "POST /predict" : "Analyze single text",
            "POST /batch"   : "Analyze multiple texts (max 50)",
            "GET  /health"  : "Server health check",
            "GET  /test"    : "Run built-in test suite",
            "GET  /model-info" : "This endpoint",
        }
    }), 200


# ════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error"    : "Endpoint not found",
        "code"     : 404,
        "endpoints": ["POST /predict", "POST /batch", "GET /health", "GET /test", "GET /model-info"]
    }), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({
        "error": "Method not allowed. Check HTTP method (GET/POST).",
        "code" : 405
    }), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        "error": "Internal server error",
        "code" : 500
    }), 500


# ════════════════════════════════════════════════════════════════
#  RUN SERVER
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "═" * 58)
    print("  PhishHunter AI — NLP API Server")
    print("  PS ID   : TUAH4818S")
    print("  Port    : 5001  (Agent API runs on 5000)")
    print("═" * 58)
    print(f"  NLP Module : {'✅ predict.py loaded' if NLP_MODULE_LOADED else '❌ predict.py MISSING'}")
    print(f"  ML Model   : {'✅ model.pkl ready'   if _MODEL_READY      else '⚠️  using rule-based fallback'}")
    print()
    print("  Endpoints:")
    print("    POST http://localhost:5001/predict    ← main prediction")
    print("    POST http://localhost:5001/batch      ← batch prediction")
    print("    GET  http://localhost:5001/health     ← health check")
    print("    GET  http://localhost:5001/test       ← run built-in tests")
    print("    GET  http://localhost:5001/model-info ← model metadata")
    print("═" * 58 + "\n")

    app.run(
        host        = "0.0.0.0",
        port        = 5001,
        debug       = True,
        use_reloader= False,
    )