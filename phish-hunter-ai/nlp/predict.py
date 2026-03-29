"""
predict.py
----------
PhishHunter AI — NLP Prediction Engine
PS ID   : TUAH4818S
Version : 1.0.0

Loads the trained Random Forest model (model.pkl) and TF-IDF
vectorizer (vectorizer.pkl), then exposes a single clean function:

    predict_phishing(text: str) -> dict

Called by:
  • agent_api.py   → main Flask endpoint
  • nlp_api.py     → standalone NLP test endpoint
  • agent_controller.py (via agent_api.py)

Returns:
    {
        "score"        : float  (0–100 danger score),
        "label"        : str    ("phishing" or "safe"),
        "trigger_words": list   (top suspicious words found),
        "confidence"   : float  (model confidence 0–1),
        "url_present"  : bool   (True if URL detected in text),
        "urgency_score": int    (0–5 urgency keyword count)
    }
"""

# ════════════════════════════════════════════════════════════════
#  IMPORTS
# ════════════════════════════════════════════════════════════════
import os
import re
import pickle
import logging

import nltk
from nltk.corpus import stopwords

# ── Logger setup ─────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "[NLP] %(levelname)s — %(message)s"
)
log = logging.getLogger(__name__)

# ── NLTK silent download ──────────────────────────────────────────
nltk.download("stopwords", quiet=True)
nltk.download("punkt",     quiet=True)


# ════════════════════════════════════════════════════════════════
#  MODEL LOADING
# ════════════════════════════════════════════════════════════════

# Resolve paths relative to this file
# Works whether called from root, nlp/, or agent/
_HERE      = os.path.dirname(os.path.abspath(__file__))
_ROOT      = os.path.dirname(_HERE)          # phish-hunter-ai/

MODEL_PATH      = os.path.join(_ROOT, "model.pkl")
VECTORIZER_PATH = os.path.join(_ROOT, "vectorizer.pkl")

# Fallback: also check nlp/ folder itself
if not os.path.exists(MODEL_PATH):
    MODEL_PATH      = os.path.join(_HERE, "model.pkl")
    VECTORIZER_PATH = os.path.join(_HERE, "vectorizer.pkl")

try:
    with open(MODEL_PATH, "rb") as f:
        _model = pickle.load(f)

    with open(VECTORIZER_PATH, "rb") as f:
        _vectorizer = pickle.load(f)

    log.info(f"model.pkl      loaded ← {MODEL_PATH}")
    log.info(f"vectorizer.pkl loaded ← {VECTORIZER_PATH}")
    _MODEL_READY = True

except FileNotFoundError as e:
    log.error(f"Model file not found: {e}")
    log.error("Run: python nlp/train_model.py  to generate model.pkl")
    _model       = None
    _vectorizer  = None
    _MODEL_READY = False

except Exception as e:
    log.error(f"Failed to load model: {e}")
    _model       = None
    _vectorizer  = None
    _MODEL_READY = False


# ════════════════════════════════════════════════════════════════
#  CONSTANTS
# ════════════════════════════════════════════════════════════════

# Urgency / phishing trigger keywords (Indian SMS context included)
URGENCY_KEYWORDS = [
    # Account / banking
    "urgent", "verify", "account", "suspended", "blocked", "expire",
    "expired", "update", "confirm", "reactivate", "access", "locked",
    # Financial
    "bank", "sbi", "hdfc", "icici", "axis", "upi", "kyc", "balance",
    "transaction", "debit", "credit", "loan", "emi", "interest",
    # Action words
    "click", "login", "password", "otp", "pin", "submit", "open",
    "download", "install", "call now", "act now", "immediately",
    # Scam bait
    "win", "won", "winner", "prize", "reward", "claim", "gift",
    "free", "selected", "congratulations", "lucky", "bonus",
    "lottery", "offer", "limited", "exclusive",
    # Impersonation
    "dear customer", "dear user", "government", "police",
    "income tax", "aadhaar", "pan card", "epfo", "trai",
    # Threat words
    "suspend", "terminate", "legal", "action", "penalty",
    "fine", "arrest", "fraud", "detected", "hacked",
]

# URL pattern — catches http://, https://, www., bare domains
_URL_REGEX = re.compile(
    r"(https?://[^\s]+)"
    r"|(\bwww\.[^\s]+)"
    r"|(\b[a-zA-Z0-9-]+\.(xyz|top|club|online|site|live|info|in|com|net|org)[^\s]*)",
    re.IGNORECASE
)

# Extra-suspicious TLDs commonly used in phishing
_SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".site",
                    ".live", ".tk", ".ml", ".ga", ".cf"}


# ════════════════════════════════════════════════════════════════
#  TEXT PREPROCESSING
# ════════════════════════════════════════════════════════════════

_STOP_WORDS = set(stopwords.words("english"))


def _preprocess(text: str) -> str:
    """
    Clean and normalize text for TF-IDF feature extraction.

    Steps:
      1. Lowercase
      2. Remove special characters (keep alphanumeric + spaces)
      3. Tokenize
      4. Remove stopwords
      5. Rejoin as clean string
    """
    text   = text.lower()
    text   = re.sub(r"[^a-z0-9\s]", " ", text)  # keep alphanumeric
    text   = re.sub(r"\s+", " ", text).strip()    # collapse whitespace
    tokens = text.split()
    tokens = [t for t in tokens if t not in _STOP_WORDS and len(t) > 1]
    return " ".join(tokens)


# ════════════════════════════════════════════════════════════════
#  FEATURE EXTRACTION HELPERS
# ════════════════════════════════════════════════════════════════

def _extract_urls(text: str) -> list:
    """Return all URLs found in text."""
    matches = _URL_REGEX.findall(text)
    # findall returns tuples of groups; flatten and filter empty
    urls = [m for group in matches for m in group if m]
    return urls


def _find_trigger_words(text: str) -> list:
    """Return urgency/phishing keywords found in text (max 5)."""
    text_lower = text.lower()
    found      = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]
    # Deduplicate while preserving order
    seen  = set()
    clean = []
    for kw in found:
        if kw not in seen:
            seen.add(kw)
            clean.append(kw)
    return clean[:5]


def _urgency_score(text: str) -> int:
    """Count urgency keyword hits (capped at 5)."""
    text_lower = text.lower()
    hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    return min(5, hits)


def _has_suspicious_tld(urls: list) -> bool:
    """Return True if any URL uses a suspicious TLD."""
    for url in urls:
        for tld in _SUSPICIOUS_TLDS:
            if tld in url.lower():
                return True
    return False


# ════════════════════════════════════════════════════════════════
#  FALLBACK: RULE-BASED SCORER
#  Used only if model.pkl failed to load
# ════════════════════════════════════════════════════════════════

def _rule_based_score(text: str) -> dict:
    """
    Rule-based phishing scorer — fallback when model is not loaded.
    Less accurate than ML model but keeps the API functional.
    """
    log.warning("Using rule-based fallback scorer (model not loaded)")

    urls          = _extract_urls(text)
    trigger_words = _find_trigger_words(text)
    urgency       = _urgency_score(text)
    url_count     = len(urls)

    keyword_score    = min(70, len(trigger_words) * 12)
    url_bonus        = 15 if url_count > 0 else 0
    sus_tld_bonus    = 10 if _has_suspicious_tld(urls) else 0
    raw_score        = min(95, keyword_score + url_bonus + sus_tld_bonus)

    return {
        "score":         float(raw_score),
        "label":         "phishing" if raw_score >= 40 else "safe",
        "trigger_words": trigger_words,
        "confidence":    round(raw_score / 100, 2),
        "url_present":   url_count > 0,
        "urgency_score": urgency,
        "method":        "rule-based-fallback",
    }


# ════════════════════════════════════════════════════════════════
#  MAIN PUBLIC FUNCTION
# ════════════════════════════════════════════════════════════════

def predict_phishing(text: str) -> dict:
    """
    Analyze text and return a phishing risk assessment.

    Parameters
    ----------
    text : str
        Raw input text — SMS body, email body, or URL string.
        Max recommended length: 5000 characters.

    Returns
    -------
    dict with keys:
        score         (float)  : 0–100 danger score
        label         (str)    : "phishing" or "safe"
        trigger_words (list)   : top suspicious words/phrases detected
        confidence    (float)  : model confidence 0.0–1.0
        url_present   (bool)   : whether a URL was found in the text
        urgency_score (int)    : 0–5, count of urgency keyword hits
        method        (str)    : "ml-model" or "rule-based-fallback"
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "score":         0.0,
            "label":         "safe",
            "trigger_words": [],
            "confidence":    0.0,
            "url_present":   False,
            "urgency_score": 0,
            "method":        "empty-input",
        }

    # Trim very long inputs
    text = text.strip()[:5000]

    # ── Fallback if model not loaded ─────────────────────────────
    if not _MODEL_READY or _model is None or _vectorizer is None:
        return _rule_based_score(text)

    # ── ML prediction ─────────────────────────────────────────────
    try:
        cleaned    = _preprocess(text)
        tfidf_vec  = _vectorizer.transform([cleaned])
        label_id   = int(_model.predict(tfidf_vec)[0])
        proba      = _model.predict_proba(tfidf_vec)[0]  # [safe_prob, phish_prob]

        # Raw score: probability of being phishing × 100
        raw_score  = float(proba[1]) * 100

        # ── Feature extraction ────────────────────────────────────
        urls           = _extract_urls(text)
        trigger_words  = _find_trigger_words(text)
        urgency        = _urgency_score(text)
        url_present    = len(urls) > 0
        text_lower     = text.lower()
        has_sus_tld    = _has_suspicious_tld(urls)

        # ── Indian banking / brand keywords ───────────────────────
        BANK_BRANDS = [
            "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bob",
            "canara", "union bank", "yes bank", "idbi", "rbl",
            "paytm", "phonepe", "gpay", "google pay", "bhim",
            "amazon", "flipkart", "aadhaar", "pan card", "epfo",
            "trai", "irctc", "nsdl", "income tax"
        ]
        has_bank_brand = any(b in text_lower for b in BANK_BRANDS)

        # ── Action/threat words that strongly indicate phishing ───
        THREAT_WORDS = [
            "blocked", "suspended", "deactivated", "terminated",
            "arrested", "legal action", "penalty", "immediately",
            "within 24", "within 2 hours", "will be closed",
            "permanently", "last warning", "final notice"
        ]
        has_threat_word = any(t in text_lower for t in THREAT_WORDS)

        # ════════════════════════════════════════════════════════
        #  OVERRIDE RULES
        #  The ML model (trained on generic SMS data) misses
        #  Indian banking phishing patterns. These rules fix that.
        # ════════════════════════════════════════════════════════

        # RULE 1 — Suspicious URL + Bank Brand = confirmed phishing
        # e.g. "sbi-secure-verify.xyz" → instantly dangerous
        if has_sus_tld and has_bank_brand:
            raw_score = max(raw_score, 78.0)

        # RULE 2 — Suspicious URL + Threat Word = high risk
        # e.g. "account blocked, click xyz-site.top"
        elif has_sus_tld and has_threat_word:
            raw_score = max(raw_score, 72.0)

        # RULE 3 — Any URL + Bank Brand + Threat Word = high risk
        # e.g. "SBI account blocked click here to verify"
        elif url_present and has_bank_brand and has_threat_word:
            raw_score = max(raw_score, 68.0)

        # RULE 4 — Suspicious TLD alone (no brand but still shady)
        elif has_sus_tld:
            raw_score = min(100.0, raw_score + 25.0)

        # RULE 5 — Many trigger words even without URL
        # e.g. pure text lottery/government scams
        if urgency >= 4 and not url_present:
            raw_score = min(100.0, raw_score + 15.0)
        elif urgency >= 3:
            raw_score = min(100.0, raw_score + 8.0)

        # ── Standard ML consistency checks ───────────────────────
        # If ML itself says phishing, enforce minimum score of 40
        if label_id == 1 and raw_score < 40:
            raw_score = 40.0

        # If ML says safe but rules overrode to >80, trust the rules
        # If ML says safe and rules give 40–79, cap at 75 (not blind trust)
        if label_id == 0 and 40 <= raw_score < 80:
            raw_score = min(raw_score, 75.0)

        final_score = round(raw_score, 2)
        label       = "phishing" if final_score >= 40 else "safe"

        return {
            "score":         final_score,
            "label":         label,
            "trigger_words": trigger_words,
            "confidence":    round(float(max(proba)), 4),
            "url_present":   url_present,
            "urgency_score": urgency,
            "method":        "ml-model",
        }

    except Exception as e:
        log.error(f"ML prediction failed: {e} — using rule-based fallback")
        return _rule_based_score(text)


# ════════════════════════════════════════════════════════════════
#  SELF-TEST
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  PhishHunter AI — predict.py SELF TEST")
    print("  PS ID: TUAH4818S")
    print("=" * 65)

    test_cases = [
        ("PHISHING",  "Your SBI account is BLOCKED! Click http://sbi-secure-verify.xyz to update KYC immediately or account will be terminated."),
        ("PHISHING",  "Congratulations! You have won Rs 1,00,000 in Lucky Draw. Claim your prize at http://lucky-winner-india.top/claim now!"),
        ("PHISHING",  "TRAI Notice: Your mobile number will be deactivated. Call 9876543210 immediately to avoid legal action."),
        ("SAFE",      "Your Zomato OTP is 492810. Valid for 10 minutes. Do not share this OTP with anyone."),
        ("SAFE",      "Hi, your Amazon order #405-1234567 has been shipped. Expected delivery: 27 March. Track at amazon.in/orders"),
        ("SAFE",      "Meeting reminder: Team standup at 10 AM today. Join via Google Meet link in the calendar invite."),
    ]

    print(f"\n{'#':<4} {'EXPECTED':<10} {'RESULT':<10} {'SCORE':<8} {'CONF':<7} {'METHOD':<20} TEXT")
    print("-" * 95)

    passed = 0
    for i, (expected, text) in enumerate(test_cases, 1):
        r = predict_phishing(text)
        result  = r["label"].upper()
        correct = "✅" if result == expected else "❌"
        if result == expected:
            passed += 1
        print(f"{i:<4} {expected:<10} {correct} {result:<8} {r['score']:<8.1f} {r['confidence']:<7.4f} {r['method']:<20} {text[:55]}...")
        if r["trigger_words"]:
            print(f"     Triggers: {r['trigger_words']}")

    print("-" * 95)
    print(f"\n  Result: {passed}/{len(test_cases)} passed")
    print("=" * 65 + "\n")