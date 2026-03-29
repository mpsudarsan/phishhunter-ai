"""
score_combiner.py
-----------------
Combines NLP score + URL risk + domain age score + threat DB score
into a final unified 0-100 danger score.
Part of PhishHunter AI — Agent Tools Layer
"""


# ── Score Weight Distribution (total = 100) ─────────────────────
WEIGHTS = {
    "nlp_score":         40,   # NLP model is the primary detector
    "url_risk_score":    20,   # URL pattern analysis
    "domain_age_score":  20,   # Domain registration age
    "threat_db_score":   20,   # PhishTank database matches
}

# ── Final Score Thresholds ───────────────────────────────────────
THRESHOLDS = {
    "BLOCK": 70,    # >= 70 → BLOCK (high confidence phishing)
    "WARN":  40,    # 40-69 → WARN (suspicious, user should be careful)
    "SAFE":   0,    # < 40  → SAFE (likely legitimate)
}

# ── Category Labels ──────────────────────────────────────────────
CATEGORIES = {
    "bank_fraud":     ["sbi", "hdfc", "icici", "axis", "bank", "netbanking", "upi", "account", "kyc"],
    "lottery_scam":   ["won", "winner", "prize", "lucky", "congratulations", "reward", "claim", "gift"],
    "otp_phishing":   ["otp", "verify", "verification", "code", "pin", "authenticate"],
    "job_scam":       ["job", "hiring", "salary", "work from home", "earn", "income", "part time"],
    "loan_fraud":     ["loan", "credit", "emi", "interest", "approved", "disburse"],
    "govt_impersonation": ["aadhaar", "pan", "epfo", "pm", "government", "ministry", "income tax"],
    "delivery_scam":  ["package", "delivery", "parcel", "shipment", "courier", "customs"],
}


def normalize_score(raw_score: float, max_possible: float) -> float:
    """Normalize a raw score to 0-100 range."""
    if max_possible == 0:
        return 0
    return min(100, max(0, (raw_score / max_possible) * 100))


def detect_category(text: str) -> str:
    """Detect the type/category of phishing from text content."""
    text_lower = text.lower()
    category_scores = {}

    for category, keywords in CATEGORIES.items():
        matches = sum(1 for kw in keywords if kw in text_lower)
        if matches > 0:
            category_scores[category] = matches

    if not category_scores:
        return "general_phishing"

    return max(category_scores, key=category_scores.get)


def get_action(final_score: int) -> str:
    """Return recommended action based on final score."""
    if final_score >= THRESHOLDS["BLOCK"]:
        return "BLOCK"
    elif final_score >= THRESHOLDS["WARN"]:
        return "WARN"
    else:
        return "SAFE"


def get_risk_label(final_score: int) -> str:
    """Return human-readable risk label."""
    if final_score >= 85:
        return "CRITICAL THREAT"
    elif final_score >= 70:
        return "HIGH RISK — Phishing"
    elif final_score >= 55:
        return "MEDIUM-HIGH RISK — Suspicious"
    elif final_score >= 40:
        return "MEDIUM RISK — Be Careful"
    elif final_score >= 20:
        return "LOW RISK — Probably Safe"
    else:
        return "SAFE — Legitimate"


def get_badge_color(final_score: int) -> str:
    """Return badge color for Chrome extension."""
    if final_score >= 70:
        return "RED"
    elif final_score >= 40:
        return "YELLOW"
    else:
        return "GREEN"


def combine_scores(
    nlp_score: float,
    url_risk_score: float = 0,
    domain_age_score: float = 0,
    threat_db_score: float = 0,
    original_text: str = ""
) -> dict:
    """
    Main function — combine all scores into a final 0-100 danger score.

    Parameters:
        nlp_score        : 0-100 from NLP model (Member 2's predict.py)
        url_risk_score   : 0-40 from url_checker.py
        domain_age_score : 0-30 from domain_age.py
        threat_db_score  : 0-30 from threat_db.py
        original_text    : original input text (for category detection)

    Returns:
        Full result dict with final score, action, and breakdown
    """

    # ── Normalize sub-scores to 0-100 before weighting ──────────
    nlp_normalized        = normalize_score(nlp_score, 100)
    url_normalized        = normalize_score(url_risk_score, 40)
    domain_age_normalized = normalize_score(domain_age_score, 30)
    threat_db_normalized  = normalize_score(threat_db_score, 30)

    # ── Apply weights ────────────────────────────────────────────
    weighted_nlp        = nlp_normalized        * (WEIGHTS["nlp_score"]        / 100)
    weighted_url        = url_normalized        * (WEIGHTS["url_risk_score"]   / 100)
    weighted_domain_age = domain_age_normalized * (WEIGHTS["domain_age_score"] / 100)
    weighted_threat_db  = threat_db_normalized  * (WEIGHTS["threat_db_score"]  / 100)

    # ── Final score (sum of all weighted components) ─────────────
    raw_final = weighted_nlp + weighted_url + weighted_domain_age + weighted_threat_db
    final_score = round(min(100, max(0, raw_final)))

    # ── BOOST: If threat DB has confirmed reports, boost score ───
    if threat_db_score >= 200:       # 200+ reports = confirmed threat
        final_score = min(100, final_score + 10)
    elif threat_db_score >= 50:
        final_score = min(100, final_score + 5)

    # ── BOOST: If domain is brand new (<7 days), boost score ─────
    if domain_age_score >= 28:       # Maps to ≤7 days
        final_score = min(100, final_score + 8)

    # ── Determine action, label, category ───────────────────────
    action       = get_action(final_score)
    risk_label   = get_risk_label(final_score)
    badge_color  = get_badge_color(final_score)
    category     = detect_category(original_text) if original_text else "unknown"

    return {
        # ── Core output ──────────────────────────────────────────
        "final_score":   final_score,
        "action":        action,
        "risk_label":    risk_label,
        "badge_color":   badge_color,
        "category":      category,

        # ── Score breakdown ──────────────────────────────────────
        "score_breakdown": {
            "nlp_score":         round(nlp_score),
            "url_risk_score":    round(url_risk_score),
            "domain_age_score":  round(domain_age_score),
            "threat_db_score":   round(threat_db_score),
        },

        # ── Weighted contributions ───────────────────────────────
        "weighted_contributions": {
            "nlp":        round(weighted_nlp, 1),
            "url":        round(weighted_url, 1),
            "domain_age": round(weighted_domain_age, 1),
            "threat_db":  round(weighted_threat_db, 1),
        },

        # ── Display-ready summary ────────────────────────────────
        "summary": f"Final Score: {final_score}/100 — {risk_label} — Action: {action}"
    }


# ── Quick self-test ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 58)
    print("SCORE COMBINER — SELF TEST")
    print("=" * 58)

    test_cases = [
        {
            "label": "High phishing SMS (bank fraud)",
            "nlp_score": 87,
            "url_risk_score": 30,
            "domain_age_score": 28,
            "threat_db_score": 412,
            "text": "Your SBI account blocked click sbi-verify.xyz to verify now"
        },
        {
            "label": "Lottery scam",
            "nlp_score": 72,
            "url_risk_score": 15,
            "domain_age_score": 20,
            "threat_db_score": 0,
            "text": "Congratulations you won Rs 50000 claim your prize now"
        },
        {
            "label": "Legitimate OTP",
            "nlp_score": 9,
            "url_risk_score": 0,
            "domain_age_score": 0,
            "threat_db_score": 0,
            "text": "Your Zomato OTP is 492810 do not share"
        },
        {
            "label": "Borderline suspicious",
            "nlp_score": 55,
            "url_risk_score": 10,
            "domain_age_score": 0,
            "threat_db_score": 0,
            "text": "Your package delivery failed verify your address"
        },
    ]

    for case in test_cases:
        print(f"\n📌 {case['label']}")
        result = combine_scores(
            nlp_score=case["nlp_score"],
            url_risk_score=case["url_risk_score"],
            domain_age_score=case["domain_age_score"],
            threat_db_score=case["threat_db_score"],
            original_text=case["text"]
        )
        print(f"   Input scores  : NLP={case['nlp_score']} | URL={case['url_risk_score']} | Age={case['domain_age_score']} | Threat={case['threat_db_score']}")
        print(f"   Final Score   : {result['final_score']}/100")
        print(f"   Risk Label    : {result['risk_label']}")
        print(f"   Action        : {result['action']}")
        print(f"   Badge Color   : {result['badge_color']}")
        print(f"   Category      : {result['category']}")
        print(f"   Contributions : {result['weighted_contributions']}")