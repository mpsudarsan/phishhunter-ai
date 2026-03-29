"""
agent_controller.py
-------------------
PhishHunter AI — Agentic AI Decision Engine
PS ID   : TUAH4818S
Version : 1.0.2 (Updated Thresholds)

Logic:
  - Score 0-29   : Safe (Green)
  - Score 30-59  : Suspicious (Orange Popup)
  - Score 60-100 : Danger (Red Popup + Redirect to warning.html)
"""

# ════════════════════════════════════════════════════════════════
#  IMPORTS
# ════════════════════════════════════════════════════════════════
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from tools.url_checker      import analyze_urls
from tools.domain_age       import check_multiple_domains
from tools.threat_db        import check_multiple_urls
from tools.score_combiner   import combine_scores
from tools.gemini_explainer import generate_explanation


# ════════════════════════════════════════════════════════════════
#  THRESHOLDS
# ════════════════════════════════════════════════════════════════
NLP_THRESHOLD_FOR_URL_CHECK  = 30   # Run URL checker if NLP score > this
NLP_THRESHOLD_FOR_DEEP_SCAN  = 60   # Run threat DB only if NLP score > this

# UI Action Thresholds
SUSPICIOUS_THRESHOLD = 30  # Show Orange Popup
DANGER_THRESHOLD     = 60  # Connect to warning.html


# ════════════════════════════════════════════════════════════════
#  MAIN AGENT FUNCTION
# ════════════════════════════════════════════════════════════════
def run_agent(text: str, nlp_result: dict) -> dict:
    """
    Main Agent Function — chains all tools and returns full analysis.

    Parameters
    ----------
    text       : str   — raw input text from user / Chrome extension
    nlp_result : dict  — output from nlp/predict.py
    """

    # ── Extract NLP values ────────────────────────────────────────
    nlp_score     = nlp_result.get("score", 0)
    nlp_label     = nlp_result.get("label", "unknown")
    trigger_words = nlp_result.get("trigger_words", [])

    print(f"\n[Agent] ── Starting Analysis ─────────────────────────")
    print(f"[Agent] NLP Score    : {nlp_score}/100")

    tools_called = ["NLP Engine"]

    # ── Default empty results (used if tools are skipped) ────────
    url_result = {
        "urls_found"    : [],
        "url_count"     : 0,
        "suspicious_urls": [],
        "trusted_urls"  : [],
        "tricks_detected": [],
        "url_risk_score": 0,
        "summary"       : "No URLs found in text"
    }

    domain_result = {
        "checked"            : [],
        "worst_risk"         : "SAFE",
        "max_domain_age_score": 0,
        "flags"              : [],
        "summary"            : "Domain check skipped"
    }

    threat_result = {
        "checked_domains" : [],
        "total_reports"   : 0,
        "max_threat_score": 0,
        "worst_risk"      : "SAFE",
        "flags"           : [],
        "summary"         : "Threat DB skipped"
    }

    # ════════════════════════════════════════════════════════════
    #  TOOL 1 — URL CHECKER
    # ════════════════════════════════════════════════════════════
    has_url_hint = any(
        x in text.lower()
        for x in ["http", "www.", ".com", ".in", ".org",
                  ".net", ".xyz", ".top", ".site", ".online"]
    )

    if nlp_score > NLP_THRESHOLD_FOR_URL_CHECK or has_url_hint:
        print("[Agent] → Running URL Checker...")
        url_result   = analyze_urls(text)
        tools_called.append("url_checker")

    # ════════════════════════════════════════════════════════════
    #  TOOL 2 — DOMAIN AGE CHECKER
    # ════════════════════════════════════════════════════════════
    urls_to_check = url_result.get("suspicious_urls") or url_result.get("urls_found", [])

    if urls_to_check:
        print(f"[Agent] → Running Domain Age check...")
        domain_result = check_multiple_domains(urls_to_check)
        tools_called.append("domain_age_checker")

    # ════════════════════════════════════════════════════════════
    #  TOOL 3 — THREAT DATABASE CHECKER
    # ════════════════════════════════════════════════════════════
    if url_result["url_count"] > 0 and nlp_score > NLP_THRESHOLD_FOR_DEEP_SCAN:
        print("[Agent] → Running Threat Database check...")
        threat_result = check_multiple_urls(url_result["urls_found"])
        tools_called.append("threat_db_checker")

    # ════════════════════════════════════════════════════════════
    #  TOOL 4 — SCORE COMBINER
    # ════════════════════════════════════════════════════════════
    nlp_boost = 40 if (url_result["url_count"] == 0 and nlp_score >= 70) else 0
    
    combined = combine_scores(
        nlp_score        = nlp_score + nlp_boost,
        url_risk_score   = url_result["url_risk_score"],
        domain_age_score = domain_result["max_domain_age_score"],
        threat_db_score  = threat_result["max_threat_score"],
        original_text    = text
    )

    # ════════════════════════════════════════════════════════════
    #  UPDATED UI LOGIC & ACTION OVERRIDES
    # ════════════════════════════════════════════════════════════
    final_score = combined['final_score']
    
    # CASE 1: DANGER (Red Popup + warning.html redirect)
    if final_score >= DANGER_THRESHOLD:
        action = "BLOCK"
        risk_label = "DANGER"
        badge_color = "red"
        ui_action = "REDIRECT_WARNING"
        status_text = "DANGEROUS PAGE"

    # CASE 2: SUSPICIOUS (Orange Popup)
    elif final_score >= SUSPICIOUS_THRESHOLD:
        action = "WARN"
        risk_label = "SUSPICIOUS"
        badge_color = "orange"
        ui_action = "SHOW_POPUP"
        status_text = "SUSPICIOUS PAGE"

    # CASE 3: SAFE (Green Header)
    else:
        action = "ALLOW"
        risk_label = "SAFE"
        badge_color = "green"
        ui_action = "NONE"
        status_text = "PAGE IS SAFE"

    # ════════════════════════════════════════════════════════════
    #  TOOL 5 — GEMINI EXPLAINER
    # ════════════════════════════════════════════════════════════
    print("[Agent] → Generating Gemini explanation...")
    tools_called.append("gemini_explainer")

    domain_flag_text = domain_result["flags"][0] if domain_result["flags"] else "Clear"
    threat_flag_text = threat_result["flags"][0] if threat_result["flags"] else "Safe"

    gemini_input = {
        **combined,
        "original_text"  : text,
        "urls_found"     : url_result["urls_found"],
        "tricks_detected": url_result["tricks_detected"],
        "domain_flag"    : domain_flag_text,
        "threat_flag"    : threat_flag_text,
        "trigger_words"  : trigger_words,
        "threat_reports" : threat_result["total_reports"],
    }

    gemini_result = generate_explanation(gemini_input)

    # ════════════════════════════════════════════════════════════
    #  FINAL RESULT BUNDLE
    # ════════════════════════════════════════════════════════════
    final_result = {
        "final_score"  : final_score,
        "action"       : action,
        "risk_label"   : risk_label,
        "badge_color"  : badge_color,
        "ui_action"    : ui_action,
        "status_text"  : status_text,
        "category"     : combined.get("category", nlp_label.capitalize()),

        "nlp_score"    : nlp_score,
        "trigger_words": trigger_words,

        "urls_found"      : url_result["urls_found"],
        "suspicious_urls" : url_result["suspicious_urls"],
        "tricks_detected" : url_result["tricks_detected"],

        "domain_flag"     : domain_flag_text,
        "threat_reports"  : threat_result["total_reports"],

        "explanation"        : gemini_result["explanation"],
        "explanation_source" : gemini_result.get("source", "ai"),

        "tools_called": tools_called,
        "summary"     : f"Score: {final_score}/100 | Action: {action} | UI: {ui_action}"
    }

    print(f"[Agent] ✅ Finished. Score={final_score} Action={action}")
    return final_result


# ════════════════════════════════════════════════════════════════
#  SELF TEST
# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("--- Running Logic Tests ---")
    # Test for Orange (Suspicious)
    test_nlp = {"score": 35.0, "label": "phishing"}
    res = run_agent("Check this out", test_nlp)
    print(f"Result for 35: {res['badge_color']} ({res['status_text']})")

    # Test for Red (Danger)
    test_nlp_2 = {"score": 64.0, "label": "phishing"}
    res_2 = run_agent("URGENT: BANK BLOCKED", test_nlp_2)
    print(f"Result for 64: {res_2['badge_color']} ({res_2['status_text']})")