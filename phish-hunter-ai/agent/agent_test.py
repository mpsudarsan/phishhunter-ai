"""
agent_test.py
-------------
Complete end-to-end test for PhishHunter AI Agent.
Tests 5 phishing + 3 safe SMS samples.
Run this at Hour 20 to verify your module is working.
Part of PhishHunter AI — Testing
"""

import sys
import os
import time

# ── Path setup ───────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from agent_controller import run_agent

# ── Test Cases ───────────────────────────────────────────────────
# NLP results are simulated here (replace with real predict.py output)
# Once Member 2 hands over predict.py, update to:
#   from predict import predict_phishing
#   nlp_result = predict_phishing(text)

TEST_CASES = [
    # ── PHISHING CASES (should score HIGH and return BLOCK/WARN) ─
    {
        "id":          1,
        "type":        "PHISHING",
        "description": "Bank fraud — SBI impersonation with suspicious URL",
        "text":        "URGENT: Your SBI account has been blocked due to KYC non-compliance. Click http://sbi-verify.xyz/login now to avoid permanent suspension!",
        "nlp_result":  {"score": 87, "label": "phishing", "trigger_words": ["urgent", "blocked", "kyc", "click", "suspension"]},
        "expected_action": "BLOCK",
        "expected_min_score": 70
    },
    {
        "id":          2,
        "type":        "PHISHING",
        "description": "Lottery scam — fake prize claim",
        "text":        "Congratulations! You have been selected as the lucky winner of Rs 50,000 in our Diwali lucky draw. Visit www.lucky-winner-claim.top/prize to claim your reward now!",
        "nlp_result":  {"score": 79, "label": "phishing", "trigger_words": ["congratulations", "winner", "lucky", "claim", "reward"]},
        "expected_action": "BLOCK",
        "expected_min_score": 65
    },
    {
        "id":          3,
        "type":        "PHISHING",
        "description": "Government impersonation — Aadhaar fraud",
        "text":        "Alert: Your Aadhaar card will be blocked in 24 hours. Update your details immediately at http://aadhaar-update-urgent.top/verify to keep it active.",
        "nlp_result":  {"score": 83, "label": "phishing", "trigger_words": ["alert", "blocked", "immediately", "verify", "aadhaar"]},
        "expected_action": "BLOCK",
        "expected_min_score": 70
    },
    {
        "id":          4,
        "type":        "PHISHING",
        "description": "Job scam — fake work from home offer",
        "text":        "Dear applicant, you are selected for our work from home job. Earn Rs 5000 daily. Register now at http://online-job-apply.site/register. Limited seats!",
        "nlp_result":  {"score": 71, "label": "phishing", "trigger_words": ["selected", "earn", "register", "limited"]},
        "expected_action": "WARN",
        "expected_min_score": 40
    },
    {
        "id":          5,
        "type":        "PHISHING",
        "description": "OTP phishing — fake bank security alert",
        "text":        "Dear Customer, your HDFC Debit Card is temporarily blocked. Share your OTP 7823 to restore access. Call 1800-FAKE-HDFC immediately.",
        "nlp_result":  {"score": 76, "label": "phishing", "trigger_words": ["dear customer", "blocked", "share", "otp", "immediately"]},
        "expected_action": "WARN",
        "expected_min_score": 35
    },

    # ── SAFE CASES (should score LOW and return SAFE) ────────────
    {
        "id":          6,
        "type":        "SAFE",
        "description": "Legitimate OTP — Zomato",
        "text":        "Your Zomato OTP is 492810. Valid for 10 minutes. Do not share this OTP with anyone.",
        "nlp_result":  {"score": 9, "label": "safe", "trigger_words": []},
        "expected_action": "SAFE",
        "expected_max_score": 35
    },
    {
        "id":          7,
        "type":        "SAFE",
        "description": "Legitimate Google Meet link",
        "text":        "Hi team, please join the project review meeting: https://meet.google.com/abc-xyz-123 at 3 PM today.",
        "nlp_result":  {"score": 5, "label": "safe", "trigger_words": []},
        "expected_action": "SAFE",
        "expected_max_score": 30
    },
    {
        "id":          8,
        "type":        "SAFE",
        "description": "Legitimate delivery update — Amazon",
        "text":        "Your Amazon order #405-1234567 has been shipped. Track at amazon.com/orders. Expected delivery: tomorrow by 9 PM.",
        "nlp_result":  {"score": 12, "label": "safe", "trigger_words": []},
        "expected_action": "SAFE",
        "expected_max_score": 40
    },
]


# ── Test Runner ───────────────────────────────────────────────────
def run_all_tests():
    """Run all test cases and print results."""
    print("\n" + "=" * 65)
    print("  PHISHUNTER AI — AGENT END-TO-END TEST")
    print("  PS ID: TUAH4818S | Leader Module Test")
    print("=" * 65)

    passed = 0
    failed = 0
    results_log = []

    for case in TEST_CASES:
        print(f"\n{'─'*65}")
        print(f"TEST {case['id']} [{case['type']}] — {case['description']}")
        print(f"INPUT: \"{case['text'][:80]}...\"" if len(case['text']) > 80 else f"INPUT: \"{case['text']}\"")
        print(f"NLP Input: score={case['nlp_result']['score']}, label={case['nlp_result']['label']}")
        print("─" * 65)

        start_time = time.time()

        try:
            result = run_agent(case["text"], case["nlp_result"])
            elapsed = round(time.time() - start_time, 2)

            final_score = result["final_score"]
            action      = result["action"]
            badge       = result["badge_color"]
            tools       = result["tools_called"]

            # ── Check pass/fail ──────────────────────────────────
            test_passed = True
            fail_reason = ""

            if case["type"] == "PHISHING":
                if final_score < case["expected_min_score"]:
                    test_passed = False
                    fail_reason = f"Score {final_score} < expected min {case['expected_min_score']}"
                elif action != case["expected_action"]:
                    test_passed = False
                    fail_reason = f"Action '{action}' != expected '{case['expected_action']}'"
            else:  # SAFE
                if final_score > case["expected_max_score"]:
                    test_passed = False
                    fail_reason = f"Score {final_score} > expected max {case['expected_max_score']}"
                elif action != case["expected_action"]:
                    test_passed = False
                    fail_reason = f"Action '{action}' != expected '{case['expected_action']}'"

            # ── Print result ─────────────────────────────────────
            status = "✅ PASS" if test_passed else "❌ FAIL"
            print(f"[Tool 1] URLs found     → {result['urls_found'] or 'None'}")
            print(f"[Tool 2] Domain check   → {result.get('domain_flag') or 'Skipped'}")
            print(f"[Tool 3] Threat reports → {result.get('threat_reports', 0)}")
            print(f"[Tool 4] Final score    → {final_score} / 100")
            print(f"[Gemini] Source         → {result.get('explanation_source', 'unknown')}")
            print(f"─" * 65)
            print(f"RESULT      : {result['risk_label']}")
            print(f"ACTION      : {action}")
            print(f"BADGE       : {badge}")
            print(f"CATEGORY    : {result['category'].replace('_', ' ').title()}")
            print(f"TOOLS USED  : {', '.join(tools)}")
            print(f"TIME        : {elapsed}s")
            print(f"EXPLANATION : {result['explanation']}")
            print(f"─" * 65)
            print(f"{status} {f'— FAILED: {fail_reason}' if not test_passed else ''}")

            if test_passed:
                passed += 1
            else:
                failed += 1

            results_log.append({
                "id":           case["id"],
                "type":         case["type"],
                "description":  case["description"],
                "score":        final_score,
                "action":       action,
                "passed":       test_passed,
                "fail_reason":  fail_reason,
                "time":         elapsed
            })

        except Exception as e:
            print(f"❌ EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  FINAL TEST SUMMARY")
    print("=" * 65)
    print(f"  Total Tests : {len(TEST_CASES)}")
    print(f"  ✅ Passed   : {passed}")
    print(f"  ❌ Failed   : {failed}")
    print(f"  Pass Rate   : {round(passed/len(TEST_CASES)*100)}%")
    print("─" * 65)
    print("  SCORE OVERVIEW:")
    for log in results_log:
        status = "✅" if log["passed"] else "❌"
        print(f"  {status} Test {log['id']} [{log['type']:8}] Score: {log['score']:3}/100 | {log['action']:5} | {log['description'][:35]}")
    print("=" * 65)

    if failed == 0:
        print("\n  🎉 ALL TESTS PASSED — Module ready for integration!")
    else:
        print(f"\n  ⚠️  {failed} test(s) failed — review above and fix before integration")

    return passed, failed


# ── Run ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    run_all_tests()