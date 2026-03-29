"""
test_scan.py
------------
PhishHunter AI — Full Pipeline Test Script
Run this from project root to verify everything works.

Usage:
    venv\Scripts\python test_scan.py
"""

import urllib.request
import urllib.error
import json

API_URL = "http://localhost:5000/scan"

TEST_CASES = [
    {
        "label" : "🔴 Bank Phishing SMS",
        "body"  : {
            "text"  : "Your SBI account is BLOCKED! Click http://sbi-secure-verify.xyz to update KYC immediately.",
            "source": "sms"
        }
    },
    {
        "label" : "🔴 Lottery Scam",
        "body"  : {
            "text"  : "Congratulations! You won Rs 1,00,000! Claim at http://lucky-winner.top/claim now!",
            "source": "sms"
        }
    },
    {
        "label" : "🟢 Legitimate OTP",
        "body"  : {
            "text"  : "Your Zomato OTP is 492810. Valid for 10 minutes. Do not share with anyone.",
            "source": "sms"
        }
    },
]


def scan(text, source):
    payload = json.dumps({"text": text, "source": source}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    print("=" * 60)
    print("  PhishHunter AI — Full Pipeline Test")
    print("=" * 60)

    # Check health first
    try:
        health_req = urllib.request.urlopen("http://localhost:5000/health", timeout=5)
        health     = json.loads(health_req.read().decode())
        print(f"\n  API Status : {health.get('status', '?')}")
        print(f"  NLP Model  : {health.get('nlp_model', '?')}")
        print(f"  Gemini AI  : {health.get('gemini', '?')}")
        print()
    except Exception as e:
        print(f"\n  ❌ API not reachable: {e}")
        print("  Make sure agent_api.py is running in the other terminal!")
        return

    # Run each test case
    for i, case in enumerate(TEST_CASES, 1):
        print(f"TEST {i}: {case['label']}")
        print(f"  Input      : {case['body']['text'][:70]}...")

        try:
            result = scan(case["body"]["text"], case["body"]["source"])

            score   = result.get("final_score", "?")
            action  = result.get("action", "?")
            label   = result.get("risk_label", "?")
            source  = result.get("explanation_source", "?")
            explain = result.get("explanation", "?")
            nlp_sc  = result.get("nlp_score", "?")
            urls    = result.get("urls_found", [])
            badge   = result.get("badge_color", "?")
            method  = result.get("nlp_method", "?")

            # Badge emoji
            badge_icon = {"RED": "🔴", "YELLOW": "🟡", "GREEN": "🟢"}.get(badge, "⚪")

            print(f"  NLP Score  : {nlp_sc}/100  ({method})")
            print(f"  Final Score: {score}/100")
            print(f"  Action     : {badge_icon} {action} — {label}")
            print(f"  URLs Found : {urls if urls else 'none'}")
            print(f"  Gemini Src : {source}")
            print(f"  Explanation: {explain[:120]}...")

        except urllib.error.URLError as e:
            print(f"  ❌ Request failed: {e}")
        except Exception as e:
            print(f"  ❌ Error: {e}")

        print("-" * 60)

    print("\n✅ All tests complete!")
    print("   If Gemini Src shows 'gemini-1.5-flash' → real AI is working")
    print("   If Gemini Src shows 'rule-based-fallback' → check your .env key")


if __name__ == "__main__":
    main()