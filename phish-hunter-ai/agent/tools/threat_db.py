"""
threat_db.py
------------
Searches the local PhishTank CSV database for known malicious URLs/domains.
Part of PhishHunter AI — Agent Tools Layer

PhishTank CSV download: https://phishtank.org/developer_info.php
Expected file: phishtank_db.csv (place in agent/tools/ folder)
"""

import csv
import os
import re

# Path to PhishTank CSV — place in same folder as this file
DB_PATH = os.path.join(os.path.dirname(__file__), "phishtank_db.csv")

# In-memory cache so we don't re-read CSV on every call
_THREAT_CACHE: dict[str, int] = {}  # domain → report count
_CACHE_LOADED = False


def get_domain(url: str) -> str:
    """Extract root domain from URL."""
    domain = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
    domain = domain.split('/')[0].split(':')[0].lower().strip()
    # Remove www.
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain


def load_threat_database() -> bool:
    """
    Load PhishTank CSV into memory cache.
    Returns True if loaded successfully, False if file not found.
    """
    global _THREAT_CACHE, _CACHE_LOADED

    if _CACHE_LOADED:
        return True

    if not os.path.exists(DB_PATH):
        # Use built-in sample database for demo/testing
        _load_sample_database()
        _CACHE_LOADED = True
        return False  # File not found — using sample

    try:
        with open(DB_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # PhishTank CSV columns: phish_id, url, phish_detail_url,
                #                        submission_time, verified, verification_time,
                #                        online, target
                url = row.get('url', '') or row.get('URL', '')
                if url:
                    domain = get_domain(url)
                    _THREAT_CACHE[domain] = _THREAT_CACHE.get(domain, 0) + 1

        _CACHE_LOADED = True
        return True

    except Exception as e:
        print(f"[threat_db] Warning: Could not load PhishTank CSV: {e}")
        _load_sample_database()
        _CACHE_LOADED = True
        return False


def _load_sample_database():
    """
    Built-in sample threat database for demo when PhishTank CSV not present.
    Contains common phishing domain patterns.
    """
    global _THREAT_CACHE

    sample_threats = {
        # Banking phishing
        "sbi-verify.xyz": 412,
        "sbi-alert-secure.com": 289,
        "hdfc-update-now.top": 176,
        "icici-kyc-verify.site": 203,
        "axisbank-login.xyz": 134,
        "paytm-reward-claim.online": 98,

        # Popular service phishing
        "amazon-prize-winner.top": 321,
        "flipkart-offer-claim.xyz": 187,
        "google-account-verify.site": 445,
        "netflix-billing-update.top": 267,
        "whatsapp-gold-download.info": 389,

        # Indian scam patterns
        "pm-kisan-subsidy-claim.xyz": 156,
        "aadhaar-update-urgent.top": 234,
        "epfo-withdraw-now.site": 145,
        "jio-free-recharge-claim.online": 312,
        "bsnl-lucky-draw.xyz": 99,

        # Generic phishing
        "lucky-winner-claim.top": 567,
        "free-gift-reward.xyz": 432,
        "verify-account-now.site": 298,
        "secure-login-update.online": 341,
        "account-suspended-fix.top": 278,
    }

    _THREAT_CACHE.update(sample_threats)


def search_domain(domain: str) -> dict:
    """
    Search for a domain in the threat database.
    Returns report count and risk assessment.
    """
    load_threat_database()

    # Clean domain
    domain = domain.lower().strip()
    if domain.startswith('www.'):
        domain = domain[4:]

    # Exact match
    report_count = _THREAT_CACHE.get(domain, 0)

    # Partial match — check if domain contains any known threat domain
    partial_matches = []
    if report_count == 0:
        for threat_domain, count in _THREAT_CACHE.items():
            if threat_domain in domain or domain in threat_domain:
                if threat_domain != domain:
                    partial_matches.append((threat_domain, count))

    # Score based on report count
    if report_count >= 200:
        risk_level = "CRITICAL"
        threat_score = 30
        flag = f"🚨 CRITICAL — {report_count} PhishTank reports for this domain"
    elif report_count >= 50:
        risk_level = "HIGH"
        threat_score = 22
        flag = f"🔴 HIGH — {report_count} PhishTank reports — confirmed phishing"
    elif report_count >= 10:
        risk_level = "MEDIUM"
        threat_score = 14
        flag = f"🟡 MEDIUM — {report_count} PhishTank reports"
    elif report_count > 0:
        risk_level = "LOW"
        threat_score = 7
        flag = f"⚠️ LOW — {report_count} report(s) in threat database"
    elif partial_matches:
        # Similar domain found
        best_match = max(partial_matches, key=lambda x: x[1])
        risk_level = "SUSPICIOUS"
        threat_score = 12
        flag = f"⚠️ SUSPICIOUS — Similar to known threat: {best_match[0]} ({best_match[1]} reports)"
    else:
        risk_level = "NOT_FOUND"
        threat_score = 0
        flag = "✅ Not found in threat database"

    return {
        "domain": domain,
        "report_count": report_count,
        "partial_matches": [m[0] for m in partial_matches[:3]],
        "risk_level": risk_level,
        "threat_score": threat_score,
        "flag": flag,
        "database_size": len(_THREAT_CACHE)
    }


def check_multiple_urls(urls: list[str]) -> dict:
    """
    Check all URLs from a list against the threat database.
    Returns combined results.
    """
    if not urls:
        return {
            "checked_domains": [],
            "total_reports": 0,
            "max_threat_score": 0,
            "worst_risk": "SAFE",
            "flags": [],
            "summary": "No URLs to check"
        }

    results = []
    for url in urls:
        domain = get_domain(url)
        result = search_domain(domain)
        results.append(result)

    total_reports = sum(r["report_count"] for r in results)
    max_score = max(r["threat_score"] for r in results)
    worst = next(r for r in results if r["threat_score"] == max_score)

    return {
        "checked_domains": [r["domain"] for r in results],
        "total_reports": total_reports,
        "max_threat_score": max_score,
        "worst_risk": worst["risk_level"],
        "flags": [r["flag"] for r in results],
        "details": results,
        "summary": f"Checked {len(results)} domain(s) — {total_reports} total threat reports found"
    }


def get_database_stats() -> dict:
    """Return stats about the loaded threat database."""
    load_threat_database()
    return {
        "total_domains": len(_THREAT_CACHE),
        "database_file": DB_PATH,
        "file_exists": os.path.exists(DB_PATH),
        "using_sample": not os.path.exists(DB_PATH)
    }


# ── Quick self-test ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("THREAT DATABASE CHECKER — SELF TEST")
    print("=" * 55)

    stats = get_database_stats()
    print(f"\nDatabase: {'PhishTank CSV' if stats['file_exists'] else 'Sample (built-in)'}")
    print(f"Entries : {stats['total_domains']} domains loaded")

    test_urls = [
        "http://sbi-verify.xyz/login",
        "http://lucky-winner-claim.top/prize",
        "https://www.google.com",
        "https://hdfcbank.com",
        "http://amazon-prize-winner.top/claim",
        "https://zomato.com/order"
    ]

    print("\n" + "-" * 55)
    for url in test_urls:
        domain = get_domain(url)
        result = search_domain(domain)
        print(f"\nDomain  : {domain}")
        print(f"Reports : {result['report_count']}")
        print(f"Risk    : {result['risk_level']}")
        print(f"Score   : {result['threat_score']}/30")
        print(f"Flag    : {result['flag']}")

    print("\n" + "=" * 55)
    print("MULTI-URL CHECK")
    multi = check_multiple_urls(test_urls)
    print(f"Total Reports : {multi['total_reports']}")
    print(f"Worst Risk    : {multi['worst_risk']}")
    print(f"Max Score     : {multi['max_threat_score']}")
    print(f"Summary       : {multi['summary']}")