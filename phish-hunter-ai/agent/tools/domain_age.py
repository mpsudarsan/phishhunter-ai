"""
domain_age.py
-------------
Checks how old a domain is using the whois library.
Flags domains newer than 30 days as HIGH DANGER.
Part of PhishHunter AI — Agent Tools Layer
"""

import re
from datetime import datetime, timezone


def get_domain(url: str) -> str:
    """Extract root domain from a URL or raw domain string."""
    domain = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
    domain = domain.split('/')[0].split(':')[0].lower().strip()
    return domain


def get_domain_age_days(domain: str) -> dict:
    """
    Query whois for domain creation date.
    Returns age in days and risk assessment.
    """
    try:
        import whois  # pip install python-whois
        w = whois.whois(domain)

        creation_date = w.creation_date

        # whois sometimes returns a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {
                "domain": domain,
                "creation_date": None,
                "age_days": None,
                "risk_level": "UNKNOWN",
                "domain_age_score": 15,  # Moderate risk if can't verify
                "flag": "⚠️ Cannot verify domain age — treat with caution",
                "error": None
            }

        # Make timezone-aware for comparison
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        # Risk scoring based on age
        if age_days <= 7:
            risk_level = "CRITICAL"
            domain_age_score = 30
            flag = f"🚨 CRITICAL — Domain only {age_days} day(s) old! Brand new domain = phishing"
        elif age_days <= 30:
            risk_level = "HIGH"
            domain_age_score = 25
            flag = f"🔴 HIGH — Domain is {age_days} days old — very suspicious"
        elif age_days <= 90:
            risk_level = "MEDIUM"
            domain_age_score = 15
            flag = f"🟡 MEDIUM — Domain is {age_days} days old — relatively new"
        elif age_days <= 365:
            risk_level = "LOW"
            domain_age_score = 5
            flag = f"🟢 LOW — Domain is {age_days} days old — acceptable age"
        else:
            risk_level = "SAFE"
            domain_age_score = 0
            flag = f"✅ SAFE — Domain is {age_days} days ({age_days // 365} year(s)) old"

        return {
            "domain": domain,
            "creation_date": creation_date.strftime("%Y-%m-%d"),
            "age_days": age_days,
            "risk_level": risk_level,
            "domain_age_score": domain_age_score,
            "flag": flag,
            "error": None
        }

    except ImportError:
        # whois not installed — return simulated result for testing
        return _simulate_whois(domain)

    except Exception as e:
        return {
            "domain": domain,
            "creation_date": None,
            "age_days": None,
            "risk_level": "UNKNOWN",
            "domain_age_score": 10,
            "flag": f"⚠️ Could not check domain age: {str(e)[:60]}",
            "error": str(e)
        }


def _simulate_whois(domain: str) -> dict:
    """
    Fallback simulation when python-whois is not installed.
    Used during development/testing.
    """
    # Known suspicious patterns → simulate new domain
    suspicious_signals = [
        '.xyz', '.top', '.tk', '.ml', '.ga', '.cf',
        'verify', 'secure', 'login', 'update', 'claim',
        'winner', 'prize', 'lucky', 'free', 'reward'
    ]
    is_suspicious = any(sig in domain.lower() for sig in suspicious_signals)

    if is_suspicious:
        age_days = 3
        return {
            "domain": domain,
            "creation_date": "2025-03-21",  # simulated
            "age_days": age_days,
            "risk_level": "CRITICAL",
            "domain_age_score": 30,
            "flag": f"🚨 CRITICAL (simulated) — Domain only {age_days} days old",
            "error": "python-whois not installed — using simulation"
        }
    else:
        age_days = 1825  # 5 years
        return {
            "domain": domain,
            "creation_date": "2020-01-01",  # simulated
            "age_days": age_days,
            "risk_level": "SAFE",
            "domain_age_score": 0,
            "flag": f"✅ SAFE (simulated) — Established domain",
            "error": "python-whois not installed — using simulation"
        }


def check_multiple_domains(urls: list[str]) -> dict:
    """
    Check age of all domains from a list of URLs.
    Returns the worst (highest risk) result.
    """
    if not urls:
        return {
            "checked": [],
            "worst_risk": "SAFE",
            "max_domain_age_score": 0,
            "flags": [],
            "summary": "No URLs to check"
        }

    results = []
    for url in urls:
        domain = get_domain(url)
        result = get_domain_age_days(domain)
        results.append(result)

    # Get worst result
    max_score = max(r["domain_age_score"] for r in results)
    worst = next(r for r in results if r["domain_age_score"] == max_score)

    return {
        "checked": results,
        "worst_risk": worst["risk_level"],
        "max_domain_age_score": max_score,
        "flags": [r["flag"] for r in results],
        "summary": f"Checked {len(results)} domain(s) — worst risk: {worst['risk_level']}"
    }


# ── Quick self-test ──────────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "http://sbi-verify.xyz/login",
        "https://www.google.com",
        "http://lucky-winner-claim.top/prize",
        "https://hdfcbank.com/netbanking"
    ]

    print("=" * 50)
    print("DOMAIN AGE CHECKER — SELF TEST")
    print("=" * 50)

    for url in test_urls:
        domain = get_domain(url)
        print(f"\nDomain: {domain}")
        result = get_domain_age_days(domain)
        print(f"  Created      : {result['creation_date']}")
        print(f"  Age (days)   : {result['age_days']}")
        print(f"  Risk Level   : {result['risk_level']}")
        print(f"  Score (+pts) : {result['domain_age_score']}/30")
        print(f"  Flag         : {result['flag']}")

    print("\n" + "=" * 50)
    print("MULTI-DOMAIN CHECK")
    print("=" * 50)
    multi = check_multiple_domains(test_urls)
    print(f"Worst Risk     : {multi['worst_risk']}")
    print(f"Max Score      : {multi['max_domain_age_score']}")
    print(f"Summary        : {multi['summary']}")