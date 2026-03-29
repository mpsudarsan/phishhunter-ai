"""
PhishHunter AI — URL Checker Tool
Robust URL extraction and analysis for Agentic AI layer
"""

import re

# ─────────────────────────────────────────────
# Regex Patterns
# ─────────────────────────────────────────────
URL_PATTERN = re.compile(
    r'(https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+)',
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r'\b[\w.-]+\.(?:com|in|org|net|xyz|top|site|online|live|click|pw|tk)\b',
    re.IGNORECASE
)

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.site', '.info',
    '.tk', '.ml', '.ga', '.cf', '.gq', '.icu', '.buzz',
    '.live', '.click', '.link', '.work', '.loan', '.win', '.pw'
}

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'amazon.com', 'flipkart.com',
    'paytm.com', 'phonepe.com', 'sbi.co.in', 'hdfcbank.com',
    'icicibank.com', 'axisbank.com', 'zomato.com', 'swiggy.com',
    'linkedin.com', 'github.com', 'microsoft.com', 'apple.com'
}


# ─────────────────────────────────────────────
# Core Functions
# ─────────────────────────────────────────────
def extract_urls(text: str) -> list[str]:
    """Safely extract all URLs from text. Never returns None."""
    if not isinstance(text, str) or not text.strip():
        return []

    urls = URL_PATTERN.findall(text)
    domains = DOMAIN_PATTERN.findall(text)

    # Convert plain domains to full URLs
    for d in domains:
        if d and not d.startswith(('http://', 'https://')):
            urls.append("http://" + d)

    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    return unique_urls


def get_domain(url: str) -> str:
    """Extract clean domain from URL safely."""
    if not isinstance(url, str) or not url.strip():
        return ""

    # Remove protocol
    domain = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
    # Remove path, query, port
    domain = domain.split('/')[0].split(':')[0].strip()
    return domain.lower()


def check_suspicious_tld(domain: str) -> bool:
    if not domain:
        return False
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


def check_trusted_domain(domain: str) -> bool:
    if not domain:
        return False
    return any(domain == t or domain.endswith('.' + t) for t in TRUSTED_DOMAINS)


def check_url_tricks(url: str) -> list[str]:
    """Detect common phishing tricks in domain."""
    if not url:
        return []

    domain = get_domain(url)
    tricks = []

    if domain.count('-') >= 3:
        tricks.append("Too many hyphens — typical phishing pattern")
    elif domain.count('-') >= 2:
        tricks.append("Multiple hyphens in domain")

    if len(domain) > 35:
        tricks.append("Very long domain name — suspicious")

    if re.search(r'\d{3,}', domain):   # 3 or more consecutive numbers
        tricks.append("Multiple numbers in domain")

    if re.search(r'[a-zA-Z]+\d+[a-zA-Z]+', domain):
        tricks.append("Mixed letters and numbers — phishing style")

    return tricks


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION (Used by Agent)
# ─────────────────────────────────────────────
def analyze_urls(text: str) -> dict:
    """
    Main function called by the agent.
    Returns consistent dictionary structure.
    """
    urls = extract_urls(text)

    if not urls:
        return {
            "urls_found": [],
            "url_count": 0,
            "suspicious_urls": [],
            "trusted_urls": [],
            "tricks_detected": [],
            "url_risk_score": 0,
            "summary": "No URLs found"
        }

    suspicious_urls = []
    trusted_urls = []
    tricks_all = []
    url_risk_score = 0

    for url in urls:
        domain = get_domain(url)

        is_trusted = check_trusted_domain(domain)
        is_suspicious_tld = check_suspicious_tld(domain)
        tricks = check_url_tricks(url)

        if is_trusted:
            trusted_urls.append(url)
            continue

        # Suspicious cases
        if is_suspicious_tld or tricks:
            suspicious_urls.append(url)
            tricks_all.extend(tricks)

            if is_suspicious_tld:
                tricks_all.append(f"Suspicious TLD: {domain}")

        # Force danger for known bad keywords (optional but useful)
        bad_keywords = ["yalla", "shoot", "stream", "free", "live", "verify", "login", "account"]
        if any(kw in domain for kw in bad_keywords):
            suspicious_urls.append(url)
            tricks_all.append(f"Keyword trigger: {domain}")
            url_risk_score = max(url_risk_score, 35)

    # Final scoring
    if suspicious_urls:
        url_risk_score = max(url_risk_score, min(40, len(suspicious_urls) * 18))

    if tricks_all:
        url_risk_score = max(url_risk_score, min(40, len(tricks_all) * 6))

    return {
        "urls_found": urls,
        "url_count": len(urls),
        "suspicious_urls": list(set(suspicious_urls)),
        "trusted_urls": list(set(trusted_urls)),
        "tricks_detected": list(set(tricks_all)),
        "url_risk_score": min(url_risk_score, 40),   # cap contribution at 40
        "summary": f"{len(urls)} URL(s) found — {len(suspicious_urls)} suspicious"
    }