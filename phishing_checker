import re
import urllib.parse

def is_phishing_url(url):
    score = 0
    reasons = []

    # 1. IP address check
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        score += 2
        reasons.append("URL contains IP address instead of domain")

    # 2. @ symbol trick
    if "@" in url:
        score += 2
        reasons.append("Contains @ symbol - possible redirection trick")

    # 3. Too long URL
    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long")

    # 4. Many dots/subdomains
    if url.count('.') > 4:
        score += 1
        reasons.append("Too many dots - suspicious subdomains")

    # 5. Suspicious keywords
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'webscr', 'ebayisapi', 'banking', 'confirm']
    for word in keywords:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains suspicious keyword: {word}")
            break

    # 6. HTTPS check
    if not url.startswith("https"):
        score += 1
        reasons.append("Not using HTTPS")

    # 7. Hyphen in domain
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    if "-" in domain:
        score += 1
        reasons.append("Hyphen in domain name - common in phishing")

    if score >= 3:
        return True, score, reasons
    else:
        return False, score, reasons

print("--- CYBERSECURITY MINI PROJECT: Phishing Link Checker ---")
url = input("Enter URL to check: ").strip()

is_phish, score, reasons = is_phishing_url(url)

print(f"\nURL: {url}")
print(f"Risk Score: {score}/7")

if is_phish:
    print("RESULT: ⚠️ SUSPICIOUS - Possible Phishing Link!")
    print("Reasons:")
    for r in reasons:
        print(f" - {r}")
else:
    print("RESULT: ✅ SAFE - Looks legitimate")
    if reasons:
        print("Minor notes:")
        for r in reasons:
            print(f" - {r}")
