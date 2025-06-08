import requests
import validators
import tldextract
import whois
from datetime import datetime

# Optional: Add your VirusTotal API key here
VT_API_KEY = 'your_virustotal_api_key'

# List of suspicious keywords
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'bank', 'free', 'security', 'account']

# List of known URL shorteners
SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly']

def is_valid_url(url):
    return validators.url(url)

def has_suspicious_keywords(url):
    return any(word in url.lower() for word in SUSPICIOUS_KEYWORDS)

def is_shortened_url(url):
    domain = tldextract.extract(url).registered_domain
    return domain in SHORTENERS

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return None
        today = datetime.now()
        age = (today - creation_date).days
        return age
    except Exception:
        return None

def check_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}
        params = {'url': url}
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
        if response.status_code == 200:
            url_id = response.json()["data"]["id"]
            analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers).json()
            stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
            return stats
        else:
            return None
    except Exception as e:
        print(f"VirusTotal error: {e}")
        return None

def analyze_url(url):
    if not is_valid_url(url):
        return "❌ Invalid URL"

    result = {"url": url}

    result['shortened'] = is_shortened_url(url)
    result['suspicious_keywords'] = has_suspicious_keywords(url)

    domain = tldextract.extract(url).registered_domain
    age = get_domain_age(domain)
    result['domain_age_days'] = age

    vt_result = check_virustotal(url)
    result['virustotal'] = vt_result

    # Simple scoring logic
    score = 0
    if result['shortened']: score += 1
    if result['suspicious_keywords']: score += 1
    if age is not None and age < 180: score += 1
    if vt_result and vt_result.get('malicious', 0) > 0: score += 2

    result['verdict'] = "⚠️ Suspicious" if score >= 2 else "✅ Looks Safe"
    return result

# 🧪 Example usage
if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ").strip()
    report = analyze_url(test_url)
    
    if isinstance(report, dict):
        for k, v in report.items():
            print(f"{k.capitalize()}: {v}")
    else:
        print(report)
