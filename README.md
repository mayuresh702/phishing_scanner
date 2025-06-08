# Phishing Link Scanner – Installation & Usage Guide

This Python-based tool helps identify suspicious or phishing URLs. It checks for common indicators like keyword patterns, domain age, shortened URLs, and optionally uses the VirusTotal API for deeper analysis.

## Prerequisites

Make sure you have Python 3.8 or higher installed.

Check your Python version with:

```bash
python3 --version
```

## Step 1: Clone the Repository

```bash
git clone https://github.com/mayuresh702/phishing_scanner.git
cd phishing_scanner
```

## Step 2: Install Required Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```


## Step 3 (Optional): Add VirusTotal API Key

To integrate with VirusTotal:

1. Create an account at [https://www.virustotal.com](https://www.virustotal.com)
2. Get your API key from your account dashboard
3. Open `phishing_scanner.py` and replace the following line:

```python
VT_API_KEY = 'your_virustotal_api_key'
```

## Step 4: Run the Scanner

Run the scanner with:

```bash
python phishing_scanner.py
```

You will be prompted to enter a URL to scan.

## Example

```bash
Enter a URL to scan: http://bit.ly/verify-now
```

## Notes

* Ensure you are connected to the internet while running the scanner.
* WHOIS queries may fail for newly registered or protected domains.
* VirusTotal checks are optional but provide higher accuracy in detecting malicious URLs.
