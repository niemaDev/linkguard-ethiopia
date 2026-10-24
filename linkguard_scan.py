#!/usr/bin/env python3
"""
LinkGuard Ethiopia — Combined Risk Scoring Engine
----------------------------------------------------
Usage:
    python3 linkguard_scan.py https://example.com

What it does:
  1. Checks the URL against VirusTotal (historical blacklist data)
  2. Checks the URL against urlscan.io (live sandboxed scan)
  3. Combines both into a single 0-100 risk score with a band
     (Safe / Suspicious / Dangerous) and a plain-English explanation

Why combine them: VirusTotal reflects what's been reported over time;
urlscan.io reflects what the page looks like right now. Neither alone
tells the whole story — a URL can be historically flagged but currently
dormant, or brand new and not yet in anyone's blacklist.
"""

import base64
import os
import sys
import time
import requests

PROJECT_DIR = os.path.expanduser("~/linkguard-ethiopia")
KEYS_FILE = os.path.join(PROJECT_DIR, "linkguard-keys.txt")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"

URLSCAN_INITIAL_WAIT = 15
URLSCAN_POLL_RETRY = 5
URLSCAN_MAX_ATTEMPTS = 6


def load_keys(path):
    keys = {}
    if not os.path.exists(path):
        print(f"Keys file not found at {path}")
        sys.exit(1)
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            keys[key.strip()] = value.strip()
    return keys


# ---------- VirusTotal ----------

def url_to_vt_id(url):
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def check_virustotal(url, api_key):
    """Returns dict with malicious/suspicious counts, or None if unavailable."""
    headers = {"x-apikey": api_key}
    url_id = url_to_vt_id(url)
    resp = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)

    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {"available": True, "malicious": stats["malicious"], "suspicious": stats["suspicious"]}

    elif resp.status_code == 404:
        # Submit for next time, but no data available right now.
        requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url})
        return {"available": False, "reason": "not previously seen, submitted for future scans"}

    else:
        return {"available": False, "reason": f"error {resp.status_code}"}


# ---------- urlscan.io ----------

def check_urlscan(url, api_key):
    """Returns dict with malicious flag/score, or None if unavailable."""
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": "public"}

    submit_resp = requests.post(f"{URLSCAN_BASE}/scan/", headers=headers, json=payload)
    if submit_resp.status_code != 200:
        return {"available": False, "reason": f"submission failed ({submit_resp.status_code})"}

    scan_uuid = submit_resp.json()["uuid"]
    time.sleep(URLSCAN_INITIAL_WAIT)

    result_url = f"{URLSCAN_BASE}/result/{scan_uuid}/"
    for _ in range(URLSCAN_MAX_ATTEMPTS):
        resp = requests.get(result_url, headers={"API-Key": api_key})
        if resp.status_code == 200:
            data = resp.json()
            verdicts = data.get("verdicts", {}).get("overall", {})
            return {
                "available": True,
                "malicious": verdicts.get("malicious", False),
                "score": verdicts.get("score", 0),
            }
        elif resp.status_code == 404:
            time.sleep(URLSCAN_POLL_RETRY)
        else:
            return {"available": False, "reason": f"error {resp.status_code}"}

    return {"available": False, "reason": "timed out waiting for scan"}


# ---------- Combined scoring ----------

def compute_risk_score(vt_result, urlscan_result):
    """
    Weighted combination:
      - VirusTotal malicious engines: up to 40 points (historical blacklist signal)
      - VirusTotal suspicious engines: up to 10 points
      - urlscan.io malicious verdict:  30 points (live behavior signal)
      - urlscan.io score:              up to 20 points (scaled from urlscan's 0-100 internal score)
    """
    score = 0
    reasons = []

    if vt_result.get("available"):
        malicious = vt_result["malicious"]
        suspicious = vt_result["suspicious"]

        vt_points = min(malicious * 4, 40)
        score += vt_points
        if malicious > 0:
            reasons.append(f"VirusTotal: {malicious} engine(s) flagged as malicious")

        vt_sus_points = min(suspicious * 3, 10)
        score += vt_sus_points
        if suspicious > 0:
            reasons.append(f"VirusTotal: {suspicious} engine(s) flagged as suspicious")
    else:
        reasons.append(f"VirusTotal: no data available ({vt_result.get('reason', 'unknown')})")

    if urlscan_result.get("available"):
        if urlscan_result["malicious"]:
            score += 30
            reasons.append("urlscan.io: live scan flagged this page as malicious")

        us_score = urlscan_result.get("score", 0)
        us_points = min(int(us_score * 0.2), 20)
        if us_points > 0:
            score += us_points
            reasons.append(f"urlscan.io: risk score {us_score}/100 from live analysis")
        elif not urlscan_result["malicious"]:
            reasons.append("urlscan.io: live scan found nothing suspicious")
    else:
        reasons.append(f"urlscan.io: no data available ({urlscan_result.get('reason', 'unknown')})")

    score = min(score, 100)

    if score <= 30:
        band = "Safe"
    elif score <= 60:
        band = "Suspicious"
    else:
        band = "Dangerous"

    return score, band, reasons


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 linkguard_scan.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    keys = load_keys(KEYS_FILE)

    vt_key = keys.get("VIRUSTOTAL_API_KEY")
    urlscan_key = keys.get("URLSCAN_API_KEY")

    if not vt_key or not urlscan_key:
        print("Missing VIRUSTOTAL_API_KEY or URLSCAN_API_KEY in your keys file.")
        sys.exit(1)

    print(f"Scanning: {target_url}")
    print("=" * 50)

    print("Checking VirusTotal...")
    vt_result = check_virustotal(target_url, vt_key)

    print("Checking urlscan.io (this takes ~15-30 seconds)...")
    urlscan_result = check_urlscan(target_url, urlscan_key)

    score, band, reasons = compute_risk_score(vt_result, urlscan_result)

    print("\n" + "=" * 50)
    print("RESULT")
    print("=" * 50)
    print(f"Risk Score: {score}/100")
    print(f"Verdict: {band}")
    print("\nReasons:")
    for reason in reasons:
        print(f"  - {reason}")


if __name__ == "__main__":
    main()
