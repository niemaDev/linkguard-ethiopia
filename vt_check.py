#!/usr/bin/env python3
"""
LinkGuard Ethiopia — Step 3: First VirusTotal API call
--------------------------------------------------------
Usage:
    python3 vt_check.py https://example.com

What it does:
  1. Reads your VirusTotal API key from ~/linkguard-ethiopia/linkguard-keys.txt
  2. Asks VirusTotal if it has already seen this URL
  3. If yes -> prints how many security engines flagged it as malicious/suspicious
  4. If no  -> submits the URL for a fresh scan and tells you to check back shortly
"""

import base64
import os
import sys
import requests

KEYS_FILE = os.path.expanduser("~/linkguard-ethiopia/linkguard-keys.txt")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def load_keys(path):
    """Parse a simple KEY=VALUE file into a dict."""
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


def url_to_vt_id(url):
    """
    VirusTotal identifies URLs by a URL-safe base64 encoding of the URL,
    with the '=' padding stripped off.
    """
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def check_existing_report(url_id, headers):
    """Ask VirusTotal if this URL has already been scanned before."""
    resp = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)
    return resp


def submit_url_for_scan(url, headers):
    """Submit a new URL to VirusTotal for scanning."""
    resp = requests.post(
        f"{VT_BASE_URL}/urls",
        headers=headers,
        data={"url": url},
    )
    return resp


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 vt_check.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    keys = load_keys(KEYS_FILE)

    api_key = keys.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("VIRUSTOTAL_API_KEY not found in your keys file.")
        sys.exit(1)

    headers = {"x-apikey": api_key}
    url_id = url_to_vt_id(target_url)

    print(f"Checking: {target_url}")
    print("-" * 50)

    resp = check_existing_report(url_id, headers)

    if resp.status_code == 200:
        data = resp.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]

        print("Existing report found on VirusTotal.\n")
        print(f"  Malicious:  {stats['malicious']}")
        print(f"  Suspicious: {stats['suspicious']}")
        print(f"  Harmless:   {stats['harmless']}")
        print(f"  Undetected: {stats['undetected']}")

        total_flags = stats["malicious"] + stats["suspicious"]
        if total_flags > 0:
            print(f"\n⚠️  {total_flags} security engine(s) flagged this URL as risky.")
        else:
            print("\n✅  No engines flagged this URL.")

    elif resp.status_code == 404:
        print("No existing report. Submitting for a fresh scan...")
        submit_resp = submit_url_for_scan(target_url, headers)

        if submit_resp.status_code == 200:
            print("Submitted successfully.")
            print("VirusTotal needs a little time to analyze it.")
            print("Wait ~15-20 seconds, then run this same command again")
            print("to see the results.")
        else:
            print(f"Submission failed: {submit_resp.status_code}")
            print(submit_resp.text)

    else:
        print(f"Unexpected response: {resp.status_code}")
        print(resp.text)


if __name__ == '__main__':
    main()
