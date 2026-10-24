#!/usr/bin/env python3
"""
LinkGuard Ethiopia — urlscan.io integration
----------------------------------------------
Usage:
    python3 urlscan_check.py https://example.com

What it does:
  1. Submits the URL to urlscan.io for a live sandboxed scan
  2. Waits for the scan to finish (usually 10-20 seconds)
  3. Prints the verdict: malicious/suspicious score, and key indicators

NOTE: Free-tier urlscan.io submissions are PUBLIC. Anyone can see the
scan result and the URL you submitted. Fine for testing known phishing
URLs, but never submit anything sensitive through the free API.
"""

import os
import sys
import time
import requests

PROJECT_DIR = os.path.expanduser("~/linkguard-ethiopia")
KEYS_FILE = os.path.join(PROJECT_DIR, "linkguard-keys.txt")
URLSCAN_BASE = "https://urlscan.io/api/v1"

# How long to wait before checking results, and how many times to retry.
INITIAL_WAIT_SECONDS = 15
POLL_RETRY_SECONDS = 5
MAX_POLL_ATTEMPTS = 6


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


def submit_scan(url, api_key):
    """Submit a URL to urlscan.io for scanning. Returns the scan UUID."""
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {"url": url, "visibility": "public"}

    resp = requests.post(f"{URLSCAN_BASE}/scan/", headers=headers, json=payload)

    if resp.status_code == 200:
        data = resp.json()
        return data["uuid"], data.get("result")
    else:
        print(f"Submission failed: {resp.status_code}")
        print(resp.text)
        return None, None


def fetch_result(scan_uuid, api_key):
    """Poll for the scan result. Returns the result JSON once ready, or None."""
    result_url = f"{URLSCAN_BASE}/result/{scan_uuid}/"

    for attempt in range(MAX_POLL_ATTEMPTS):
        resp = requests.get(result_url, headers={"API-Key": api_key})

        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            # Not ready yet — urlscan is still processing.
            print(f"  Scan still processing, waiting {POLL_RETRY_SECONDS}s...")
            time.sleep(POLL_RETRY_SECONDS)
        else:
            print(f"Unexpected error fetching result: {resp.status_code}")
            return None

    print("Timed out waiting for scan result.")
    return None


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 urlscan_check.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    keys = load_keys(KEYS_FILE)
    api_key = keys.get("URLSCAN_API_KEY")

    if not api_key:
        print("URLSCAN_API_KEY not found in your keys file.")
        sys.exit(1)

    print(f"Submitting to urlscan.io: {target_url}")
    scan_uuid, result_link = submit_scan(target_url, api_key)

    if not scan_uuid:
        sys.exit(1)

    print(f"Scan submitted. UUID: {scan_uuid}")
    if result_link:
        print(f"You can also view this scan in a browser at: {result_link}")

    print(f"Waiting {INITIAL_WAIT_SECONDS}s for the scan to complete...")
    time.sleep(INITIAL_WAIT_SECONDS)

    result = fetch_result(scan_uuid, api_key)
    if not result:
        print("Could not retrieve scan results. Try checking the link above manually.")
        sys.exit(1)

    print("-" * 50)

    verdicts = result.get("verdicts", {}).get("overall", {})
    malicious = verdicts.get("malicious", False)
    score = verdicts.get("score", 0)
    categories = verdicts.get("categories", [])

    page = result.get("page", {})
    final_url = page.get("url", target_url)
    domain = page.get("domain", "unknown")

    print(f"Final landing URL: {final_url}")
    print(f"Domain: {domain}")
    print(f"Malicious verdict: {malicious}")
    print(f"Score: {score}")
    if categories:
        print(f"Categories: {', '.join(categories)}")

    if malicious:
        print("\n⚠️  urlscan.io flagged this as malicious.")
    else:
        print("\n✅  urlscan.io did not flag this as malicious.")


if __name__ == "__main__":
    main()
