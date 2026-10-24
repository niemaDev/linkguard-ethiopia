#!/usr/bin/env python3
"""
LinkGuard Ethiopia — Batch dataset tester
-------------------------------------------
Usage:
    python3 batch_test.py

What it does:
  1. Reads every URL from bad_urls.txt (label: BAD) and good_urls.txt (label: GOOD)
  2. Checks each one against VirusTotal, respecting the free-tier rate limit
  3. Prints a per-URL result and a final accuracy summary
     (how many bad URLs were correctly flagged, how many good URLs
     were incorrectly flagged — i.e. false positives)
"""

import base64
import os
import sys
import time
import requests

PROJECT_DIR = os.path.expanduser("~/linkguard-ethiopia")
KEYS_FILE = os.path.join(PROJECT_DIR, "linkguard-keys.txt")
BAD_URLS_FILE = os.path.join(PROJECT_DIR, "bad_urls.txt")
GOOD_URLS_FILE = os.path.join(PROJECT_DIR, "good_urls.txt")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Free tier: 4 requests/minute. 16 seconds between calls keeps us safely under that.
SECONDS_BETWEEN_REQUESTS = 16


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


def load_url_list(path):
    if not os.path.exists(path):
        print(f"Warning: {path} not found, skipping.")
        return []
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def url_to_vt_id(url):
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def check_url(url, headers):
    url_id = url_to_vt_id(url)
    resp = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)

    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        flags = stats["malicious"] + stats["suspicious"]
        return {"status": "checked", "flags": flags, "stats": stats}

    elif resp.status_code == 404:
        requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url})
        return {"status": "submitted"}

    else:
        return {"status": "error", "code": resp.status_code, "text": resp.text}


def main():
    keys = load_keys(KEYS_FILE)
    api_key = keys.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("VIRUSTOTAL_API_KEY not found in keys file.")
        sys.exit(1)
    headers = {"x-apikey": api_key}

    bad_urls = [(url, "BAD") for url in load_url_list(BAD_URLS_FILE)]
    good_urls = [(url, "GOOD") for url in load_url_list(GOOD_URLS_FILE)]
    all_urls = bad_urls + good_urls

    if not all_urls:
        print("No URLs found in bad_urls.txt or good_urls.txt.")
        sys.exit(1)

    print(f"Testing {len(all_urls)} URLs ({len(bad_urls)} bad, {len(good_urls)} good)")
    print(f"Pausing {SECONDS_BETWEEN_REQUESTS}s between requests to respect the free API rate limit.\n")

    results = []

    for i, (url, label) in enumerate(all_urls, start=1):
        print(f"[{i}/{len(all_urls)}] ({label}) {url}")
        result = check_url(url, headers)

        if result["status"] == "checked":
            flags = result["flags"]
            verdict = "FLAGGED" if flags > 0 else "clean"
            print(f"    -> {flags} engines flagged it. Verdict: {verdict}")
            results.append({"url": url, "label": label, "flags": flags, "verdict": verdict})

        elif result["status"] == "submitted":
            print("    -> Not seen before, submitted for scanning (skipped this run).")
            results.append({"url": url, "label": label, "flags": None, "verdict": "submitted"})

        else:
            print(f"    -> Error {result['code']}: {result['text'][:100]}")
            results.append({"url": url, "label": label, "flags": None, "verdict": "error"})

        if i < len(all_urls):
            time.sleep(SECONDS_BETWEEN_REQUESTS)
            print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)

    checked = [r for r in results if r["verdict"] in ("FLAGGED", "clean")]
    bad_checked = [r for r in checked if r["label"] == "BAD"]
    good_checked = [r for r in checked if r["label"] == "GOOD"]

    bad_detected = [r for r in bad_checked if r["verdict"] == "FLAGGED"]
    good_false_positives = [r for r in good_checked if r["verdict"] == "FLAGGED"]

    print(f"Bad URLs correctly detected:   {len(bad_detected)}/{len(bad_checked)}")
    print(f"Good URLs falsely flagged:     {len(good_false_positives)}/{len(good_checked)}")

    submitted = [r for r in results if r["verdict"] == "submitted"]
    if submitted:
        print(f"\n{len(submitted)} URL(s) were new to VirusTotal and submitted for scanning.")
        print("Run this script again in a minute or two to get their results.")

    if good_false_positives:
        print("\nFalse positives (legit sites incorrectly flagged):")
        for r in good_false_positives:
            print(f"  - {r['url']} ({r['flags']} engines)")



if __name__ == "__main__":
 main()
