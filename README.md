# LinkGuard Ethiopia

Scan a suspicious link **before** you click it.

LinkGuard Ethiopia is a small cybersecurity web app that helps people avoid social-engineering scams such as fake online stores, phishing pages and malicious websites. You paste a link, and it returns a **0-100 risk score** with a plain-language list of reasons. Users can also report suspicious links, and a moderator approves reports before they appear on a public list.

> Educational project. Results are a warning sign, not proof. Always use your own judgment.

## Features

- **Link scanning** using three independent sources: VirusTotal, urlscan.io (live scan) and Google Safe Browsing
- **Risk score with reasons**, banded as Safe, Suspicious or Dangerous
- **Unverified result** when a source fails, so a missing check is never shown as a false "Safe"
- **URL cleanup**: the same link always gets the same form, and non-links are rejected
- **Community reporting**, limited to one report per visitor per link
- **Moderated public list** at `/reports`, with links shown defanged (`hxxps://evil[.]com`) so nobody opens them by accident
- **Protected admin area** at `/admin` to approve or reject reports

## How the score works

| Signal | Points |
|---|---|
| VirusTotal engines flagging malicious | 4 each, max 40 |
| VirusTotal engines flagging suspicious | 3 each, max 10 |
| Google Safe Browsing match | +35 |
| urlscan.io malicious verdict | +30 |
| urlscan.io risk score | 20% of it, max 20 |
| Community reports | 5 each, max 25 |

The total is capped at 100. Bands: **0-30 Safe**, **31-60 Suspicious**, **61-100 Dangerous**. Reports on a link a moderator rejected are not counted.

## Security design

- One report per visitor per link, using a salted hash of the IP address (the raw IP is never stored)
- Parameterised SQL queries
- Admin password stored only as a hash, with no default password
- CSRF token on every admin form
- 5 wrong passwords lock a visitor out for 15 minutes
- HttpOnly, SameSite session cookie with a 30-minute lifetime
- Security headers on every page
- `TRUSTED_PROXIES` setting so a forged `X-Forwarded-For` header is ignored unless you run behind a real proxy

## Setup

Requires Python 3 and free API keys from [VirusTotal](https://www.virustotal.com), [urlscan.io](https://urlscan.io) and the [Google Safe Browsing API](https://developers.google.com/safe-browsing).

```
git clone https://github.com/niemaDev/linkguard-ethiopia.git ~/linkguard-ethiopia
cd ~/linkguard-ethiopia
python3 -m venv ~/linkguard-env
source ~/linkguard-env/bin/activate
pip install -r requirements.txt
```

### Keys file

Create `linkguard-keys.txt` in the project folder (it is listed in `.gitignore`, so it is never uploaded). Use one `NAME=value` per line:

```
VIRUSTOTAL_API_KEY=your-key
URLSCAN_API_KEY=your-key
GOOGLE_SAFE_BROWSING_KEY=your-key
REPORT_SALT=any-long-random-string
```

Generate the extra secrets for the admin area:

```
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> linkguard-keys.txt
python3 -c "import getpass; from werkzeug.security import generate_password_hash as g; print('ADMIN_PASSWORD_HASH=' + g(getpass.getpass('Choose an admin password: ')))" >> linkguard-keys.txt
```

Settings are read from environment variables first, then from the keys file. If the admin secrets are missing, the admin area stays disabled.

### Run

```
python3 app.py
```

Open http://127.0.0.1:5000. Moderators log in at http://127.0.0.1:5000/admin. The database tables are created automatically on first start.

## Project files

| File | Purpose |
|---|---|
| `app.py` | Flask web app: scanner, reporting, moderation, admin |
| `vt_check.py` | Check one URL against VirusTotal |
| `urlscan_check.py` | Scan one URL with urlscan.io |
| `linkguard_scan.py` | Command-line scanner that combines the sources |
| `batch_test.py` | Test a list of known-good and known-bad URLs |
| `bad_urls.txt`, `good_urls.txt` | Test datasets |

## Test results

On a 27-URL test set (15 phishing, 12 legitimate), VirusTotal alone detected 15/15 phishing links with 0/12 false positives. The legitimate set contained only well-known sites, so small or obscure legitimate sites still need testing.

## Limitations and next steps

- Free API tiers are rate limited (VirusTotal allows 4 requests per minute)
- The one-report limit is based on IP address, so it is a speed bump, not a guarantee
- The admin lockout counter lives in memory and resets when the server restarts
- Planned: domain age, SSL, redirect and typosquatting checks, plus deployment with debug mode off and a production server

## Safety note

This tool never opens the links it checks on your machine, but only test with links you are comfortable handling, and keep your API keys private.
