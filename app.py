#!/usr/bin/env python3
"""
Usage:
    python3 app.py
    Then open http://127.0.0.1:5000 in a browser.
    Moderators log in at http://127.0.0.1:5000/admin
"""

import base64
import functools
import hashlib
import hmac
import ipaddress
import os
import secrets
import sqlite3
import time
from datetime import timedelta
from urllib.parse import urlsplit

import requests
from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

PROJECT_DIR = os.environ.get("LINKGUARD_DIR", os.path.expanduser("~/linkguard-ethiopia"))
KEYS_FILE = os.path.join(PROJECT_DIR, "linkguard-keys.txt")
DB_FILE = os.path.join(PROJECT_DIR, "linkguard.db")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

URLSCAN_INITIAL_WAIT = 15
URLSCAN_POLL_RETRY = 5
URLSCAN_MAX_ATTEMPTS = 6

MAX_URL_LENGTH = 2048
INVALID_URL_MESSAGE = "That doesn't look like a valid web link. Try something like https://example.com"

REPORTS_PAGE_LIMIT = 100
ADMIN_PAGE_LIMIT = 200

# Admin login protection: too many wrong passwords locks that visitor out for a while.
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60
FAILED_LOGINS = {}


def load_keys(path):
    keys = {}
    if not os.path.exists(path):
        return keys
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            keys[key.strip()] = value.strip()
    return keys


def get_secret(name):
    """Read a secret from an environment variable first (used when deployed), then from the keys file."""
    value = os.environ.get(name)
    if value:
        return value
    return load_keys(KEYS_FILE).get(name)


app = Flask(__name__)
app.secret_key = get_secret("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

# Number of reverse proxies in front of the app. Keep 0 when running locally,
# otherwise visitors could fake their IP address with a forged header.
TRUSTED_PROXIES = int(os.environ.get("TRUSTED_PROXIES", "0"))
if TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    if request.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store"
    return response


def init_db():
    """Create the database tables if they don't exist yet (safe to run every time)."""
    os.makedirs(PROJECT_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reports ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "url TEXT NOT NULL, "
            "notes TEXT, "
            "reported_at TEXT DEFAULT CURRENT_TIMESTAMP, "
            "reporter TEXT)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_url_reporter ON reports(url, reporter)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS link_reviews ("
            "url TEXT PRIMARY KEY NOT NULL, "
            "status TEXT NOT NULL CHECK (status IN ('approved', 'rejected')), "
            "reviewed_at TEXT DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.commit()
    finally:
        conn.close()


init_db()


def normalize_url(raw):
    """
    Clean up a link so the same page always gets the same form
    (lowercase host, no default port, no #fragment, "/" for an empty path).
    Returns the cleaned URL, or None if the input is not a valid web link.
    """
    raw = (raw or "").strip()
    if not raw or len(raw) > MAX_URL_LENGTH:
        return None
    if any(ch.isspace() or not ch.isprintable() for ch in raw):
        return None

    if "://" not in raw:
        raw = "https://" + raw

    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        return None

    host = parts.hostname.rstrip(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if not is_ip:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if "." not in host:
            return None
    elif ":" in host:
        host = f"[{host}]"

    userinfo = parts.netloc.rpartition("@")[0] + "@" if "@" in parts.netloc else ""
    default_port = 80 if scheme == "http" else 443
    port_part = f":{port}" if port and port != default_port else ""
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""

    return f"{scheme}://{userinfo}{host}{port_part}{path}{query}"


def defang(url):
    """Make a link unclickable (hxxp, [.]) so nobody opens a reported phishing link by accident."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def short_time(value):
    return f"{value[:16]} UTC" if value else ""


#  Community reports and moderation 

def get_reporter_id(salt):
    """Anonymous visitor ID: a salted hash of the visitor's IP address (the raw IP is never stored)."""
    raw = f"{salt}:{request.remote_addr}"
    return hashlib.sha256(raw.encode()).hexdigest()


def save_report(url, reporter, notes=""):
    """Save a report. Returns True if saved, False if this visitor already reported this URL."""
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute(
            "INSERT INTO reports (url, reporter, notes) VALUES (?, ?, ?)",
            (url, reporter, notes),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_report_count(url):
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        "SELECT COUNT(*) FROM reports WHERE url = ?",
        (url,),
    ).fetchone()
    conn.close()
    return row[0]


def get_review_status(url):
    """'approved', 'rejected', or None if a moderator hasn't reviewed this link yet."""
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute("SELECT status FROM link_reviews WHERE url = ?", (url,)).fetchone()
    conn.close()
    return row[0] if row else None


def set_review(url, decision):
    """Record a moderator decision: approve, reject, or undo (back to waiting for review)."""
    conn = sqlite3.connect(DB_FILE)
    try:
        if decision == "undo":
            conn.execute("DELETE FROM link_reviews WHERE url = ?", (url,))
        elif conn.execute("SELECT 1 FROM reports WHERE url = ? LIMIT 1", (url,)).fetchone():
            status = "approved" if decision == "approve" else "rejected"
            conn.execute(
                "INSERT OR REPLACE INTO link_reviews (url, status) VALUES (?, ?)", (url, status)
            )
        conn.commit()
    finally:
        conn.close()


def get_reported_links(limit=REPORTS_PAGE_LIMIT):
    """Links a moderator approved for the public list, most-reported first."""
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT r.url, COUNT(*) AS n, MAX(r.reported_at) FROM reports r "
        "JOIN link_reviews v ON v.url = r.url "
        "WHERE v.status = 'approved' "
        "GROUP BY r.url ORDER BY n DESC, MAX(r.reported_at) DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {"url": url, "display": defang(url), "count": count, "last": short_time(last)}
        for url, count, last in rows
    ]


def get_pending_links(limit=ADMIN_PAGE_LIMIT):
    """Reported links that no moderator has reviewed yet."""
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT url, COUNT(*) AS n, MAX(reported_at) FROM reports "
        "WHERE url NOT IN (SELECT url FROM link_reviews) "
        "GROUP BY url ORDER BY n DESC, MAX(reported_at) DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {"url": url, "display": defang(url), "count": count, "last": short_time(last)}
        for url, count, last in rows
    ]


def get_reviewed_links(limit=ADMIN_PAGE_LIMIT):
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT v.url, v.status, v.reviewed_at, "
        "(SELECT COUNT(*) FROM reports r WHERE r.url = v.url) "
        "FROM link_reviews v ORDER BY v.reviewed_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [
        {
            "url": url,
            "display": defang(url),
            "status": status,
            "count": count,
            "reviewed": short_time(reviewed_at),
        }
        for url, status, reviewed_at, count in rows
    ]


# Admin security 

def admin_is_configured():
    return bool(get_secret("SECRET_KEY") and get_secret("ADMIN_PASSWORD_HASH"))


def get_csrf_token():
    """One secret token per browser session; every admin form must send it back."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def csrf_is_valid():
    sent = request.form.get("csrf", "")
    expected = session.get("csrf", "")
    return bool(expected) and hmac.compare_digest(sent.encode(), expected.encode())


def login_locked_out(ip):
    now = time.time()
    recent = [t for t in FAILED_LOGINS.get(ip, []) if now - t < LOCKOUT_SECONDS]
    if recent:
        FAILED_LOGINS[ip] = recent
    else:
        FAILED_LOGINS.pop(ip, None)
    return len(recent) >= MAX_FAILED_LOGINS


def record_failed_login(ip):
    FAILED_LOGINS.setdefault(ip, []).append(time.time())


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapper


# Threat-intelligence checks

def run_check(check_fn, *args):
    """Run one threat-intel check; if the network fails, return 'no data' instead of crashing."""
    try:
        return check_fn(*args)
    except requests.exceptions.RequestException:
        return {"available": False, "reason": "network error"}


def find_missing_sources(vt_result, urlscan_result, safe_browsing_result):
    """Names of the sources that returned no usable data for this scan."""
    checks = [
        ("VirusTotal", vt_result),
        ("urlscan.io", urlscan_result),
        ("Google Safe Browsing", safe_browsing_result),
    ]
    return [name for name, result in checks if not result.get("available")]


def url_to_vt_id(url):
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def check_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    url_id = url_to_vt_id(url)
    resp = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)

    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {"available": True, "malicious": stats["malicious"], "suspicious": stats["suspicious"]}
    elif resp.status_code == 404:
        requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url})
        return {"available": False, "reason": "not previously seen, submitted for future scans"}
    else:
        return {"available": False, "reason": f"error {resp.status_code}"}


def check_urlscan(url, api_key):
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": "public"}

    submit_resp = requests.post(f"{URLSCAN_BASE}/scan/", headers=headers, json=payload)
    if submit_resp.status_code != 200:
        try:
            detail = submit_resp.json().get("description", "")
        except ValueError:
            detail = ""
        if submit_resp.status_code == 400 and "blocked from scanning" in detail:
            return {
                "available": False,
                "blocked": True,
                "reason": "urlscan.io does not allow scanning this site",
            }
        return {
            "available": False,
            "reason": f"submission failed ({submit_resp.status_code}) {detail}"[:150],
        }

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


def check_safe_browsing(url, api_key):
    """
    Checks a URL against Google Safe Browsing's list of known
    malware/phishing/unwanted-software sites.
    """
    payload = {
        "client": {"clientId": "linkguard-ethiopia", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    resp = requests.post(
        SAFE_BROWSING_URL,
        params={"key": api_key},
        json=payload,
    )

    if resp.status_code != 200:
        return {"available": False, "reason": f"error {resp.status_code}"}

    data = resp.json()
    matches = data.get("matches", [])

    if matches:
        threat_types = sorted(set(m["threatType"] for m in matches))
        return {"available": True, "flagged": True, "threat_types": threat_types}
    else:
        return {"available": True, "flagged": False, "threat_types": []}


def compute_risk_score(vt_result, urlscan_result, safe_browsing_result, report_count=0):
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

        if malicious == 0 and suspicious == 0:
            reasons.append("VirusTotal: no engines flagged this URL")
    else:
        reasons.append(f"VirusTotal: no data available ({vt_result.get('reason', 'unknown')})")

    if safe_browsing_result.get("available"):
        if safe_browsing_result["flagged"]:
            score += 35
            types = ", ".join(safe_browsing_result["threat_types"])
            reasons.append(f"Google Safe Browsing: flagged as {types}")
        else:
            reasons.append("Google Safe Browsing: no known threats found")
    else:
        reasons.append(f"Google Safe Browsing: no data available ({safe_browsing_result.get('reason', 'unknown')})")

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

    if report_count > 0:
        report_points = min(report_count * 5, 25)
        score += report_points
        reasons.append(f"Community: reported by {report_count} user(s)")

    score = min(score, 100)

    if score <= 30:
        band = "Safe"
    elif score <= 60:
        band = "Suspicious"
    else:
        band = "Dangerous"

    return score, band, reasons


#  Pages 

BASE_CSS = """
  body {
    font-family: -apple-system, Segoe UI, Roboto, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    max-width: 640px;
    margin: 60px auto;
    padding: 0 20px;
  }
  body.wide { max-width: 900px; }
  h1 { color: #38bdf8; margin-bottom: 4px; }
  h2 { color: #cbd5e1; font-size: 18px; margin-top: 32px; }
  p.tagline { color: #94a3b8; margin-top: 0; }
  form { display: flex; gap: 8px; margin: 24px 0; }
  form.inline { display: inline; margin: 0; }
  td form.inline { margin-left: 6px; }
  input[type=text], input[type=password] {
    flex: 1;
    padding: 12px;
    border-radius: 8px;
    border: 1px solid #334155;
    background: #1e293b;
    color: #e2e8f0;
    font-size: 16px;
  }
  button {
    padding: 12px 20px;
    border-radius: 8px;
    border: none;
    background: #38bdf8;
    color: #0f172a;
    font-weight: 600;
    cursor: pointer;
    font-size: 16px;
  }
  button:hover { background: #7dd3fc; }
  button.small { padding: 6px 10px; font-size: 13px; }
  button.approve { background: #22c55e; color: #052e16; }
  button.reject { background: #ef4444; color: #fff; }
  .result {
    margin-top: 24px;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #334155;
  }
  .safe { border-color: #22c55e; background: #052e16; }
  .suspicious { border-color: #eab308; background: #422006; }
  .dangerous { border-color: #ef4444; background: #450a0a; }
  .unverified { border-color: #94a3b8; background: #1e293b; }
  .score { font-size: 40px; font-weight: 700; margin: 0; }
  .band { font-size: 20px; margin: 4px 0 16px 0; }
  ul { padding-left: 20px; line-height: 1.6; }
  .warning { background: #422006; border: 1px solid #eab308; border-radius: 8px; padding: 10px 12px; font-size: 14px; margin: 0 0 16px 0; }
  .checked { color: #94a3b8; font-size: 14px; word-break: break-all; margin: 0 0 12px 0; }
  .result form { margin-top: 16px; }
  .result button {
    background: #ef4444;
    color: #fff;
  }
  .result button:hover { background: #f87171; }
  a { color: #38bdf8; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid #334155; font-size: 14px; vertical-align: top; }
  .mono { font-family: monospace; word-break: break-all; }
  .disclaimer { background: #1e293b; border-left: 3px solid #94a3b8; padding: 10px 12px; font-size: 14px; color: #cbd5e1; }
  .status-approved { color: #22c55e; }
  .status-rejected { color: #ef4444; }
  .nav { margin-top: 32px; }
"""
app.jinja_env.globals["BASE_CSS"] = BASE_CSS


PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LinkGuard Ethiopia</title>
<style>{{ BASE_CSS|safe }}</style>
</head>
<body>
  <h1>LinkGuard Ethiopia</h1>
  <p class="tagline">Paste a link to check it before you click.</p>

  <form method="POST" action="/scan">
    <input type="text" name="url" placeholder="https://example.com"
           value="{{ url or '' }}" required>
    <button type="submit">Scan</button>
  </form>

  {% if result %}
  <div class="result {{ result.band|lower }}">
    <p class="score">{{ result.score }}/100</p>
    <p class="band">{{ result.band }}</p>
    {% if result.missing %}
    <p class="warning"> Incomplete scan: {{ result.missing|join(', ') }} could not be checked, so this result may be missing threats.</p>
    {% endif %}
    <p class="checked">Checked: {{ url }}</p>
    <ul>
      {% for reason in result.reasons %}
        <li>{{ reason }}</li>
      {% endfor %}
    </ul>
    <form method="POST" action="/report">
      <input type="hidden" name="url" value="{{ url }}">
      <button type="submit">Report this link</button>
    </form>
  </div>
  {% endif %}

  {% if notice %}
    <p style="color:#38bdf8;">{{ notice }}</p>
  {% endif %}
  <p class="nav"><a href="/reports">Community reports</a></p>
</body>
</html>
"""


REPORTS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Community reports — LinkGuard Ethiopia</title>
<style>{{ BASE_CSS|safe }}</style>
</head>
<body>
  <h1>Community reports</h1>
  <p class="tagline">Links reported by LinkGuard users and checked by a moderator.</p>
  <p class="disclaimer">
    A moderator reviews community reports before a link is listed here. The list can still contain
    mistakes, so treat it as a warning sign, not proof. Links are shown in a "defanged" form
    (hxxp, [.]) so they can't be opened by accident.
  </p>

  {% if rows %}
  <table>
    <tr><th>Link</th><th>Reports</th><th>Last reported</th><th></th></tr>
    {% for row in rows %}
    <tr>
      <td class="mono">{{ row.display }}</td>
      <td>{{ row.count }}</td>
      <td>{{ row.last }}</td>
      <td><a href="/?url={{ row.url|urlencode }}">Check</a></td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No links have been approved for this list yet.</p>
  {% endif %}

  <p class="nav"><a href="/">&larr; Back to the scanner</a></p>
</body>
</html>
"""


ADMIN_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin login — LinkGuard Ethiopia</title>
<style>{{ BASE_CSS|safe }}</style>
</head>
<body>
  <h1>Admin login</h1>
  {% if configured %}
  <form method="POST" action="/admin/login">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <input type="password" name="password" placeholder="Admin password"
           autocomplete="current-password" required>
    <button type="submit">Log in</button>
  </form>
  {% endif %}
  {% if notice %}
    <p style="color:#fbbf24;">{{ notice }}</p>
  {% endif %}
  <p class="nav"><a href="/">&larr; Back to the scanner</a></p>
</body>
</html>
"""


ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Moderation — LinkGuard Ethiopia</title>
<style>{{ BASE_CSS|safe }}</style>
</head>
<body class="wide">
  <h1>Moderation</h1>
  <p class="tagline">Review community reports before they appear on the public list.</p>

  <form method="POST" action="/admin/logout" class="inline">
    <input type="hidden" name="csrf" value="{{ csrf_token() }}">
    <button type="submit" class="small">Log out</button>
  </form>

  <h2>Waiting for review ({{ pending|length }})</h2>
  {% if pending %}
  <table>
    <tr><th>Link</th><th>Reports</th><th>Last reported</th><th>Decision</th></tr>
    {% for row in pending %}
    <tr>
      <td class="mono">{{ row.display }}</td>
      <td>{{ row.count }}</td>
      <td>{{ row.last }}</td>
      <td>
        <a href="/?url={{ row.url|urlencode }}">Check</a>
        <form method="POST" action="/admin/review" class="inline">
          <input type="hidden" name="csrf" value="{{ csrf_token() }}">
          <input type="hidden" name="url" value="{{ row.url }}">
          <input type="hidden" name="decision" value="approve">
          <button type="submit" class="small approve">Approve</button>
        </form>
        <form method="POST" action="/admin/review" class="inline">
          <input type="hidden" name="csrf" value="{{ csrf_token() }}">
          <input type="hidden" name="url" value="{{ row.url }}">
          <input type="hidden" name="decision" value="reject">
          <button type="submit" class="small reject">Reject</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>Nothing is waiting for review.</p>
  {% endif %}

  <h2>Already reviewed</h2>
  {% if reviewed %}
  <table>
    <tr><th>Link</th><th>Decision</th><th>Reports</th><th>Reviewed</th><th></th></tr>
    {% for row in reviewed %}
    <tr>
      <td class="mono">{{ row.display }}</td>
      <td class="status-{{ row.status }}">{{ row.status }}</td>
      <td>{{ row.count }}</td>
      <td>{{ row.reviewed }}</td>
      <td>
        <form method="POST" action="/admin/review" class="inline">
          <input type="hidden" name="csrf" value="{{ csrf_token() }}">
          <input type="hidden" name="url" value="{{ row.url }}">
          <input type="hidden" name="decision" value="undo">
          <button type="submit" class="small">Undo</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No decisions yet.</p>
  {% endif %}

  <p class="nav"><a href="/">&larr; Back to the scanner</a></p>
</body>
</html>
"""


# Public routes 

@app.route("/", methods=["GET"])
def index():
    prefill = request.args.get("url", "")[:MAX_URL_LENGTH]
    return render_template_string(PAGE_TEMPLATE, url=prefill or None, result=None, notice=None)


@app.route("/reports", methods=["GET"])
def reports_page():
    return render_template_string(REPORTS_TEMPLATE, rows=get_reported_links())


@app.route("/scan", methods=["POST"])
def scan():
    raw_input = request.form.get("url", "")
    target_url = normalize_url(raw_input)
    if not target_url:
        return render_template_string(
            PAGE_TEMPLATE, url=raw_input.strip()[:200], result=None, notice=INVALID_URL_MESSAGE
        )

    vt_key = get_secret("VIRUSTOTAL_API_KEY")
    urlscan_key = get_secret("URLSCAN_API_KEY")
    safe_browsing_key = get_secret("GOOGLE_SAFE_BROWSING_KEY")

    if not vt_key or not urlscan_key or not safe_browsing_key:
        return render_template_string(
            PAGE_TEMPLATE,
            url=target_url,
            result=None,
            notice="The scanner is not set up yet: an API key is missing from the keys file.",
        )

    vt_result = run_check(check_virustotal, target_url, vt_key)
    urlscan_result = run_check(check_urlscan, target_url, urlscan_key)
    safe_browsing_result = run_check(check_safe_browsing, target_url, safe_browsing_key)

    # Only reports a moderator approved count toward the score.
    review_status = get_review_status(target_url)
    raw_report_count = get_report_count(target_url)
    report_count = raw_report_count if review_status == "approved" else 0

    score, band, reasons = compute_risk_score(
        vt_result, urlscan_result, safe_browsing_result, report_count
    )
    if raw_report_count > 0 and review_status != "approved":
        if review_status == "rejected":
            reasons.append("Community: reports on this link were reviewed by a moderator and not counted")
        else:
            reasons.append("Community: reports are waiting for moderator review and are not counted yet")

    missing = find_missing_sources(vt_result, urlscan_result, safe_browsing_result)
    if urlscan_result.get("blocked"):
        missing = [name for name in missing if name != "urlscan.io"]
    if missing and band == "Safe":
        band = "Unverified"

    result = {
        "score": score,
        "band": band,
        "reasons": reasons,
        "report_count": report_count,
        "missing": missing,
    }
    return render_template_string(PAGE_TEMPLATE, url=target_url, result=result, notice=None)


@app.route("/report", methods=["POST"])
def report():
    raw_input = request.form.get("url", "")
    target_url = normalize_url(raw_input)
    salt = get_secret("REPORT_SALT")

    if not target_url:
        notice = INVALID_URL_MESSAGE
    elif not salt:
        notice = "Reporting is not set up yet (REPORT_SALT is missing from the keys file)."
    elif save_report(target_url, get_reporter_id(salt)):
        notice = "Thanks — this link has been reported."
    else:
        notice = "You have already reported this link. Thank you!"

    shown_url = target_url or raw_input.strip()[:200]
    return render_template_string(PAGE_TEMPLATE, url=shown_url, result=None, notice=notice)


#  Admin routes 

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if not admin_is_configured():
        return render_template_string(
            ADMIN_LOGIN_TEMPLATE,
            configured=False,
            notice="Admin is not set up yet (SECRET_KEY or ADMIN_PASSWORD_HASH is missing).",
        )

    notice = None
    status = 200
    if request.method == "POST":
        ip = request.remote_addr
        if login_locked_out(ip):
            notice = "Too many wrong passwords. Please try again in 15 minutes."
            status = 429
        elif not csrf_is_valid():
            abort(400)
        else:
            password = request.form.get("password", "")[:1000]
            if check_password_hash(get_secret("ADMIN_PASSWORD_HASH"), password):
                session.clear()
                session["admin"] = True
                session.permanent = True
                return redirect(url_for("admin_queue"))
            record_failed_login(ip)
            notice = "Wrong password."
            status = 401

    return (
        render_template_string(ADMIN_LOGIN_TEMPLATE, configured=True, notice=notice),
        status,
    )


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    if not csrf_is_valid():
        abort(400)
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin", methods=["GET"])
@admin_required
def admin_queue():
    return render_template_string(
        ADMIN_TEMPLATE, pending=get_pending_links(), reviewed=get_reviewed_links()
    )


@app.route("/admin/review", methods=["POST"])
@admin_required
def admin_review():
    if not csrf_is_valid():
        abort(400)
    decision = request.form.get("decision", "")
    url = normalize_url(request.form.get("url", ""))
    if url and decision in ("approve", "reject", "undo"):
        set_review(url, decision)
    return redirect(url_for("admin_queue"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
