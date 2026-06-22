# AI-Powered Security Operations & Threat Intelligence Platform

A self-hosted threat-detection dashboard that combines threat-intelligence APIs with Google Gemini to analyse URLs, QR codes, security logs, and Gmail inboxes for phishing and malware. It ships with a live web dashboard, a real-time detection feed, and email alerting.

Every external integration degrades gracefully. If an API key is missing or a call fails, that source is skipped (logged as a warning) and the rest of the app keeps working.

## Features

| Feature | What it does | Tab |
|---|---|---|
| URL Check | Scores a URL using VirusTotal, Google Safe Browsing, RDAP domain age, and Gemini reasoning | URL Check |
| QR Scan | Decodes a QR image, extracts the URL, and runs it through the URL pipeline | QR Scan |
| SOC Log Analyzer | Rule-based detections (brute-force, off-hours, malicious IPs via AbuseIPDB) plus Gemini on ambiguous lines | SOC Analyzer |
| Email Scanner | Reads a connected Gmail inbox and scores each message for phishing (URL reputation plus NLP heuristics) | Email Scanner |
| Live Threat Feed | Real-time SocketIO feed of every detection, visible on all tabs | (always visible) |
| Email Alerts | Sends an email via Brevo when a result crosses the risk threshold | (background) |
| Settings | Green/red status of every configured service plus CSV export | Settings |

## Tech stack

- Backend: Python 3.11, Flask, Flask-SocketIO
- Storage: SQLite (`threat_intel.db`, auto-created)
- Frontend: plain HTML/CSS/JS (no framework), Socket.IO client
- AI: Google Gemini (`gemini-2.5-flash`)
- QR decoding: OpenCV (`cv2.QRCodeDetector`), which needs no system dependencies (chosen over pyzbar, which requires the native zbar/libiconv libs)

## Project structure

```
backend/
  app.py                  # entry point: Flask + SocketIO, registers blueprints
  config.py               # loads .env; is_configured(service) helper
  realtime.py             # SocketIO broadcast helper for the live feed
  requirements.txt
  models/
    database.py           # SQLite schema + insert helpers (emit live-feed events)
  routes/                 # one blueprint per feature
    dashboard.py  check_url.py  scan_qr.py  soc_analyzer.py
    email_scanner.py  settings.py
  services/               # one file per integration (swappable / disableable)
    virustotal_service.py  safebrowsing_service.py  rdap_service.py
    abuseipdb_service.py   gemini_service.py        risk_aggregator.py
    log_analyzer.py        qr_service.py            gmail_service.py
    email_phishing_service.py  alert_service.py
  templates/dashboard.html
  credentials/            # Gmail OAuth files (gitignored): credentials.json, token.json
  sample_data/            # sample logs + QR images for testing
.env                      # your real secrets (not committed)
.env.example              # documented template
```

## Prerequisites

Python 3.11 (the project is tested on 3.11). On Windows, if you have multiple Python installs, make sure you install dependencies into and run the app with the same interpreter. Using a virtual environment (below) avoids this entirely.

## Setup

```bash
# 1. From the project root, create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Create your .env from the template and fill in keys
cp .env.example .env        # Windows: copy .env.example .env
```

Then edit `.env` (see the key guide below). You can run with zero keys. The app still works using RDAP (free, no key) and rule-based heuristics, and the AI and commercial sources activate as you add keys.

## API keys: what each unlocks and where to get it

All keys go in `.env`. The dashboard Settings tab shows a green/red dot for each.

| Key | Unlocks | Without it | Get it from |
|---|---|---|---|
| `GEMINI_API_KEY` | AI risk scoring and written reasoning on URLs, QR, email, logs | Falls back to weighted average of other sources / rules only | https://aistudio.google.com/app/apikey (free) |
| `VIRUSTOTAL_API_KEY` | Multi-engine (70+) URL/file reputation | URL pipeline skips VT | https://www.virustotal.com/gui/my-apikey (free) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google's blocklist of malicious URLs | URL pipeline skips Safe Browsing | Google Cloud Console, enable "Safe Browsing API", create API key |
| `ABUSEIPDB_API_KEY` | Malicious-IP reputation in SOC logs (impossible-travel, known-bad IPs) | Those log rules skip | https://www.abuseipdb.com/account/api (free) |
| `GMAIL_CREDENTIALS_PATH` | Gmail inbox phishing scanning | Email Scanner disabled | Google Cloud Console OAuth (see below) |
| `BREVO_API_KEY` + `ALERT_EMAIL_FROM`/`TO` | Email alerts above `ALERT_THRESHOLD` | Alerts are logged as "would have sent", not emailed | https://app.brevo.com/settings/keys/api (free tier) |
| `PHISHTANK_API_KEY` | Optional community phishing DB | Skipped (new keys are closed by Cisco) | n/a |

`ALERT_THRESHOLD` (default `70`) controls the score at or above which an alert fires.

RDAP (domain-age checks) needs no key and always runs.

## Gmail setup (read-only inbox scanning)

This requests READ access to a real Gmail inbox. The app can only read recent messages. It cannot send, delete, or modify anything. Use a throwaway or test Gmail account first if you are unsure. You can revoke access anytime at https://myaccount.google.com/permissions.

1. In Google Cloud Console, create a project and enable the Gmail API.
2. Configure the OAuth consent screen (Google Auth Platform):
   - User type External, publishing status Testing.
   - Under Audience > Test users, add the exact Gmail address you will scan.
3. Credentials > Create credentials > OAuth client ID > Desktop app. Download the JSON.
4. Save it as `backend/credentials/credentials.json`.
5. Start the app, open the Email Scanner tab, click Connect Gmail. A browser window opens. Choose the test account, click Advanced > Go to ... (unsafe), which is normal for your own unverified test app, then click Allow. A `token.json` is cached so you will not re-auth.

In Testing mode the OAuth refresh token expires after about 7 days. If scanning stops working, delete `backend/credentials/token.json` and click Connect Gmail again.

## Running

```bash
cd backend
python app.py
```

Open http://localhost:5000/dashboard.

The server starts on port 5000 with SocketIO. `threat_intel.db` is created on first run.

## Using it

- URL Check: paste a URL, click Check URL. Tick force refresh to bypass the 1-hour cache.
- QR Scan: drag/drop or pick a QR image (try `backend/sample_data/qr_test_malicious.png`).
- SOC Analyzer: paste logs or upload a file (try `backend/sample_data/*.log`).
- Email Scanner: Connect Gmail, then Scan inbox.
- Live Threat Feed (right column): updates in real time as detections happen.
- Settings: see which services are active, export `threat_logs`, `soc_events`, `email_scans` as CSV.

### Try a phishing detection

Send yourself an email containing urgency language and a lookalike link (for example `http://secure-paypa1-login.tk/verify`), then click Scan inbox. With Gemini and Safe Browsing on, it should score as Phishing.

## Security notes

- Secrets: `.env` and `backend/credentials/` are for local secrets only. Keep them out of version control. `backend/credentials/.gitignore` already excludes the JSON files, and the root `.gitignore` excludes `.env`.
- Gmail: read-only scope (`gmail.readonly`). Revoke at https://myaccount.google.com/permissions. Prefer a test account.
- This is a self-hosted single-operator tool, not a multi-tenant SaaS. Serving it to other users would require publishing the OAuth app (Google verification) and per-user token storage.
- The bundled Flask dev server is for local use. Put a real WSGI server in front for anything public.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `{{ db_status }}` shows literally in the browser | You are viewing the template file directly. Open the Flask URL http://localhost:5000/dashboard, not the `.html` file. |
| `ModuleNotFoundError` on start | Deps installed into a different Python than you are running. Use a venv. |
| Email Scanner says "not connected" | `credentials.json` missing, or token expired (delete `token.json`, reconnect). |
| VirusTotal not shown in a URL's sources | VT only has data on previously-seen URLs. A brand-new or fabricated domain returns no verdict. |
| Live feed empty | It populates on activity, so run any scan. Requires the page to reach `cdn.socket.io` (internet). |
| Alerts never arrive | Brevo not configured, or score below `ALERT_THRESHOLD`. Check server logs for "WOULD have emailed". |
