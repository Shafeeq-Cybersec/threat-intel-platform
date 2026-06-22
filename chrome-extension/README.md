# Threat Intel URL Scanner (Chrome Extension)

A companion browser extension for the Threat Intelligence platform. Scan the page
you are on, or right-click any link, to check it for phishing and malware using the
same backend pipeline (VirusTotal, Google Safe Browsing, RDAP, and Gemini).

## Features

- One-click scan of the current tab from the toolbar popup
- Right-click context menu: "Scan link with Threat Intel" on any link
- Risk score, verdict, threat type, AI reasoning, and the sources used
- Configurable backend URL (works against a local server or the deployed site)

## Install (developer mode)

1. Open `chrome://extensions` in Chrome or Edge.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select this `chrome-extension` folder.
4. Pin the extension from the puzzle-piece menu.

## Configure the backend

Click the extension icon, expand **Backend settings**, and set the URL of your
running platform:

- Local development: `http://localhost:5000`
- Deployed: your hosting URL, for example `https://your-app.up.railway.app`

Click **Save**. The setting is stored per browser.

## How it works

The popup and the context menu send the target URL to the backend's `/check-url`
endpoint and render the returned verdict. The page contents are never read; only
the URL is sent.
