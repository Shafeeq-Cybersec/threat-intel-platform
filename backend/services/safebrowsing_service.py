import logging
import requests
import config

log = logging.getLogger(__name__)
_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT = 20

_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def check_url(url: str):
    if not config.is_configured("safe_browsing"):
        log.warning("[safe_browsing] no API key, skipping")
        return None

    body = {
        "client": {"clientId": "threat-intel-platform", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            _ENDPOINT,
            params={"key": config.GOOGLE_SAFE_BROWSING_API_KEY},
            json=body,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        matches = data.get("matches", [])
        malicious = len(matches) > 0
        # Safe Browsing is binary; a match is high-confidence malicious
        return {
            "source": "safe_browsing",
            "malicious": malicious,
            "score": 95 if malicious else 0,
            "raw": data,
        }
    except Exception as e:
        log.warning(f"[safe_browsing] lookup failed: {e}")
        return None
