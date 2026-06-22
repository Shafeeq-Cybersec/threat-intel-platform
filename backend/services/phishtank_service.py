import logging
import requests
import config

log = logging.getLogger(__name__)
_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"
TIMEOUT = 15


def check_url(url: str):
    """Checks a URL against PhishTank's verified-phish database.

    Returns {source, malicious, score, raw} or None if unconfigured/failed.
    PhishTank requires a registered application key (see README note).
    """
    if not config.is_configured("phishtank"):
        log.warning("[phishtank] no API key, skipping")
        return None
    try:
        r = requests.post(
            _ENDPOINT,
            data={"url": url, "format": "json", "app_key": config.PHISHTANK_API_KEY},
            headers={"User-Agent": "phishtank/threat-intel-platform"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        results = r.json().get("results", {})
        is_phish = bool(results.get("in_database") and results.get("valid"))
        return {
            "source": "phishtank",
            "malicious": is_phish,
            "score": 95 if is_phish else 0,
            "raw": results,
        }
    except Exception as e:
        log.warning(f"[phishtank] lookup failed: {e}")
        return None
