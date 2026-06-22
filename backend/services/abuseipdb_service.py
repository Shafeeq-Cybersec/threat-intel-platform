import logging
import requests
import config

log = logging.getLogger(__name__)
_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 15

_cache = {}  # ip -> result (per-process, avoids re-querying same IP in one run)


def check_ip(ip: str):
    """Returns {source, malicious, score, country, raw} or None if unconfigured/failed."""
    if not config.is_configured("abuseipdb"):
        return None
    if ip in _cache:
        return _cache[ip]

    try:
        r = requests.get(
            _ENDPOINT,
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        result = {
            "source": "abuseipdb",
            "malicious": score >= 50,
            "score": score,
            "country": data.get("countryCode"),
            "raw": data,
        }
        _cache[ip] = result
        return result
    except Exception as e:
        log.warning(f"[abuseipdb] lookup failed for {ip}: {e}")
        return None
