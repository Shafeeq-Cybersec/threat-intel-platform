import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

log = logging.getLogger(__name__)
TIMEOUT = 15
# rdap.org returns 403 to requests without a User-Agent
_HEADERS = {"User-Agent": "threat-intel-platform/1.0"}
# Domains younger than this are treated as elevated risk (phishing sites are often fresh)
_YOUNG_DAYS = 30


def _extract_domain(url: str) -> str:
    host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    parts = host.split(".")
    # registrable domain ~ last two labels (good enough for common TLDs)
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _registration_date(events: list):
    for ev in events or []:
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                return datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def check_url(url: str):
    domain = _extract_domain(url)
    if not domain:
        return None
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=_HEADERS, timeout=TIMEOUT)
        if r.status_code == 404:
            # No RDAP record found, unusual/suspicious but not conclusive
            return {"source": "rdap", "malicious": False, "score": 30,
                    "raw": {"domain": domain, "note": "no RDAP record"}}
        r.raise_for_status()
        data = r.json()
        reg = _registration_date(data.get("events"))
        if not reg:
            return {"source": "rdap", "malicious": False, "score": 10,
                    "raw": {"domain": domain, "note": "registration date unavailable"}}

        age_days = (datetime.now(timezone.utc) - reg).days
        if age_days < 7:
            score = 70
        elif age_days < _YOUNG_DAYS:
            score = 45
        elif age_days < 180:
            score = 20
        else:
            score = 0
        return {
            "source": "rdap",
            "malicious": False,
            "score": score,
            "raw": {"domain": domain, "registration_date": reg.isoformat(), "age_days": age_days},
        }
    except Exception as e:
        log.warning(f"[rdap] lookup failed for {domain}: {e}")
        return None
