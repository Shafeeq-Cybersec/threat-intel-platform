"""
Geolocates attacker IP addresses pulled from stored detections, for the threat map.

Uses ip-api.com's free batch endpoint (no key, server-side only so there is no
mixed-content issue on an HTTPS deployment). Results are cached per process.
"""
import re
import logging
import requests

log = logging.getLogger(__name__)
_BATCH_URL = "http://ip-api.com/batch"
TIMEOUT = 15

_IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_geo_cache = {}  # ip -> {lat, lon, country, city} or None (un-geolocatable)


def _is_public_ip(ip: str) -> bool:
    m = _IP_RE.match(ip)
    if not m:
        return False
    o = [int(x) for x in m.groups()]
    if any(x > 255 for x in o):
        return False
    # Drop private / reserved ranges that cannot be geolocated
    if o[0] == 10:
        return False
    if o[0] == 172 and 16 <= o[1] <= 31:
        return False
    if o[0] == 192 and o[1] == 168:
        return False
    if o[0] == 127 or o[0] == 0 or o[0] >= 224:
        return False
    return True


def extract_ips(text: str):
    return [m.group(0) for m in _IP_RE.finditer(text or "")]


def geolocate(ips: list) -> dict:
    """Returns {ip: {lat, lon, country, city}} for the public, resolvable IPs given."""
    out = {}
    to_query = []
    for ip in dict.fromkeys(ips):           # de-dupe, keep order
        if not _is_public_ip(ip):
            continue
        if ip in _geo_cache:
            if _geo_cache[ip]:
                out[ip] = _geo_cache[ip]
        else:
            to_query.append(ip)

    # ip-api batch allows up to 100 IPs per request
    for i in range(0, len(to_query), 100):
        chunk = to_query[i:i + 100]
        try:
            r = requests.post(_BATCH_URL, json=chunk, timeout=TIMEOUT,
                              params={"fields": "status,country,city,lat,lon,query"})
            r.raise_for_status()
            for rec in r.json():
                ip = rec.get("query")
                if rec.get("status") == "success" and ip:
                    geo = {"lat": rec["lat"], "lon": rec["lon"],
                           "country": rec.get("country"), "city": rec.get("city")}
                    _geo_cache[ip] = geo
                    out[ip] = geo
                elif ip:
                    _geo_cache[ip] = None
        except Exception as e:
            log.warning(f"[geo] batch geolocation failed: {e}")
            break
    return out
