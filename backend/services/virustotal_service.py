import base64
import logging
import requests
import config

log = logging.getLogger(__name__)
_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 20


def _url_id(url: str) -> str:
    # VT uses base64-urlsafe of the URL without padding as the resource id
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _normalize(stats: dict, raw: dict) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    score = round(100 * (malicious + 0.5 * suspicious) / total)
    return {
        "source": "virustotal",
        "malicious": malicious > 0,
        "score": min(score, 100),
        "raw": raw,
    }


def check_file_hash(file_hash: str):
    """Looks up a file by its hash (md5/sha1/sha256) in VirusTotal.

    Only the hash is sent to VirusTotal, never the file contents. Returns a
    structured report, or {"found": False} if VT has never seen the file.
    """
    if not config.is_configured("virustotal"):
        return {"error": "VirusTotal not configured."}

    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    try:
        r = requests.get(f"{_BASE}/files/{file_hash}", headers=headers, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"found": False}
        r.raise_for_status()
        attr = r.json()["data"]["attributes"]
        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = min(round(100 * (malicious + 0.5 * suspicious) / total), 100)

        # Collect the engine names that flagged it (most informative for an analyst)
        detections = []
        for engine, res in (attr.get("last_analysis_results") or {}).items():
            if res.get("category") in ("malicious", "suspicious") and res.get("result"):
                detections.append({"engine": engine, "result": res["result"]})
        detections.sort(key=lambda d: d["engine"].lower())

        threat = (attr.get("popular_threat_classification") or {}).get("suggested_threat_label")
        names = attr.get("names") or []
        return {
            "found": True,
            "score": score,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "threat_label": threat,
            "file_name": attr.get("meaningful_name") or (names[0] if names else None),
            "type_description": attr.get("type_description"),
            "size": attr.get("size"),
            "sha256": attr.get("sha256"),
            "md5": attr.get("md5"),
            "first_seen": attr.get("first_submission_date"),
            "last_analyzed": attr.get("last_analysis_date"),
            "detections": detections,
        }
    except Exception as e:
        log.warning(f"[virustotal] file lookup failed: {e}")
        return {"error": f"VirusTotal lookup failed: {e}"}


def check_url(url: str):
    if not config.is_configured("virustotal"):
        log.warning("[virustotal] no API key, skipping")
        return None

    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    try:
        # Try existing report first
        r = requests.get(f"{_BASE}/urls/{_url_id(url)}", headers=headers, timeout=TIMEOUT)
        if r.status_code == 404:
            # Not seen before: submit then re-read once
            sub = requests.post(f"{_BASE}/urls", headers=headers, data={"url": url}, timeout=TIMEOUT)
            sub.raise_for_status()
            r = requests.get(f"{_BASE}/urls/{_url_id(url)}", headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return _normalize(stats, data["data"]["attributes"])
    except Exception as e:
        log.warning(f"[virustotal] lookup failed: {e}")
        return None
