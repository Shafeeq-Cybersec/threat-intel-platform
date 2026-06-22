import json
import logging
import re
from urllib.parse import urlparse
import config

log = logging.getLogger(__name__)
_MODEL = "gemini-2.0-flash-lite"
_VALID_LABELS = {"Phishing", "Malware", "Safe", "Suspicious", "Unknown"}

# Heuristic phishing signals used when the AI is unavailable
_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "zip", "mov", "click", "link",
    "work", "country", "stream", "download", "loan", "racing", "rest", "fit",
    "review", "kim", "men", "date", "win", "bid", "trade", "party", "gdn",
}
_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "netflix", "outlook", "office365", "wellsfargo", "chase", "coinbase",
    "binance", "metamask", "whatsapp", "linkedin", "dhl", "fedex", "ups", "usps",
    "irs", "icloud", "dropbox", "steam", "roblox", "bankofamerica",
]
_CRED_WORDS = [
    "verify", "login", "signin", "account", "secure", "update", "confirm",
    "password", "banking", "wallet", "unlock", "suspend", "validate",
    "authenticate", "recover", "billing", "invoice", "payment",
]
_LEET = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "4": "a", "7": "t", "$": "s"})


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def heuristic_url_score(url: str):
    """Returns (score 0-95, label, factors[]) from URL structure alone."""
    try:
        p = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return 0, "Unknown", []
    host = (p.hostname or "").lower()
    path = (p.path or "").lower()
    if not host:
        return 0, "Unknown", []

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    reg = _registrable(host)
    blob = host + path
    deleet = blob.translate(_LEET)
    factors = []
    score = 0

    # Raw IP address as host
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 35; factors.append({"label": "Raw IP address host", "points": 35})

    # High-risk TLD
    if tld in _SUSPICIOUS_TLDS:
        score += 25; factors.append({"label": f"High-risk .{tld} domain", "points": 25})

    # Punycode (homograph attacks)
    if "xn--" in host:
        score += 20; factors.append({"label": "Punycode / homograph domain", "points": 20})

    # Brand impersonation: a known brand appears (even leetspeak), but the
    # registrable domain is not that brand's real domain.
    for brand in _BRANDS:
        if (brand in deleet or brand in blob) and not reg.startswith(brand):
            score += 30; factors.append({"label": f"Impersonates '{brand}'", "points": 30})
            break

    # Credential-harvesting language in host/path
    hits = [w for w in _CRED_WORDS if w in deleet]
    if hits:
        pts = min(10 + 5 * (len(hits) - 1), 20)
        score += pts
        factors.append({"label": f"Credential-harvesting terms ({', '.join(hits[:3])})", "points": pts})

    # Structural noise: many hyphens or deep subdomains
    if host.count("-") >= 2:
        score += 8; factors.append({"label": "Multiple hyphens in domain", "points": 8})
    if host.count(".") >= 4:
        score += 8; factors.append({"label": "Excessive subdomains", "points": 8})

    # "@" trick in the authority
    if "@" in (p.netloc or ""):
        score += 20; factors.append({"label": "Embedded '@' redirect trick", "points": 20})

    score = min(score, 95)
    # A lone credential word on an otherwise clean domain is not enough to flag.
    label = "Phishing" if score >= 60 else "Suspicious" if score >= 25 else "Safe"
    return score, label, factors


def _fallback(other_results: list, url: str = "", reason: str = "not_configured") -> dict:
    """AI unavailable: blend a structural phishing heuristic with the other sources'
    scores, taking the stronger signal so obvious phishing is never diluted to zero."""
    scored = [r for r in other_results if r]
    avg = round(sum(r["score"] for r in scored) / len(scored)) if scored else 0
    h_score, h_label, h_factors = heuristic_url_score(url) if url else (0, "Safe", [])

    final = max(avg, h_score)
    if final >= 70:
        label = "Malware" if any(r["source"] == "safe_browsing" and r["malicious"] for r in scored) else "Phishing"
    elif final >= 25:
        label = "Suspicious"
    else:
        label = "Safe"

    why = {"not_configured": "Gemini not configured",
           "rate_limited": "Gemini rate-limited",
           "unavailable": "Gemini unavailable"}.get(reason, "Gemini unavailable")
    if h_factors and h_score >= avg:
        reasoning = f"Heuristic analysis of URL structure ({why}; AI verification skipped)."
    elif scored:
        reasoning = f"Weighted average of {len(scored)} source(s) ({why})."
    else:
        reasoning = f"No threat sources were available ({why})."

    return {"risk_score": final, "threat_label": label, "reasoning": reasoning,
            "factors": h_factors, "_fallback": True}


def _parse_json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return json.loads(m.group(0)) if m else {}


def assess(url: str, other_results: list) -> dict:
    if not config.is_configured("gemini"):
        log.warning("[gemini] no API key, using heuristic fallback")
        return _fallback(other_results, url, "not_configured")

    import google.generativeai as genai
    evidence = [{"source": r["source"], "malicious": r["malicious"], "score": r["score"]}
                for r in other_results if r]
    prompt = (
        "You are a cybersecurity analyst. Assess this URL's risk using the evidence from "
        "threat-intel sources. Respond with ONLY a JSON object, no markdown, with these keys: "
        "risk_score (0-100 integer), "
        "threat_label (one of: Phishing, Malware, Safe, Suspicious, Unknown), "
        "reasoning (one short sentence), "
        "factors (array of up to 6 objects each with 'label' string and 'points' positive integer "
        "showing what signals contributed to the score, e.g. Brand Impersonation +25).\n\n"
        f"URL: {url}\nEvidence: {json.dumps(evidence)}"
    )
    for attempt in range(len(config._GEMINI_KEYS) or 1):
        try:
            genai.configure(api_key=config.get_gemini_key())
            resp = genai.GenerativeModel(_MODEL).generate_content(prompt)
            result = _parse_json(resp.text)
            score = int(result.get("risk_score", 0))
            label = result.get("threat_label", "Unknown")
            if label not in _VALID_LABELS:
                label = "Unknown"
            factors = result.get("factors", [])
            if not isinstance(factors, list):
                factors = []
            return {
                "risk_score": max(0, min(score, 100)),
                "threat_label": label,
                "reasoning": result.get("reasoning", ""),
                "factors": factors,
                "_fallback": False,
            }
        except Exception as e:
            msg = str(e).lower()
            if ("429" in msg or "quota" in msg or "rate limit" in msg) and len(config._GEMINI_KEYS) > 1:
                log.warning(f"[gemini] key {config._gemini_key_index + 1} rate limited, rotating to next key")
                config.rotate_gemini_key()
            else:
                reason = "rate_limited" if ("429" in msg or "quota" in msg) else "unavailable"
                log.warning(f"[gemini] assessment failed ({reason}): {e}")
                return _fallback(other_results, url, reason)
    return _fallback(other_results, url, "rate_limited")
