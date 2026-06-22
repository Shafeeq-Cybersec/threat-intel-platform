import logging
from services import (virustotal_service, safebrowsing_service, rdap_service,
                      phishtank_service, gemini_service)

log = logging.getLogger(__name__)

_DISPLAY = {
    "virustotal": "VirusTotal",
    "safe_browsing": "Safe Browsing",
    "rdap": "RDAP",
    "phishtank": "PhishTank",
    "gemini": "Gemini",
}


def analyze_url(url: str) -> dict:
    """Runs the URL through every configured source + Gemini, returns a unified verdict."""
    source_results = []
    for svc in (virustotal_service, safebrowsing_service, rdap_service, phishtank_service):
        try:
            res = svc.check_url(url)
        except Exception as e:
            log.warning(f"[aggregator] {svc.__name__} raised: {e}")
            res = None
        if res:
            source_results.append(res)

    verdict = gemini_service.assess(url, source_results)

    sources_used = [_DISPLAY[r["source"]] for r in source_results]
    if not verdict.get("_fallback"):
        sources_used.append("Gemini")
    elif verdict.get("factors"):
        sources_used.append("Heuristics")

    return {
        "risk_score": verdict["risk_score"],
        "threat_label": verdict["threat_label"],
        "reasoning": verdict.get("reasoning", ""),
        "factors": verdict.get("factors", []),
        "sources_used": sources_used,
        "raw_response": {
            "sources": source_results,
            "assessment": verdict,
        },
    }
