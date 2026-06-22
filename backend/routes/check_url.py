import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, request, jsonify
from models.database import get_recent_log, insert_threat_log
from services import risk_aggregator, alert_service

log = logging.getLogger(__name__)
bp = Blueprint("check_url", __name__)

_MAX_BULK = 20  # cap to keep one request bounded


@bp.route("/check-url", methods=["POST"])
def check_url():
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    force_refresh = bool(body.get("force_refresh", False))

    if not url:
        return jsonify({"error": "missing 'url'"}), 400

    if not force_refresh:
        cached = get_recent_log("url", url, max_age_minutes=1440)
        if cached:
            try:
                raw = json.loads(cached["raw_response"] or "{}")
                factors = raw.get("assessment", {}).get("factors", [])
                reasoning = raw.get("assessment", {}).get("reasoning", "")
            except Exception:
                factors, reasoning = [], ""
            return jsonify({
                "risk_score": cached["risk_score"],
                "threat": cached["threat_label"],
                "sources": json.loads(cached["sources_used"] or "[]"),
                "reasoning": reasoning,
                "factors": factors,
                "timestamp": cached["timestamp"],
                "cached": True,
            })

    result = risk_aggregator.analyze_url(url)

    insert_threat_log(
        source_type="url",
        input_value=url,
        risk_score=result["risk_score"],
        threat_label=result["threat_label"],
        sources_used=result["sources_used"],
        raw_response=result["raw_response"],
    )

    alert_service.maybe_alert("URL", [{"title": url, "score": result["risk_score"],
                                       "label": result["threat_label"]}])

    return jsonify({
        "risk_score": result["risk_score"],
        "threat": result["threat_label"],
        "sources": result["sources_used"],
        "reasoning": result.get("reasoning", ""),
        "factors": result.get("factors", []),
        "cached": False,
    })


def _scan_one(url: str) -> dict:
    """Scan a single URL through the pipeline (cache-aware) and persist. Used by bulk."""
    cached = get_recent_log("url", url, max_age_minutes=1440)
    if cached:
        return {"url": url, "risk_score": cached["risk_score"],
                "threat": cached["threat_label"], "cached": True}
    result = risk_aggregator.analyze_url(url)
    insert_threat_log(
        source_type="url", input_value=url,
        risk_score=result["risk_score"], threat_label=result["threat_label"],
        sources_used=result["sources_used"], raw_response=result["raw_response"],
    )
    return {"url": url, "risk_score": result["risk_score"],
            "threat": result["threat_label"], "cached": False}


@bp.route("/check-url/bulk", methods=["POST"])
def check_url_bulk():
    body = request.get_json(silent=True) or {}
    raw = body.get("urls", "")
    if isinstance(raw, str):
        candidates = re.split(r"[\s,]+", raw)
    else:
        candidates = list(raw or [])

    # Normalise, de-dupe, keep order
    seen, urls = set(), []
    for c in candidates:
        c = (c or "").strip()
        if not c:
            continue
        if not re.match(r"^https?://", c, re.I):
            c = "http://" + c
        if c not in seen:
            seen.add(c)
            urls.append(c)

    if not urls:
        return jsonify({"error": "no valid URLs provided"}), 400
    if len(urls) > _MAX_BULK:
        return jsonify({"error": f"too many URLs (max {_MAX_BULK})"}), 400

    results = []
    with ThreadPoolExecutor(max_workers=min(len(urls), 5)) as pool:
        futures = {pool.submit(_scan_one, u): u for u in urls}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                log.warning(f"[bulk] scan failed for {futures[fut]}: {e}")
                results.append({"url": futures[fut], "risk_score": None,
                                "threat": "Error", "cached": False})

    alert_service.maybe_alert("URL (bulk)", [
        {"title": r["url"], "score": r["risk_score"] or 0, "label": r["threat"]}
        for r in results
    ])

    results.sort(key=lambda r: r["risk_score"] if r["risk_score"] is not None else -1, reverse=True)
    high = sum(1 for r in results if (r["risk_score"] or 0) >= 70)
    return jsonify({"scanned": len(results), "high_risk": high, "results": results})
