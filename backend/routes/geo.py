import logging
from flask import Blueprint, jsonify
from models.database import get_all_soc_events, get_all_threat_logs
from realtime import SEV_SCORE
from services import geo_service

log = logging.getLogger(__name__)
bp = Blueprint("geo", __name__)


@bp.route("/api/geo-threats")
def geo_threats():
    ip_hits = {}

    def add(ip, score, label):
        h = ip_hits.get(ip)
        if h:
            h["count"] += 1
            if score > h["max_score"]:
                h["max_score"] = score
                h["label"] = label
        else:
            ip_hits[ip] = {"count": 1, "max_score": score, "label": label}

    for r in get_all_soc_events()[-500:]:
        score = SEV_SCORE.get(r.get("severity"), 0)
        for ip in geo_service.extract_ips(r.get("raw_log_line", "")):
            add(ip, score, r.get("category") or "SOC event")

    for r in get_all_threat_logs()[-500:]:
        for ip in geo_service.extract_ips(r.get("input_value", "")):
            add(ip, r.get("risk_score") or 0, r.get("threat_label") or "Threat")

    geo = geo_service.geolocate(list(ip_hits.keys()))

    points = []
    for ip, info in ip_hits.items():
        g = geo.get(ip)
        if not g:
            continue
        points.append({
            "ip": ip,
            "lat": g["lat"], "lon": g["lon"],
            "country": g["country"], "city": g["city"],
            "count": info["count"], "score": info["max_score"], "label": info["label"],
        })
    points.sort(key=lambda p: p["score"], reverse=True)

    by_country = {}
    for p in points:
        c = p["country"] or "Unknown"
        by_country[c] = by_country.get(c, 0) + p["count"]
    top_countries = sorted(by_country.items(), key=lambda kv: kv[1], reverse=True)[:8]

    return jsonify({
        "points": points,
        "total_ips": len(points),
        "total_events": sum(p["count"] for p in points),
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
    })
