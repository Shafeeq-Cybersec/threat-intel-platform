import io
import csv
from flask import Blueprint, jsonify, Response, request
import config
from models.database import (
    get_all_threat_logs, get_all_soc_events, get_all_email_scans, get_recent_feed
)
from realtime import SEV_SCORE

bp = Blueprint("settings", __name__)

_SERVICES = [
    ("virustotal", "VirusTotal", "URL/QR/email link reputation (70+ engines)"),
    ("safe_browsing", "Google Safe Browsing", "Google's blocklist of known-malicious URLs"),
    ("abuseipdb", "AbuseIPDB", "Malicious-IP reputation in SOC logs"),
    ("phishtank", "PhishTank", "Community phishing DB (built; new API keys closed by Cisco, optional)"),
    ("gemini", "Gemini AI", "AI risk scoring + written reasoning"),
]

_EXPORTABLE = {"threat_logs", "soc_events", "email_scans"}


@bp.route("/api/settings")
def settings():
    return jsonify({
        "services": [
            {"key": k, "name": n, "desc": d, "configured": config.is_configured(k)}
            for k, n, d in _SERVICES
        ],
        "alert_threshold": config.ALERT_THRESHOLD,
    })


def _band(score):
    if score is None:
        return None
    if score >= 70:
        return "high"
    return "medium" if score >= 40 else "low"


@bp.route("/api/stats")
def stats():
    bands = {"high": 0, "medium": 0, "low": 0}
    tl = get_all_threat_logs()
    soc = get_all_soc_events()
    em = get_all_email_scans()
    for r in tl:
        b = _band(r.get("risk_score"))
        if b:
            bands[b] += 1
    for r in em:
        b = _band(r.get("phishing_score"))
        if b:
            bands[b] += 1
    for r in soc:
        b = _band(SEV_SCORE.get(r.get("severity"), 0))
        if b:
            bands[b] += 1
    active = sum(1 for k, _, _ in _SERVICES if config.is_configured(k))
    return jsonify({
        "total": len(tl) + len(soc) + len(em),
        "high": bands["high"], "medium": bands["medium"], "low": bands["low"],
        "emails": len(em), "url_qr": len(tl), "log_events": len(soc),
        "sources_active": active, "sources_total": len(_SERVICES),
    })


@bp.route("/api/feed")
def feed():
    return jsonify(get_recent_feed(limit=20))


@bp.route("/api/history")
def history():
    from datetime import datetime, timedelta
    try:
        days = max(1, min(int(request.args.get("days", 7)), 90))
    except (TypeError, ValueError):
        days = 7

    today = datetime.utcnow().date()
    date_keys = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    buckets = {d: {"total": 0, "high": 0, "medium": 0, "low": 0} for d in date_keys}
    cutoff = (today - timedelta(days=days - 1)).isoformat()

    def add(ts, band):
        d = (ts or "")[:10]
        b = buckets.get(d)
        if b:
            b["total"] += 1
            b[band] += 1

    for r in get_all_threat_logs(cutoff_date=cutoff):
        band = _band(r.get("risk_score"))
        if band:
            add(r.get("timestamp"), band)
    for r in get_all_email_scans(cutoff_date=cutoff):
        band = _band(r.get("phishing_score"))
        if band:
            add(r.get("timestamp"), band)
    for r in get_all_soc_events(cutoff_date=cutoff):
        band = _band(SEV_SCORE.get(r.get("severity"), 0))
        if band:
            add(r.get("timestamp"), band)

    return jsonify({
        "days":   date_keys,
        "total":  [buckets[d]["total"] for d in date_keys],
        "high":   [buckets[d]["high"] for d in date_keys],
        "medium": [buckets[d]["medium"] for d in date_keys],
        "low":    [buckets[d]["low"] for d in date_keys],
    })


@bp.route("/api/report.pdf")
def report_pdf():
    from datetime import datetime
    from services import report_service
    try:
        days = max(1, min(int(request.args.get("days", 7)), 90))
    except (TypeError, ValueError):
        days = 7
    pdf_bytes = report_service.generate(days)
    fname = f"threat-report-{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return Response(pdf_bytes, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


@bp.route("/api/export/<table>.csv")
def export(table):
    if table not in _EXPORTABLE:
        return jsonify({"error": "unknown table"}), 404
    if table == "threat_logs":
        rows = get_all_threat_logs()
    elif table == "soc_events":
        rows = get_all_soc_events()
    else:
        rows = get_all_email_scans()
    out = io.StringIO()
    writer = csv.writer(out)
    if rows:
        writer.writerow(rows[0].keys())
        for r in rows:
            writer.writerow(r.values())
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={table}.csv"})
