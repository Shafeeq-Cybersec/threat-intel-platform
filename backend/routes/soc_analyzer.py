import logging
from collections import Counter
from flask import Blueprint, request, jsonify
from models.database import insert_soc_event
from realtime import SEV_SCORE
from services import log_analyzer, alert_service, mitre_service

log = logging.getLogger(__name__)
bp = Blueprint("soc_analyzer", __name__)

_MAX_BYTES = 2 * 1024 * 1024  # 2 MB upload cap


@bp.route("/api/soc-analyzer", methods=["POST"])
def soc_analyzer():
    text = ""
    # 1) file upload
    if "file" in request.files and request.files["file"].filename:
        raw = request.files["file"].read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            return jsonify({"error": "file too large (max 2MB)"}), 413
        text = raw.decode("utf-8", errors="replace")
    else:
        # 2) pasted text (JSON or form)
        body = request.get_json(silent=True) or {}
        text = body.get("log_text") or request.form.get("log_text") or ""

    text = text.strip()
    if not text:
        return jsonify({"error": "provide a log file or 'log_text'"}), 400

    events = log_analyzer.analyze(text)

    # Tag each detection with its MITRE ATT&CK technique
    for e in events:
        e["mitre"] = mitre_service.map_category(e["category"], e.get("explanation", ""))

    for e in events:
        insert_soc_event(e["raw_log_line"], e["severity"], e["category"],
                         e["explanation"], e["ai_assisted"])

    alert_service.maybe_alert("SOC", [{"title": e["category"], "score": SEV_SCORE.get(e["severity"], 0),
                                       "label": e["severity"]} for e in events])

    sev_counts = Counter(e["severity"] for e in events)
    return jsonify({
        "lines_analyzed": len([l for l in text.splitlines() if l.strip()]),
        "flagged_count": len(events),
        "severity_breakdown": dict(sev_counts),
        "events": events,
    })
