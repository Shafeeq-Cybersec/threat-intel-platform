import os
import logging
from flask import Blueprint, request, jsonify
from models.database import insert_threat_log, get_recent_log
from services import qr_service, alert_service

log = logging.getLogger(__name__)
bp = Blueprint("scan_qr", __name__)

_MAX_BYTES = 5 * 1024 * 1024  # 5 MB image cap
_SAMPLE_QR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "sample_data", "qr_test_malicious.png")


@bp.route("/api/scan-qr", methods=["POST"])
def scan_qr():
    # Demo path: scan the bundled sample QR (lets a first-time user try it instantly)
    if (request.get_json(silent=True) or {}).get("sample") or request.args.get("sample"):
        try:
            with open(_SAMPLE_QR, "rb") as fh:
                raw = fh.read()
        except OSError:
            return jsonify({"error": "sample QR image not available"}), 404
        return _scan_bytes(raw)

    f = request.files.get("qr_image")
    if not f or not f.filename:
        return jsonify({"error": "missing 'qr_image' file"}), 400

    raw = f.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        return jsonify({"error": "image too large (max 5MB)"}), 413

    return _scan_bytes(raw)


def _scan_bytes(raw):
    res = qr_service.analyze(raw)
    if "error" in res:
        return jsonify(res), 422

    if not get_recent_log("qr", res["decoded_url"], max_age_minutes=1440):
        insert_threat_log(
            source_type="qr",
            input_value=res["decoded_url"],
            risk_score=res["risk_score"],
            threat_label=res["threat_label"],
            sources_used=res["sources_used"],
            raw_response=res["raw_response"],
        )

    alert_service.maybe_alert("QR", [{"title": res["decoded_url"], "score": res["risk_score"],
                                      "label": res["threat_label"]}])

    return jsonify({
        "decoded_url": res["decoded_url"],
        "risk_score": res["risk_score"],
        "threat": res["threat_label"],
        "sources": res["sources_used"],
    })
