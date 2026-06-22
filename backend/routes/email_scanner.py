import logging
import email as email_lib
from flask import Blueprint, request, jsonify
from models.database import insert_email_scan, _get_db
from services import email_phishing_service, alert_service
from datetime import datetime, timedelta

log = logging.getLogger(__name__)
bp = Blueprint("email_scanner", __name__, url_prefix="/email_scanner")


def _already_scanned(sender, subject, hours=24):
    """Returns True if this sender+subject was already scanned within the last N hours."""
    try:
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        return _get_db()["email_scans"].find_one({
            "sender": sender, "subject": subject,
            "timestamp": {"$gte": cutoff}
        }) is not None
    except Exception:
        return False


@bp.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    sender  = (data.get("sender")  or "").strip()
    subject = (data.get("subject") or "").strip()
    body    = (data.get("body")    or "").strip()

    if not body and not subject:
        return jsonify({"error": "Provide at least the email body or subject."}), 400

    em = {"id": "manual", "sender": sender, "subject": subject, "body": body,
          "reply_to": "", "attachments": []}
    assessment = email_phishing_service.analyze(em)

    if not _already_scanned(sender, subject):
        insert_email_scan("manual", sender, subject,
                          assessment["phishing_score"], assessment["label"],
                          assessment["flagged_urls"], assessment["signals"])

    alert_service.maybe_alert("Email", [{
        "title": subject or sender or "Manual scan",
        "score": assessment["phishing_score"],
        "label": assessment["label"],
    }])

    return jsonify({
        "scanned": 1,
        "flagged": 1 if assessment["phishing_score"] >= _STORE_THRESHOLD else 0,
        "results": [{
            "sender":         sender,
            "subject":        subject,
            "phishing_score": assessment["phishing_score"],
            "label":          assessment["label"],
            "flagged_urls":   assessment["flagged_urls"],
            "signals":        assessment["signals"],
        }],
    })


@bp.route("/api/scan-eml", methods=["POST"])
def scan_eml():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file uploaded."}), 400

    try:
        msg = email_lib.message_from_bytes(f.read())
    except Exception:
        return jsonify({"error": "Could not parse .eml file."}), 400

    sender  = msg.get("From", "")
    subject = msg.get("Subject", "")
    reply_to = msg.get("Reply-To", "")
    body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd:
                fn = part.get_filename() or ""
                if fn:
                    attachments.append(fn)
            elif ct == "text/plain" and not body:
                body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
            elif ct == "text/html" and not body:
                import re
                raw = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                body = re.sub(r"<[^>]+>", " ", raw)
    else:
        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")

    em = {"id": "eml", "sender": sender, "subject": subject,
          "body": body, "reply_to": reply_to, "attachments": attachments}
    assessment = email_phishing_service.analyze(em)

    if not _already_scanned(sender, subject):
        insert_email_scan("eml", sender, subject,
                          assessment["phishing_score"], assessment["label"],
                          assessment["flagged_urls"], assessment["signals"])

    return jsonify({
        "scanned": 1,
        "flagged": 1 if assessment["phishing_score"] >= _STORE_THRESHOLD else 0,
        "results": [{
            "sender":         sender,
            "subject":        subject,
            "phishing_score": assessment["phishing_score"],
            "label":          assessment["label"],
            "flagged_urls":   assessment["flagged_urls"],
            "signals":        assessment["signals"],
        }],
    })
