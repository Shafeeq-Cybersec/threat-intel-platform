import re
import hashlib
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from services import virustotal_service

log = logging.getLogger(__name__)
bp = Blueprint("file_scan", __name__)

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_MAX_FILE_MB = 32


def _verdict(score, found):
    if not found:
        return "Unknown"
    if score >= 50:
        return "Malicious"
    if score >= 15:
        return "Suspicious"
    return "Clean"


def _fmt_ts(unix):
    if not unix:
        return None
    try:
        return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return None


@bp.route("/api/file-scan", methods=["POST"])
def file_scan():
    file_hash = None
    file_meta = {}

    # Path 1: a file was uploaded, hash it locally (contents never leave this server)
    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        data = f.read()
        if len(data) > _MAX_FILE_MB * 1024 * 1024:
            return jsonify({"error": f"File too large (max {_MAX_FILE_MB} MB)."}), 400
        file_hash = hashlib.sha256(data).hexdigest()
        file_meta = {"uploaded_name": f.filename, "uploaded_size": len(data)}
    else:
        # Path 2: a hash string was provided
        body = request.get_json(silent=True) or request.form
        file_hash = (body.get("hash") or "").strip()
        if not _HASH_RE.match(file_hash):
            return jsonify({"error": "Provide a file, or a valid MD5/SHA-1/SHA-256 hash."}), 400

    result = virustotal_service.check_file_hash(file_hash)
    if "error" in result:
        return jsonify(result), 502

    result["query_hash"] = file_hash
    result.update(file_meta)
    result["verdict"] = _verdict(result.get("score", 0), result.get("found"))
    result["first_seen"] = _fmt_ts(result.get("first_seen"))
    result["last_analyzed"] = _fmt_ts(result.get("last_analyzed"))
    return jsonify(result)
