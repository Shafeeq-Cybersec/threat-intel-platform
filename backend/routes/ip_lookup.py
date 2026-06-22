import logging
from flask import Blueprint, request, jsonify
from services import lookup_service

log = logging.getLogger(__name__)
bp = Blueprint("ip_lookup", __name__)


@bp.route("/api/ip-lookup", methods=["POST"])
def ip_lookup():
    body = request.get_json(silent=True) or {}
    value = (body.get("value") or "").strip()
    if not value:
        return jsonify({"error": "missing 'value'"}), 400
    result = lookup_service.lookup(value)
    status = 200 if "error" not in result else 400
    return jsonify(result), status
