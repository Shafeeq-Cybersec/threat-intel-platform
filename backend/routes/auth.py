import os
import time
import logging
from collections import defaultdict
from flask import (Blueprint, request, jsonify, render_template,
                   redirect, url_for, session)
from services import mongo_service, mail_service

log = logging.getLogger(__name__)
bp = Blueprint("auth", __name__)

_register_hits: dict = defaultdict(list)
_RATE_LIMIT = 5
_RATE_WINDOW = 3600


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _register_hits[ip] if now - t < _RATE_WINDOW]
    _register_hits[ip] = hits
    if len(hits) >= _RATE_LIMIT:
        return True
    _register_hits[ip].append(now)
    return False


def _base_url() -> str:
    return os.environ.get("BASE_URL", "http://localhost:5000").rstrip("/")


def _admin_key() -> str:
    return os.environ.get("ADMIN_KEY", "")


def is_authorised() -> bool:
    return bool(session.get("is_admin") or session.get("access_token"))


@bp.route("/register")
def register_page():
    return render_template("register.html")


@bp.route("/api/register", methods=["POST"])
def register():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    role = (body.get("role") or "").strip()
    description = (body.get("description") or "").strip()
    email = (body.get("email") or "").strip()

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if _is_rate_limited(ip):
        return jsonify({"error": "Too many requests. Please wait an hour before trying again."}), 429

    if not name or not role or not email:
        return jsonify({"error": "Name, role, and email are required."}), 400
    if "@" not in email:
        return jsonify({"error": "Please enter a valid email address."}), 400

    try:
        mongo_service.create_request(name, role, description, email)
        admin_url = f"{_base_url()}/admin?key={_admin_key()}"
        mail_service.notify_admin(name, role, description, admin_url)
        return jsonify({"ok": True})
    except Exception as e:
        log.error(f"[auth] register failed: {e}")
        return jsonify({"error": "Could not save request. Please try again."}), 500


@bp.route("/access/<token>")
def access(token):
    doc = mongo_service.get_by_token(token)
    if not doc:
        return render_template("register.html",
                               error="This access link is invalid or has already been used.")
    session.permanent = False
    session["access_token"] = token
    session["user_name"] = doc.get("name", "")
    return redirect(url_for("dashboard.dashboard"))


@bp.route("/admin")
def admin_page():
    key = request.args.get("key", "")
    if not _admin_key() or key != _admin_key():
        return render_template("register.html", error="Unauthorized."), 401
    session["is_admin"] = True
    try:
        reqs = mongo_service.get_all_requests()
    except Exception as e:
        reqs = []
        log.error(f"[auth] admin fetch failed: {e}")
    return render_template("admin.html", requests=reqs)


@bp.route("/api/admin/approve/<request_id>", methods=["POST"])
def approve(request_id):
    if not session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        token = mongo_service.approve_request(request_id)
        all_reqs = mongo_service.get_all_requests()
        req = next((r for r in all_reqs if r["_id"] == request_id), None)
        if req and req.get("email"):
            access_url = f"{_base_url()}/access/{token}"
            mail_service.notify_approved(req["email"], req["name"], access_url)
        return jsonify({"ok": True})
    except Exception as e:
        log.error(f"[auth] approve failed: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/api/admin/reject/<request_id>", methods=["POST"])
def reject(request_id):
    if not session.get("is_admin"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        all_reqs = mongo_service.get_all_requests()
        req = next((r for r in all_reqs if r["_id"] == request_id), None)
        mongo_service.reject_request(request_id)
        if req and req.get("email"):
            mail_service.notify_rejected(req["email"], req["name"])
        return jsonify({"ok": True})
    except Exception as e:
        log.error(f"[auth] reject failed: {e}")
        return jsonify({"error": str(e)}), 500


@bp.route("/logout")
def logout():
    token = session.get("access_token")
    if token:
        try:
            mongo_service.mark_used(token)
        except Exception:
            pass
    session.clear()
    return redirect(url_for("auth.register_page"))
