from flask import Blueprint, render_template
from datetime import datetime

bp = Blueprint("dashboard", __name__)

@bp.route("/dashboard")
def dashboard():
    try:
        from models.database import _get_db
        _get_db().command("ping")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {e}"

    return render_template(
        "dashboard.html",
        db_status=db_status,
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
