import eventlet
eventlet.monkey_patch()

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, redirect, url_for
from flask_socketio import SocketIO
import config
import realtime

from routes.dashboard import bp as dashboard_bp
from routes.check_url import bp as check_url_bp
from routes.soc_analyzer import bp as soc_analyzer_bp
from routes.scan_qr import bp as scan_qr_bp
from routes.email_scanner import bp as email_scanner_bp
from routes.settings import bp as settings_bp
from routes.ip_lookup import bp as ip_lookup_bp
from routes.file_scan import bp as file_scan_bp
from routes.geo import bp as geo_bp

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["TEMPLATES_AUTO_RELOAD"] = config.DEBUG

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
realtime.init(socketio)

app.register_blueprint(dashboard_bp)
app.register_blueprint(check_url_bp)
app.register_blueprint(soc_analyzer_bp)
app.register_blueprint(scan_qr_bp)
app.register_blueprint(email_scanner_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(ip_lookup_bp)
app.register_blueprint(file_scan_bp)
app.register_blueprint(geo_bp)

@app.route("/")
def index():
    return redirect(url_for("dashboard.dashboard"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", debug=config.DEBUG,
                 port=port, allow_unsafe_werkzeug=True)
