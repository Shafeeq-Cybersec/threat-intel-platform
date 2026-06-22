import logging

log = logging.getLogger(__name__)
_socketio = None


def init(socketio):
    """Called once from app.py after the SocketIO instance is created."""
    global _socketio
    _socketio = socketio


def push_event(item: dict):
    """Broadcast a single feed item to all connected dashboard clients."""
    if _socketio is None:
        return
    try:
        _socketio.emit("threat_event", item)
    except Exception as e:
        log.warning(f"[realtime] emit failed: {e}")


def push_email_result(row: dict):
    if _socketio is None:
        return
    try:
        _socketio.emit("email_scan_result", row)
    except Exception as e:
        log.warning(f"[realtime] email emit failed: {e}")


def push_email_done(summary: dict):
    if _socketio is None:
        return
    try:
        _socketio.emit("email_scan_done", summary)
    except Exception as e:
        log.warning(f"[realtime] email done emit failed: {e}")


# severity -> 0-100 score, so the feed can color logs the same way as URLs/emails
SEV_SCORE = {"critical": 90, "high": 75, "medium": 50, "low": 20}
