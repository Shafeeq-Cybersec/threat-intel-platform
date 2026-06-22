import logging
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
import realtime

log = logging.getLogger(__name__)

_db = None

def _get_db():
    global _db
    if _db is None:
        from pymongo import MongoClient, DESCENDING, ASCENDING
        client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
        _db = client["threat_intel"]
        _db["threat_logs"].create_index([("timestamp", DESCENDING)])
        _db["threat_logs"].create_index([("source_type", ASCENDING)])
        _db["threat_logs"].create_index([("input_value", ASCENDING), ("timestamp", DESCENDING)])
        _db["soc_events"].create_index([("timestamp", DESCENDING)])
        _db["email_scans"].create_index([("timestamp", DESCENDING)])
    return _db


def init_db():
    try:
        db = _get_db()
        db.command("ping")
        print("[DB] MongoDB connected successfully")
    except Exception as e:
        print(f"[DB] MongoDB connection failed: {e}")


# --- Write functions ---

def insert_soc_event(raw_log_line, severity, category=None, explanation=None, ai_assisted=False):
    ts = datetime.utcnow().isoformat()
    try:
        _get_db()["soc_events"].insert_one({
            "timestamp": ts,
            "raw_log_line": raw_log_line,
            "severity": severity,
            "category": category,
            "explanation": explanation,
            "ai_assisted": 1 if ai_assisted else 0,
        })
    except Exception as e:
        log.error(f"[DB] insert_soc_event failed: {e}")
    realtime.push_event({"kind": "soc", "title": category or raw_log_line[:90],
                         "score": realtime.SEV_SCORE.get(severity, 0), "label": severity, "timestamp": ts})


def insert_email_scan(gmail_id, sender, subject, phishing_score, label, flagged_urls=None, signals=None):
    ts = datetime.utcnow().isoformat()
    try:
        _get_db()["email_scans"].insert_one({
            "timestamp": ts,
            "gmail_id": gmail_id,
            "sender": sender,
            "subject": subject,
            "phishing_score": phishing_score,
            "label": label,
            "flagged_urls": flagged_urls or [],
            "signals": signals or [],
        })
    except Exception as e:
        log.error(f"[DB] insert_email_scan failed: {e}")
    realtime.push_event({"kind": "email", "title": (subject or sender or "")[:120],
                         "score": phishing_score, "label": label, "timestamp": ts})


def get_recent_log(source_type, input_value, max_age_minutes=60):
    cutoff = (datetime.utcnow() - timedelta(minutes=max_age_minutes)).isoformat()
    try:
        row = _get_db()["threat_logs"].find_one(
            {"source_type": source_type, "input_value": input_value, "timestamp": {"$gte": cutoff}},
            sort=[("timestamp", -1)]
        )
        if row:
            row.pop("_id", None)
            return row
    except Exception as e:
        log.error(f"[DB] get_recent_log failed: {e}")
    return None


def insert_threat_log(source_type, input_value, risk_score=None,
                      threat_label=None, sources_used=None, raw_response=None):
    ts = datetime.utcnow().isoformat()
    try:
        _get_db()["threat_logs"].insert_one({
            "timestamp": ts,
            "source_type": source_type,
            "input_value": input_value,
            "risk_score": risk_score,
            "threat_label": threat_label,
            "sources_used": sources_used or [],
            "raw_response": raw_response or {},
        })
    except Exception as e:
        log.error(f"[DB] insert_threat_log failed: {e}")
    realtime.push_event({"kind": source_type, "title": (input_value or "")[:120],
                         "score": risk_score, "label": threat_label, "timestamp": ts})


# --- Read functions ---

def get_all_threat_logs(cutoff_date=None):
    q = {"timestamp": {"$gte": cutoff_date}} if cutoff_date else {}
    try:
        return list(_get_db()["threat_logs"].find(q, {"_id": 0}))
    except Exception as e:
        log.error(f"[DB] get_all_threat_logs failed: {e}")
        return []


def get_all_soc_events(cutoff_date=None):
    q = {"timestamp": {"$gte": cutoff_date}} if cutoff_date else {}
    try:
        return list(_get_db()["soc_events"].find(q, {"_id": 0}))
    except Exception as e:
        log.error(f"[DB] get_all_soc_events failed: {e}")
        return []


def get_all_email_scans(cutoff_date=None):
    q = {"timestamp": {"$gte": cutoff_date}} if cutoff_date else {}
    try:
        return list(_get_db()["email_scans"].find(q, {"_id": 0}))
    except Exception as e:
        log.error(f"[DB] get_all_email_scans failed: {e}")
        return []


def get_recent_feed(limit=20):
    try:
        db = _get_db()
        items = []
        for r in db["threat_logs"].find({}, {"_id": 0}).sort("timestamp", -1).limit(limit):
            items.append({"kind": r.get("source_type"), "title": r.get("input_value"),
                          "score": r.get("risk_score"), "label": r.get("threat_label"),
                          "timestamp": r.get("timestamp")})
        for r in db["soc_events"].find({}, {"_id": 0}).sort("timestamp", -1).limit(limit):
            items.append({"kind": "soc", "title": r.get("category") or r.get("raw_log_line"),
                          "score": realtime.SEV_SCORE.get(r.get("severity"), 0),
                          "label": r.get("severity"), "timestamp": r.get("timestamp")})
        for r in db["email_scans"].find({}, {"_id": 0}).sort("timestamp", -1).limit(limit):
            items.append({"kind": "email", "title": r.get("subject") or r.get("sender"),
                          "score": r.get("phishing_score"), "label": r.get("label"),
                          "timestamp": r.get("timestamp")})
        items.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
        return items[:25]
    except Exception as e:
        log.error(f"[DB] get_recent_feed failed: {e}")
        return []
