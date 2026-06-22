import os
import uuid
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_client = None
_db = None


def _get_db():
    global _client, _db
    if _db is None:
        from pymongo import MongoClient
        uri = os.environ.get("MONGO_URI", "")
        if not uri:
            raise RuntimeError("MONGO_URI environment variable is not set")
        _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        _db = _client["threat_intel"]
        _db.access_requests.create_index("token", sparse=True)
        _db.access_requests.create_index("status")
        log.info("[mongo] connected to Atlas")
    return _db


def create_request(name: str, role: str, description: str, email: str) -> dict:
    db = _get_db()
    doc = {
        "name": name,
        "role": role,
        "description": description,
        "email": email,
        "status": "pending",
        "token": None,
        "created_at": datetime.now(timezone.utc),
    }
    result = db.access_requests.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    return doc


def get_all_requests() -> list:
    db = _get_db()
    docs = list(db.access_requests.find().sort("created_at", -1))
    for d in docs:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("created_at"), datetime):
            d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M UTC")
    return docs


def approve_request(request_id: str) -> str:
    from bson import ObjectId
    db = _get_db()
    token = str(uuid.uuid4())
    db.access_requests.update_one(
        {"_id": ObjectId(request_id)},
        {"$set": {"status": "approved", "token": token,
                  "approved_at": datetime.now(timezone.utc)}},
    )
    return token


def reject_request(request_id: str):
    from bson import ObjectId
    db = _get_db()
    db.access_requests.update_one(
        {"_id": ObjectId(request_id)},
        {"$set": {"status": "rejected",
                  "rejected_at": datetime.now(timezone.utc)}},
    )


def get_by_token(token: str) -> dict | None:
    db = _get_db()
    doc = db.access_requests.find_one({"token": token, "status": "approved"})
    if doc:
        doc["_id"] = str(doc["_id"])
    return doc


def mark_used(token: str):
    db = _get_db()
    db.access_requests.update_one(
        {"token": token},
        {"$set": {"status": "used", "used_at": datetime.now(timezone.utc)}},
    )
