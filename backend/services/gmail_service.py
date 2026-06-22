import os
import base64
import logging
import config

log = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CRED_PATH = config.GMAIL_CREDENTIALS_PATH
TOKEN_PATH = os.path.join(os.path.dirname(CRED_PATH), "token.json")


def _restore_token_from_env():
    """On Render (or any deployment), restore token.json from GMAIL_TOKEN_B64 env var."""
    b64 = os.environ.get("GMAIL_TOKEN_B64", "").strip()
    if not b64 or os.path.exists(TOKEN_PATH):
        return
    try:
        os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
        with open(TOKEN_PATH, "w") as f:
            f.write(base64.b64decode(b64).decode())
        log.info("[gmail] Restored token.json from GMAIL_TOKEN_B64 env var.")
    except Exception as e:
        log.warning(f"[gmail] Could not restore token from env: {e}")


def _restore_creds_from_env():
    """On Render, restore credentials.json from GMAIL_CREDENTIALS_B64 env var."""
    b64 = os.environ.get("GMAIL_CREDENTIALS_B64", "").strip()
    if not b64 or os.path.exists(CRED_PATH):
        return
    try:
        os.makedirs(os.path.dirname(CRED_PATH), exist_ok=True)
        with open(CRED_PATH, "w") as f:
            f.write(base64.b64decode(b64).decode())
        log.info("[gmail] Restored credentials.json from GMAIL_CREDENTIALS_B64 env var.")
    except Exception as e:
        log.warning(f"[gmail] Could not restore credentials from env: {e}")


_restore_creds_from_env()
_restore_token_from_env()


def credentials_present() -> bool:
    return os.path.exists(CRED_PATH)


def is_authorized() -> bool:
    return os.path.exists(TOKEN_PATH)


def _load_creds():
    """Loads cached token, refreshing if expired. Returns Credentials or None."""
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request

    if not is_authorized():
        return None
    creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            _save(creds)
        except Exception as e:
            log.warning(f"[gmail] token refresh failed (re-auth needed): {e}")
            return None
    return creds if creds and creds.valid else None


def _save(creds):
    with open(TOKEN_PATH, "w") as f:
        f.write(creds.to_json())


def authorize() -> dict:
    """Runs the interactive local-browser OAuth flow and caches the token.
    Intended to be triggered by the dashboard 'Connect Gmail' button."""
    if not credentials_present():
        return {"ok": False, "error": f"credentials.json not found at {CRED_PATH}. "
                "Create a Desktop OAuth client in Google Cloud Console and place it there."}
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
        flow = InstalledAppFlow.from_client_secrets_file(CRED_PATH, SCOPES)
        creds = flow.run_local_server(port=0, prompt="consent")
        _save(creds)
        return {"ok": True, "email": _account_email(creds)}
    except Exception as e:
        log.warning(f"[gmail] authorization failed: {e}")
        return {"ok": False, "error": str(e)}


def _account_email(creds=None):
    try:
        svc = _service(creds or _load_creds())
        return svc.users().getProfile(userId="me").execute().get("emailAddress")
    except Exception:
        return None


def _service(creds):
    from googleapiclient.discovery import build
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def status() -> dict:
    return {
        "credentials_present": credentials_present(),
        "authorized": is_authorized(),
        "email": _account_email() if is_authorized() else None,
    }


def _decode(data: str) -> str:
    return base64.urlsafe_b64decode(data.encode()).decode("utf-8", errors="replace")


def _extract_body_and_attachments(payload) -> tuple:
    """Walks MIME parts; returns (text_body, [attachment_filenames])."""
    body, attachments = "", []

    def walk(part):
        nonlocal body
        mime = part.get("mimeType", "")
        fname = part.get("filename")
        data = part.get("body", {}).get("data")
        if fname:
            attachments.append(fname)
        elif mime == "text/plain" and data and not body:
            body = _decode(data)
        elif mime == "text/html" and data and not body:
            body = _decode(data)
        for sub in part.get("parts", []) or []:
            walk(sub)

    walk(payload)
    return body, attachments


def fetch_recent(count: int = 10) -> list:
    """Returns up to `count` recent messages as dicts. Empty list if not authorized."""
    creds = _load_creds()
    if not creds:
        return []
    svc = _service(creds)
    listing = svc.users().messages().list(userId="me", maxResults=count).execute()
    out = []
    for ref in listing.get("messages", []):
        msg = svc.users().messages().get(userId="me", id=ref["id"], format="full").execute()
        headers = {h["name"].lower(): h["value"] for h in msg["payload"].get("headers", [])}
        body, attachments = _extract_body_and_attachments(msg["payload"])
        out.append({
            "id": msg["id"],
            "sender": headers.get("from", ""),
            "reply_to": headers.get("reply-to", ""),
            "subject": headers.get("subject", ""),
            "body": body,
            "attachments": attachments,
        })
    return out
