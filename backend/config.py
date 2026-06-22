import os
from dotenv import load_dotenv

load_dotenv()

# --- API Keys ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_API_KEY_2 = os.getenv("GEMINI_API_KEY_2")
GEMINI_API_KEY_3 = os.getenv("GEMINI_API_KEY_3")
_GEMINI_KEYS = [k for k in [GEMINI_API_KEY, GEMINI_API_KEY_2, GEMINI_API_KEY_3] if k]
_gemini_key_index = 0

def get_gemini_key() -> str | None:
    global _gemini_key_index
    if not _GEMINI_KEYS:
        return None
    return _GEMINI_KEYS[_gemini_key_index % len(_GEMINI_KEYS)]

def rotate_gemini_key():
    global _gemini_key_index
    _gemini_key_index = (_gemini_key_index + 1) % max(len(_GEMINI_KEYS), 1)
# OAuth client secret file; defaults to backend/credentials/credentials.json
GMAIL_CREDENTIALS_PATH = os.getenv("GMAIL_CREDENTIALS_PATH") or os.path.join(
    os.path.dirname(__file__), "credentials", "credentials.json")

# --- Alerting (Brevo) ---
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO")
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "70"))

# --- MongoDB + Auth ---
MONGO_URI = os.getenv("MONGO_URI", "")
ADMIN_KEY = os.getenv("ADMIN_KEY", "")
MAIL_USER = os.getenv("MAIL_USER", "")
MAIL_PASS = os.getenv("MAIL_PASS", "")
BASE_URL  = os.getenv("BASE_URL", "http://localhost:5000")

# --- App Config ---
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-prod")
_default_db = "/data/threat_intel.db" if os.path.isdir("/data") else "threat_intel.db"
DATABASE_PATH = os.getenv("DATABASE_PATH", _default_db)
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# Map service names to their required env vars
_SERVICE_KEYS = {
    "virustotal": VIRUSTOTAL_API_KEY,
    "safe_browsing": GOOGLE_SAFE_BROWSING_API_KEY,
    "phishtank": PHISHTANK_API_KEY,
    "abuseipdb": ABUSEIPDB_API_KEY,
    "gemini": GEMINI_API_KEY,
    "gmail": GMAIL_CREDENTIALS_PATH,
    "brevo": BREVO_API_KEY,
}

def is_configured(service_name: str) -> bool:
    """Returns True if the named service has its required key/credential set.

    For 'gmail' this means the OAuth client secret file actually exists on disk
    (not just an env var), since that's what gates the connect flow.
    """
    if service_name == "gmail":
        return os.path.exists(GMAIL_CREDENTIALS_PATH)
    return bool(_SERVICE_KEYS.get(service_name))
