import os
import logging
import requests

log = logging.getLogger(__name__)

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


def send_alert(to: str, subject: str, html: str):
    api_key = os.environ.get("BREVO_API_KEY", "")
    if not api_key:
        log.warning("[mail] BREVO_API_KEY not configured — alert skipped")
        return
    try:
        resp = requests.post(
            BREVO_API_URL,
            headers={"api-key": api_key, "Content-Type": "application/json"},
            json={
                "sender": {"name": "Threat Intel Platform", "email": "shafeeqstudy1@gmail.com"},
                "to": [{"email": to}],
                "subject": subject,
                "htmlContent": html,
            },
            timeout=10,
        )
        if resp.status_code in (200, 201):
            log.info(f"[mail] alert sent to {to}")
        else:
            log.error(f"[mail] Brevo error {resp.status_code}: {resp.text}")
    except Exception as e:
        log.error(f"[mail] failed to send alert: {e}")
