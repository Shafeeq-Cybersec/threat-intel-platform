import html
import logging
import requests
import config
from datetime import datetime, timezone

log = logging.getLogger(__name__)
_ENDPOINT = "https://api.brevo.com/v3/smtp/email"
TIMEOUT = 15

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high":     "#ef4444",
    "phishing": "#ef4444",
    "malware":  "#ef4444",
    "suspicious": "#f59e0b",
    "medium":   "#f59e0b",
    "low":      "#10b981",
    "safe":     "#10b981",
}

_BAND_META = {
    "high":   {"label": "HIGH RISK",     "color": "#ef4444", "bar": "#ef4444"},
    "medium": {"label": "MEDIUM RISK",   "color": "#f59e0b", "bar": "#f59e0b"},
    "low":    {"label": "LOW RISK",      "color": "#10b981", "bar": "#10b981"},
}


def _severity_color(label: str) -> str:
    return _SEVERITY_COLOR.get((label or "").lower(), "#6b7280")


def _band(score: int) -> dict:
    if score >= 70:
        return _BAND_META["high"]
    if score >= 40:
        return _BAND_META["medium"]
    return _BAND_META["low"]


def _build_html(source: str, flagged: list, threshold: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    worst = max(flagged, key=lambda i: i["score"])
    worst_band = _band(worst["score"])

    rows_html = ""
    for idx, item in enumerate(flagged, 1):
        sc   = item["score"]
        lbl  = html.escape(str(item.get("label", "Unknown")))
        ttl  = html.escape(str(item.get("title", "")))
        c    = _severity_color(item.get("label", ""))
        bar_pct = min(sc, 100)
        rows_html += f"""
        <tr>
          <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;font-size:13px;
                     color:#6b7280;text-align:center;width:32px">{idx}</td>
          <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb">
            <div style="font-size:13px;color:#111827;word-break:break-all;margin-bottom:6px">{ttl}</div>
            <div style="background:#f3f4f6;border-radius:4px;height:4px;width:100%;overflow:hidden">
              <div style="background:{c};height:4px;width:{bar_pct}%;border-radius:4px"></div>
            </div>
          </td>
          <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;white-space:nowrap">
            <span style="display:inline-block;background:{c}18;color:{c};
                         border:1px solid {c};border-radius:5px;
                         padding:3px 10px;font-size:11px;font-weight:700;
                         letter-spacing:0.6px;text-transform:uppercase">{lbl}</span>
          </td>
          <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;text-align:center;
                     font-family:monospace;font-size:15px;font-weight:700;color:{c};
                     white-space:nowrap">{sc}<span style="font-size:10px;color:#9ca3af">/100</span></td>
        </tr>"""

    action = (f"<span style='color:#dc2626;font-weight:600'>Immediate investigation required.</span> "
              f"One or more indicators scored above 70. Isolate affected systems and escalate to Tier 2."
              if worst["score"] >= 70 else
              f"<span style='color:#d97706;font-weight:600'>Monitor and investigate.</span> "
              f"Indicators are elevated but not critical. Review flagged items and apply contextual judgment.")

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6">
    <tr><td align="center" style="padding:40px 16px">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1)">

        <!-- Header -->
        <tr>
          <td style="background:#111827;padding:28px 32px;border-bottom:3px solid {worst_band['color']}">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <div style="font-size:11px;letter-spacing:1.2px;text-transform:uppercase;
                               color:#9ca3af;margin-bottom:6px">Threat Intel Platform</div>
                  <div style="font-size:22px;font-weight:700;color:#ffffff">Security Alert Notification</div>
                  <div style="font-size:13px;color:#6b7280;margin-top:4px">{now}</div>
                </td>
                <td align="right" style="vertical-align:top">
                  <div style="background:{worst_band['color']};border-radius:8px;
                               padding:8px 18px;text-align:center;display:inline-block">
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;
                                 color:#ffffff;font-weight:700;opacity:0.85">Risk Level</div>
                    <div style="font-size:16px;font-weight:800;color:#ffffff;letter-spacing:1px">
                      {worst_band['label']}
                    </div>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Summary stats -->
        <tr>
          <td style="background:#f9fafb;padding:20px 32px;border-bottom:1px solid #e5e7eb">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="border-right:1px solid #e5e7eb;padding-right:24px">
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.7px;
                               color:#6b7280;margin-bottom:4px">Source</div>
                  <div style="font-size:15px;font-weight:600;color:#111827">{html.escape(source)}</div>
                </td>
                <td style="padding:0 24px;border-right:1px solid #e5e7eb">
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.7px;
                               color:#6b7280;margin-bottom:4px">Threats Detected</div>
                  <div style="font-size:15px;font-weight:600;color:#dc2626">{len(flagged)}</div>
                </td>
                <td style="padding:0 24px;border-right:1px solid #e5e7eb">
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.7px;
                               color:#6b7280;margin-bottom:4px">Risk Threshold</div>
                  <div style="font-size:15px;font-weight:600;color:#111827">{threshold}</div>
                </td>
                <td style="padding-left:24px">
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.7px;
                               color:#6b7280;margin-bottom:4px">Highest Score</div>
                  <div style="font-size:15px;font-weight:700;color:{worst_band['color']}">{worst['score']}/100</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Table -->
        <tr>
          <td style="padding:0">
            <table width="100%" cellpadding="0" cellspacing="0">
              <thead>
                <tr style="background:#f9fafb">
                  <th style="padding:10px 16px;font-size:10px;text-transform:uppercase;
                              letter-spacing:0.7px;color:#6b7280;font-weight:600;
                              text-align:center;width:32px;border-bottom:1px solid #e5e7eb">#</th>
                  <th style="padding:10px 16px;font-size:10px;text-transform:uppercase;
                              letter-spacing:0.7px;color:#6b7280;font-weight:600;
                              text-align:left;border-bottom:1px solid #e5e7eb">Target / Indicator</th>
                  <th style="padding:10px 16px;font-size:10px;text-transform:uppercase;
                              letter-spacing:0.7px;color:#6b7280;font-weight:600;
                              text-align:left;border-bottom:1px solid #e5e7eb;white-space:nowrap">Threat Type</th>
                  <th style="padding:10px 16px;font-size:10px;text-transform:uppercase;
                              letter-spacing:0.7px;color:#6b7280;font-weight:600;
                              text-align:center;border-bottom:1px solid #e5e7eb;white-space:nowrap">Risk Score</th>
                </tr>
              </thead>
              <tbody>{rows_html}</tbody>
            </table>
          </td>
        </tr>

        <!-- Recommended action -->
        <tr>
          <td style="background:#fafafa;padding:20px 32px;border-top:1px solid #e5e7eb">
            <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.7px;
                         color:#6b7280;margin-bottom:8px;font-weight:600">Recommended Action</div>
            <div style="font-size:13px;color:#374151;line-height:1.6">{action}</div>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f3f4f6;padding:16px 32px;border-top:1px solid #e5e7eb;
                     border-radius:0 0 12px 12px">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="font-size:11px;color:#9ca3af">
                  Automated alert from <strong style="color:#6b7280">Threat Intel Platform</strong>. Do not reply.
                </td>
                <td align="right" style="font-size:11px;color:#9ca3af;white-space:nowrap">
                  Threshold: {threshold} &middot; {now}
                </td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def maybe_alert(source: str, items: list) -> dict:
    """Sends ONE summary email if any item scores >= ALERT_THRESHOLD."""
    flagged = [i for i in items if (i.get("score") or 0) >= config.ALERT_THRESHOLD]
    if not flagged:
        return {"sent": False, "reason": "below_threshold"}

    if not config.is_configured("brevo"):
        log.warning(f"[alert] BREVO_API_KEY not set, WOULD have emailed alert for "
                    f"{len(flagged)} item(s) from {source} (threshold {config.ALERT_THRESHOLD}).")
        return {"sent": False, "reason": "not_configured", "would_alert": len(flagged)}

    to = config.ALERT_EMAIL_TO or config.ALERT_EMAIL_FROM
    if not (config.ALERT_EMAIL_FROM and to):
        log.warning("[alert] ALERT_EMAIL_FROM / ALERT_EMAIL_TO not set, cannot send.")
        return {"sent": False, "reason": "no_recipient"}

    worst = max(flagged, key=lambda i: i["score"])
    band_label = "HIGH" if worst["score"] >= 70 else "MEDIUM" if worst["score"] >= 40 else "LOW"
    subject = (f"[{band_label} RISK] {html.escape(source)}: "
               f"{len(flagged)} threat{'s' if len(flagged) > 1 else ''} detected "
               f"(score {worst['score']}/100)")

    try:
        r = requests.post(
            _ENDPOINT, timeout=TIMEOUT,
            headers={"api-key": config.BREVO_API_KEY, "Content-Type": "application/json"},
            json={
                "sender": {"email": config.ALERT_EMAIL_FROM, "name": "Threat Intel Platform"},
                "to": [{"email": to}],
                "subject": subject,
                "htmlContent": _build_html(source, flagged, config.ALERT_THRESHOLD),
            },
        )
        r.raise_for_status()
        return {"sent": True, "count": len(flagged)}
    except Exception as e:
        log.warning(f"[alert] Brevo send failed: {e}")
        return {"sent": False, "reason": str(e)}
