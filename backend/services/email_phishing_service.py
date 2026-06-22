import re
import json
import logging
import config
from concurrent.futures import ThreadPoolExecutor, as_completed
from services import risk_aggregator

log = logging.getLogger(__name__)

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_EMAIL_DOMAIN_RE = re.compile(r"@([\w.-]+)")
_MAX_URLS = 5

_TRUSTED_SENDER_DOMAINS = {
    "google.com", "googlemail.com", "accounts.google.com",
    "microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk", "amazonaws.com",
    "linkedin.com", "slack.com", "github.com", "gitlab.com",
    "paypal.com", "stripe.com",
    "brevo.com", "brevosend.com", "sendinblue.com", "sendgrid.net", "mailchimp.com",
    "twitter.com", "x.com", "facebook.com", "instagram.com",
    "netflix.com", "spotify.com", "zoom.us", "dropbox.com",
}

_SAFE_URL_PATTERNS = re.compile(
    r"https?://("
    r"[\w-]+\.google\.com|c\.gle|goo\.gl|g\.co|"
    r"[\w-]+\.microsoft\.com|[\w-]+\.office\.com|"
    r"[\w-]+\.apple\.com|"
    r"[\w-]+\.amazon\.com|[\w-]+\.amazonaws\.com|"
    r"[\w-]+\.linkedin\.com|[\w-]+\.github\.com|github\.com|"
    r"[\w-]+\.paypal\.com|click\.stripe\.com|"
    r"[\w-]+\.slack\.com|"
    r"[\w-]+\.brevo\.com|[\w-]+\.sendinblue\.com|"
    r"[\w-]+\.mailchimp\.com|"
    r"accounts\.google\.com"
    r")", re.I
)

_URGENCY_RULES = [
    (re.compile(r"your account (will be |has been |is being )?suspended", re.I), 18),
    (re.compile(r"account (has been |will be )?locked", re.I), 18),
    (re.compile(r"verify your (account|identity|email|information)", re.I), 12),
    (re.compile(r"confirm your (account|identity|email|payment|details)", re.I), 12),
    (re.compile(r"(unusual|suspicious) (activity|sign.in|login)", re.I), 15),
    (re.compile(r"update your (payment|billing|credit card|bank)", re.I), 18),
    (re.compile(r"click here (to verify|to confirm|immediately|now)", re.I), 15),
    (re.compile(r"within (24|48|72) hours?", re.I), 8),
    (re.compile(r"final (notice|warning|reminder)", re.I), 15),
    (re.compile(r"act (now|immediately)", re.I), 10),
    (re.compile(r"password (will )?expire", re.I), 12),
    (re.compile(r"immediate(ly)? (action|attention|response)", re.I), 12),
]

_RISKY_ATTACH = (
    ".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd",
    ".iso", ".lnk", ".docm", ".xlsm", ".pptm", ".ps1", ".hta",
)

_GEMINI_MODEL = "gemini-2.5-flash"


def _root_domain(host: str) -> str:
    parts = host.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _sender_root(addr: str) -> str:
    m = _EMAIL_DOMAIN_RE.search(addr or "")
    return _root_domain(m.group(1)) if m else ""


def _is_trusted_sender(addr: str) -> bool:
    addr_lower = (addr or "").lower()
    # Never flag our own alert emails
    if config.ALERT_EMAIL_FROM and config.ALERT_EMAIL_FROM.lower() in addr_lower:
        return True
    root = _sender_root(addr)
    return root in _TRUSTED_SENDER_DOMAINS or any(
        root == _root_domain(d) for d in _TRUSTED_SENDER_DOMAINS
    )


def _parse_json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return json.loads(m.group(0)) if m else {}


def _label(score: int) -> str:
    if score >= 70:
        return "Phishing"
    if score >= 45:
        return "Suspicious"
    return "Likely Safe"


def _scan_url(u: str) -> dict | None:
    """Scan a single URL in a thread pool."""
    try:
        res = risk_aggregator.analyze_url(u)
        return {"url": u, "score": res["risk_score"], "threat": res["threat_label"]}
    except Exception as e:
        log.warning(f"[email_phishing] url scan failed for {u}: {e}")
        return None


def _gemini_verify(sender: str, subject: str, body: str,
                   heuristic_signals: list, url_findings: list,
                   heuristic_score: int) -> dict | None:
    if not config.is_configured("gemini"):
        return None
    import google.generativeai as genai
    evidence = {
        "sender": sender, "subject": subject,
        "body_excerpt": body[:2000].strip(),
        "heuristic_signals": heuristic_signals,
        "url_findings": url_findings,
        "rule_based_score": heuristic_score,
    }
    prompt = (
        "You are an expert email security analyst. Determine whether this email is "
        "phishing, suspicious, or legitimate.\n\n"
        "Key rules:\n"
        "- Legitimate companies (Google, Microsoft, Apple, banks) DO send urgent "
        "notifications, so urgency alone is NOT evidence of phishing.\n"
        "- High URL score on a redirect/tracking link from a trusted sender means "
        "the link scanner was overly cautious, so weigh sender context heavily.\n"
        "- Phishing indicators: mismatched sender domain, credential harvesting, "
        "impersonation of a brand the sender domain doesn't match, raw-IP links, "
        "suspicious attachments, requests for passwords/payment.\n"
        "- Newsletter/marketing/service emails from known providers should score LOW.\n\n"
        "Respond with ONLY a JSON object, no markdown:\n"
        "  phishing_score (0-100), label ('Phishing'|'Suspicious'|'Likely Safe'), "
        "reasoning (one sentence)\n\n"
        f"Evidence: {json.dumps(evidence, ensure_ascii=False)}"
    )
    for attempt in range(len(config._GEMINI_KEYS) or 1):
        try:
            genai.configure(api_key=config.get_gemini_key())
            resp = genai.GenerativeModel(_GEMINI_MODEL).generate_content(prompt)
            result = _parse_json(resp.text)
            score = max(0, min(int(result.get("phishing_score", heuristic_score)), 100))
            label = result.get("label", _label(score))
            if label not in ("Phishing", "Suspicious", "Likely Safe"):
                label = _label(score)
            return {"phishing_score": score, "label": label, "reasoning": result.get("reasoning", "")}
        except Exception as e:
            msg = str(e).lower()
            if ("429" in msg or "quota" in msg or "rate limit" in msg) and len(config._GEMINI_KEYS) > 1:
                log.warning(f"[email_phishing] Gemini key rate limited, rotating")
                config.rotate_gemini_key()
            else:
                log.warning(f"[email_phishing] Gemini verify failed: {e}")
        return None


def analyze(email: dict) -> dict:
    body    = email.get("body", "") or ""
    subject = email.get("subject", "") or ""
    sender  = email.get("sender", "") or ""
    text    = f"{subject}\n{body}"
    signals = []

    trusted_sender = _is_trusted_sender(sender)

    # 1. Parallel URL reputation
    raw_urls  = list(dict.fromkeys(_URL_RE.findall(body)))[:_MAX_URLS]
    scan_urls = [u for u in raw_urls if not _SAFE_URL_PATTERNS.match(u)]

    flagged_urls, max_url_score, url_findings = [], 0, []
    if scan_urls:
        with ThreadPoolExecutor(max_workers=min(len(scan_urls), 5)) as pool:
            futures = {pool.submit(_scan_url, u): u for u in scan_urls}
            for fut in as_completed(futures):
                r = fut.result()
                if r is None:
                    continue
                max_url_score = max(max_url_score, r["score"])
                url_findings.append(r)
                if r["score"] >= 55:
                    flagged_urls.append({"url": r["url"], "risk_score": r["score"], "threat": r["threat"]})

    if flagged_urls:
        signals.append(f"{len(flagged_urls)} high-risk link(s) found")

    # 2. Heuristics
    heuristic = 0
    urgency_pts, hit_labels = 0, []
    for pattern, pts in _URGENCY_RULES:
        if pattern.search(text):
            urgency_pts += pts
            hit_labels.append(pattern.pattern[:50])
    if urgency_pts >= 16:
        heuristic += min(urgency_pts, 30)
        signals.append(f"Phishing language: {'; '.join(hit_labels[:3])}")

    sd = _sender_root(sender)
    rd = _sender_root(email.get("reply_to", ""))
    if sd and rd and sd != rd and not trusted_sender:
        heuristic += 20
        signals.append(f"Reply-To domain ({rd}) differs from sender ({sd})")

    bad_attach = [a for a in email.get("attachments", [])
                  if a.lower().endswith(_RISKY_ATTACH)]
    if bad_attach:
        heuristic += min(len(bad_attach) * 15, 30)
        signals.append(f"Risky attachment(s): {', '.join(bad_attach)}")

    if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", body):
        heuristic += 20
        signals.append("Link points directly to a raw IP address")

    # 3. Rule-based score (Gemini fallback)
    url_weight   = 0.45 if trusted_sender else 0.65
    effective_url = max(max_url_score - (15 if trusted_sender else 0), 0)
    if effective_url == 0 and heuristic == 0:
        rule_score = 0
    elif effective_url == 0:
        rule_score = min(heuristic, 100)
    else:
        rule_score = min(round(effective_url * url_weight + heuristic), 100)
    if trusted_sender and not flagged_urls and rule_score > 39:
        rule_score = 39

    # 4. Gemini final verdict
    gemini = _gemini_verify(sender, subject, body, signals, url_findings, rule_score)
    if gemini:
        score = gemini["phishing_score"]
        label = gemini["label"]
        if gemini.get("reasoning"):
            signals.append(f"AI: {gemini['reasoning']}")
    else:
        score = rule_score
        label = _label(score)

    return {
        "phishing_score": score,
        "label":          label,
        "flagged_urls":   flagged_urls,
        "signals":        signals,
    }
