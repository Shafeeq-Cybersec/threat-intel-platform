import re
import json
import logging
from collections import defaultdict
import config
from services import abuseipdb_service

log = logging.getLogger(__name__)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"\bfor (?:invalid user )?(\w+)", re.I)
# matches "14:23:01" or ISO "T14:23:01"
_HOUR_RE = re.compile(r"[T ](\d{2}):\d{2}:\d{2}")

_FAIL_KW = ("failed password", "authentication failure", "failed login", "invalid user", "access denied", "401", "403")
_OK_KW = ("accepted password", "session opened", "login successful", "accepted publickey")
# lines worth escalating to the AI when no rule fired
_AMBIG_KW = ("sudo", "root", "privilege", "escalat", "unusual", "anomal", "warning", "error", "denied", "exploit", "malware")

_FAIL_THRESHOLD = 3          # failed logins from one IP => brute force (lowered from 5)
_OFF_HOURS = range(0, 6)     # 00:00-05:59 local
_MAX_IP_LOOKUPS = 25         # cap AbuseIPDB calls per run
_MAX_AI_LINES = 8            # cap Gemini calls per run

_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Regex: "sudo: <user> : ... USER=root ; COMMAND=/path"
_SUDO_RE = re.compile(
    r"sudo\s*:.*?(?P<user>\S+)\s+:.*?USER=(?P<as_user>\S+)\s*;.*?COMMAND=(?P<cmd>\S+)",
    re.I
)
# Also catch "sudo: <user> : command not allowed"
_SUDO_DENIED_RE = re.compile(r"sudo\s*:.*?command not allowed", re.I)


def _parse(line: str) -> dict:
    ip_m = _IP_RE.search(line)
    user_m = _USER_RE.search(line)
    hour_m = _HOUR_RE.search(line)
    sudo_m = _SUDO_RE.search(line)
    low = line.lower()
    return {
        "raw": line.strip(),
        "ip": ip_m.group(0) if ip_m else None,
        "user": user_m.group(1) if user_m else None,
        "hour": int(hour_m.group(1)) if hour_m else None,
        "failed": any(k in low for k in _FAIL_KW),
        "ok": any(k in low for k in _OK_KW),
        # sudo escalation fields
        "sudo_user": sudo_m.group("user") if sudo_m else None,
        "sudo_as":   sudo_m.group("as_user") if sudo_m else None,
        "sudo_cmd":  sudo_m.group("cmd") if sudo_m else None,
        "sudo_denied": bool(_SUDO_DENIED_RE.search(line)),
    }


def _rule_based(parsed: list) -> tuple:
    """Returns (flagged_events, set_of_flagged_indices)."""
    events = []
    flagged_idx = set()

    fails_by_ip = defaultdict(list)
    success_by_ip = defaultdict(list)   # ip -> list of indices with successful logins
    logins_by_user = defaultdict(set)   # user -> set of countries (needs AbuseIPDB)
    unique_ips = []

    for i, p in enumerate(parsed):
        if p["ip"] and p["ip"] not in unique_ips:
            unique_ips.append(p["ip"])
        if p["failed"] and p["ip"]:
            fails_by_ip[p["ip"]].append(i)
        if p["ok"] and p["ip"]:
            success_by_ip[p["ip"]].append(i)

        # Rule: off-hours successful access
        if p["ok"] and p["hour"] is not None and p["hour"] in _OFF_HOURS:
            events.append(_mk(p["raw"], "medium", "Off-Hours Access",
                             f"Successful login at {p['hour']:02d}:xx (outside business hours).", False))
            flagged_idx.add(i)

        # Rule: Privilege Escalation - sudo command executed as root
        if p["sudo_user"] and p["sudo_as"] and p["sudo_as"].lower() == "root" and p["sudo_cmd"]:
            events.append(_mk(p["raw"], "high", "Privilege Escalation",
                              f"User '{p['sudo_user']}' ran '{p['sudo_cmd']}' as root via sudo.", False))
            flagged_idx.add(i)

        # Rule: Privilege Escalation - sudo denied / command not allowed
        elif p["sudo_denied"] and i not in flagged_idx:
            events.append(_mk(p["raw"], "medium", "Privilege Escalation Attempt",
                              "Unauthorized sudo command attempted but was denied.", False))
            flagged_idx.add(i)

    # Rule: brute force (3+ failures from same IP)
    for ip, idxs in fails_by_ip.items():
        if len(idxs) >= _FAIL_THRESHOLD:
            flagged_idx.update(idxs)
            events.append(_mk(parsed[idxs[0]]["raw"], "high", "Brute Force / Credential Stuffing",
                             f"{len(idxs)} failed login attempts from {ip}.", False))

    # Rule: Account Takeover - failed attempts followed by success from same IP
    for ip, ok_idxs in success_by_ip.items():
        fail_idxs = fails_by_ip.get(ip, [])
        if not fail_idxs:
            continue
        for ok_i in ok_idxs:
            preceding_fails = [fi for fi in fail_idxs if fi < ok_i]
            if preceding_fails:
                success_line = parsed[ok_i]["raw"]
                events.append(_mk(success_line, "critical", "Account Takeover",
                                  f"Successful login from {ip} after {len(preceding_fails)} "
                                  f"failed attempt(s) - possible brute-force account compromise.", False))
                flagged_idx.update(preceding_fails)
                flagged_idx.add(ok_i)
                break  # one event per IP is enough

    # Rule: known-malicious IPs (+ country collection for impossible-travel)
    for ip in unique_ips[:_MAX_IP_LOOKUPS]:
        rep = abuseipdb_service.check_ip(ip)
        if not rep:
            continue
        if rep["country"]:
            for p in parsed:
                if p["ip"] == ip and p["ok"] and p["user"]:
                    logins_by_user[p["user"]].add(rep["country"])
        if rep["malicious"]:
            sev = "critical" if rep["score"] >= 85 else "high"
            line = next((p["raw"] for p in parsed if p["ip"] == ip), ip)
            events.append(_mk(line, sev, "Known Malicious IP",
                             f"{ip} has AbuseIPDB confidence {rep['score']}% ({rep['country']}).", False))

    # Rule: impossible travel (same user, 2+ countries)
    for user, countries in logins_by_user.items():
        if len(countries) >= 2:
            events.append(_mk(f"user={user}", "high", "Impossible Travel",
                             f"User '{user}' logged in from {len(countries)} countries: {', '.join(sorted(countries))}.", False))

    return events, flagged_idx


def _ai_assisted(parsed: list, flagged_idx: set) -> list:
    if not config.is_configured("gemini"):
        return []
    candidates = [p["raw"] for i, p in enumerate(parsed)
                  if i not in flagged_idx and any(k in p["raw"].lower() for k in _AMBIG_KW)]
    candidates = candidates[:_MAX_AI_LINES]
    if not candidates:
        return []

    from google import genai as _genai
    prompt = (
        "You are a SOC analyst. For each numbered security log line, decide if it is suspicious. "
        "Respond with ONLY a JSON array; one object per SUSPICIOUS line you find, with keys: "
        "line_index (int, 0-based), severity (low|medium|high|critical), category (short string), "
        "explanation (one sentence). Omit benign lines.\n\nLines:\n"
        + "\n".join(f"{i}: {l}" for i, l in enumerate(candidates))
    )
    verdicts = []
    for attempt in range(len(config._GEMINI_KEYS) or 1):
        try:
            client = _genai.Client(api_key=config.get_gemini_key())
            resp = client.models.generate_content(model="gemini-3.5-flash-lite", contents=prompt)
            m = re.search(r"\[.*\]", resp.text, re.DOTALL)
            verdicts = json.loads(m.group(0)) if m else []
            break
        except Exception as e:
            msg = str(e).lower()
            if ("429" in msg or "quota" in msg or "rate limit" in msg) and len(config._GEMINI_KEYS) > 1:
                log.warning(f"[log_analyzer] Gemini key rate limited, rotating")
                config.rotate_gemini_key()
            else:
                log.warning(f"[log_analyzer] AI pass failed: {e}")
                return []

    events = []
    for v in verdicts:
        idx = v.get("line_index")
        if not isinstance(idx, int) or not (0 <= idx < len(candidates)):
            continue
        sev = v.get("severity", "low")
        events.append(_mk(candidates[idx], sev if sev in _SEV_RANK else "low",
                         v.get("category", "AI-Flagged"), v.get("explanation", ""), True))
    return events


def _mk(raw, severity, category, explanation, ai):
    return {"raw_log_line": raw, "severity": severity, "category": category,
            "explanation": explanation, "ai_assisted": ai}


def analyze(text: str) -> list:
    """Runs rule-based + AI passes over raw log text; returns flagged events sorted by severity."""
    parsed = [_parse(ln) for ln in text.splitlines() if ln.strip()]
    events, flagged_idx = _rule_based(parsed)
    events += _ai_assisted(parsed, flagged_idx)
    events.sort(key=lambda e: _SEV_RANK.get(e["severity"], 0), reverse=True)
    return events
