"""
Maps SOC detection categories to MITRE ATT&CK techniques.

Each detection is tagged with its technique id, name, tactic, and a link to the
official ATT&CK reference so analysts can pivot to the knowledge base.
"""

# technique_id -> (name, tactic)
_TECHNIQUES = {
    "T1110":     ("Brute Force", "Credential Access"),
    "T1110.004": ("Brute Force: Credential Stuffing", "Credential Access"),
    "T1078":     ("Valid Accounts", "Defense Evasion / Persistence"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "Persistence"),
    "T1071":     ("Application Layer Protocol", "Command and Control"),
    "T1190":     ("Exploit Public-Facing Application", "Initial Access"),
    "T1133":     ("External Remote Services", "Initial Access"),
    "T1548":     ("Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "T1068":     ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1566":     ("Phishing", "Initial Access"),
    "T1204":     ("User Execution", "Execution"),
    "T1041":     ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1059":     ("Command and Scripting Interpreter", "Execution"),
    "T1562":     ("Impair Defenses", "Defense Evasion"),
    "T1098":     ("Account Manipulation", "Persistence"),
}

# Exact match on the analyzer's rule-based category names
_CATEGORY_MAP = {
    "brute force / credential stuffing": "T1110.004",
    "off-hours access": "T1078",
    "known malicious ip": "T1071",
    "impossible travel": "T1078",
    "account takeover": "T1110.004",
    "privilege escalation": "T1548",
    "privilege escalation attempt": "T1548",
}


# Keyword fallback for AI-generated categories / free-text
_KEYWORD_MAP = [
    ("credential stuff", "T1110.004"),
    ("brute", "T1110"),
    ("password spray", "T1110"),
    ("privilege escal", "T1548"),
    ("sudo", "T1548"),
    ("elevat", "T1548"),
    ("exploit", "T1190"),
    ("phish", "T1566"),
    ("malware", "T1204"),
    ("ransomware", "T1486"),
    ("exfiltrat", "T1041"),
    ("data theft", "T1041"),
    ("remote service", "T1133"),
    ("rdp", "T1133"),
    ("ssh", "T1110"),
    ("powershell", "T1059"),
    ("script", "T1059"),
    ("disable", "T1562"),
    ("account creat", "T1098"),
    ("impossible travel", "T1078"),
    ("off-hours", "T1078"),
    ("off hours", "T1078"),
    ("anomalous login", "T1078"),
    ("malicious ip", "T1071"),
    ("c2", "T1071"),
    ("command and control", "T1071"),
    ("beacon", "T1071"),
]


def _build(tid):
    info = _TECHNIQUES.get(tid)
    if not info:
        return None
    name, tactic = info
    base = tid.split(".")[0]
    sub = tid.split(".")[1] if "." in tid else None
    url = f"https://attack.mitre.org/techniques/{base}/" + (f"{sub}/" if sub else "")
    return {"id": tid, "name": name, "tactic": tactic, "url": url}


def map_category(category: str, explanation: str = "") -> dict | None:
    """Returns a MITRE ATT&CK technique dict for a detection, or None if unmapped."""
    if not category:
        return None
    key = category.strip().lower()
    if key in _CATEGORY_MAP:
        return _build(_CATEGORY_MAP[key])

    hay = f"{key} {(explanation or '').lower()}"
    for kw, tid in _KEYWORD_MAP:
        if kw in hay:
            return _build(tid)
    return None
