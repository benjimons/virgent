"""Log normalization.

Turns heterogeneous log lines (sshd/auth, sudo, syslog, JSON, web access
logs) into a common :class:`LogEvent` schema so detection rules don't care
about source format. Parsers are best-effort and never raise on a malformed
line — an unrecognized line becomes a generic event.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..models import Evidence

IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

_SYSLOG_PREFIX = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<proc>[^:\[\s]+)")

_AUTH_PATTERNS = [
    ("ssh_login_failed", re.compile(rf"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>{IPV4})")),
    ("ssh_invalid_user", re.compile(rf"Invalid user (?P<user>\S+) from (?P<ip>{IPV4})")),
    ("ssh_login_success", re.compile(rf"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>{IPV4})")),
    ("session_opened", re.compile(r"session opened for user (?P<user>\S+)")),
    ("sudo_command", re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")),
    ("user_added", re.compile(r"(?:useradd|new user)[^\n]*name=(?P<user>[\w.\-]+)")),
    ("group_change", re.compile(r"(?:usermod|gpasswd)[^\n]*(?:group of |to group |add '?)(?P<grp>sudo|root|wheel|admin)")),
]

# web-access-log attack signatures
_WEB_ATTACKS = [
    ("sqli", re.compile(r"(?i)(?:union\s+select|or\s+1=1|';--|/\*.*\*/|sleep\(\d)")),
    ("path_traversal", re.compile(r"(?:\.\./){2,}|/etc/passwd|%2e%2e%2f")),
    ("xss", re.compile(r"(?i)<script\b|onerror\s*=|javascript:")),
    ("cmd_injection", re.compile(r"(?i);\s*(?:cat|wget|curl|nc|bash)\b|\$\(.*\)|`.*`")),
]


@dataclass
class LogEvent:
    ts: str
    source: str
    host: str
    event_type: str
    user: str = ""
    src_ip: str = ""
    message: str = ""
    fields: dict = field(default_factory=dict)
    evidence_id: str = ""

    def entities(self) -> dict:
        e = {}
        if self.src_ip:
            e["ip"] = self.src_ip
        if self.user:
            e["user"] = self.user
        if self.host:
            e["host"] = self.host
        return e


def _parse_json(line: str, source: str) -> LogEvent | None:
    try:
        d = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(d, dict):
        return None

    def pick(*keys):
        for k in keys:
            if k in d and d[k] not in (None, ""):
                return str(d[k])
        return ""

    return LogEvent(
        ts=pick("timestamp", "ts", "time", "@timestamp", "eventTime"),
        source=source,
        host=pick("host", "hostname", "computer", "device"),
        event_type=pick("event_type", "event", "action", "type", "eventid") or "json",
        user=pick("user", "username", "account", "user_name", "subject"),
        src_ip=pick("src_ip", "source_ip", "ip", "client_ip", "remote_addr", "srcaddr"),
        message=pick("message", "msg", "description", "raw"),
        fields=d,
    )


def _parse_auth(line: str, source: str) -> LogEvent | None:
    m = _SYSLOG_PREFIX.search(line)
    ts = m.group("ts") if m else ""
    host = m.group("host") if m else ""
    for event_type, pattern in _AUTH_PATTERNS:
        pm = pattern.search(line)
        if pm:
            gd = pm.groupdict()
            return LogEvent(
                ts=ts, source=source, host=host, event_type=event_type,
                user=gd.get("user", "") or "", src_ip=gd.get("ip", "") or "",
                message=line.strip(), fields={k: v for k, v in gd.items() if v},
            )
    return None


def _parse_web(line: str, source: str) -> LogEvent | None:
    # common/combined access log: IP - - [ts] "METHOD path proto" status size ...
    m = re.match(rf'(?P<ip>{IPV4})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+(?P<status>\d{{3}})', line)
    if not m:
        return None
    return LogEvent(
        ts=m.group("ts"), source=source, host="", event_type="web_request",
        src_ip=m.group("ip"), message=m.group("req"),
        fields={"status": m.group("status"), "request": m.group("req")},
    )


def parse_line(line: str, source: str = "log") -> LogEvent | None:
    line = line.rstrip("\n")
    if not line.strip():
        return None
    if line.lstrip().startswith("{"):
        ev = _parse_json(line, source)
        if ev:
            return ev
    for parser in (_parse_auth, _parse_web):
        ev = parser(line, source)
        if ev:
            return ev
    m = _SYSLOG_PREFIX.search(line)
    return LogEvent(
        ts=m.group("ts") if m else "", source=source,
        host=m.group("host") if m else "", event_type="generic",
        message=line.strip(),
    )


def parse_evidence(evidence: Evidence) -> list[LogEvent]:
    """Parse a log-evidence blob into events, tagging each with the evidence ID."""
    events: list[LogEvent] = []
    for line in evidence.content.splitlines():
        ev = parse_line(line, source=evidence.source)
        if ev is None:
            continue
        ev.evidence_id = evidence.id
        if not ev.host:
            ev.host = evidence.metadata.get("host", "") if evidence.metadata else ""
        events.append(ev)
    return events


def enrich_web_attacks(event: LogEvent) -> list[str]:
    """Return attack-signature names present in a web/generic event message."""
    hits = []
    for name, pattern in _WEB_ATTACKS:
        if pattern.search(event.message):
            hits.append(name)
    return hits
