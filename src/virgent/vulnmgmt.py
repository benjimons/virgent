"""Vulnerability management.

Turns the raw stream of findings into a managed register: findings are
deduplicated by semantic fingerprint across every scan, given a risk score,
tracked through a remediation lifecycle, and aged against SLA targets. Status
transitions are recorded in a JSONL log so the register is itself auditable.

Lifecycle states:
    open          -> newly discovered or re-observed, unresolved
    acknowledged  -> triaged, remediation planned
    resolved      -> fixed and verified (auto-reopens if re-observed)
    accepted      -> risk formally accepted (with a reason + who accepted)
    false_positive-> not a real issue
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, Severity, utcnow

STATES = {"open", "acknowledged", "resolved", "accepted", "false_positive"}
OPEN_STATES = {"open", "acknowledged"}

# base risk by severity (0-100 scale before modifiers)
_SEVERITY_SCORE = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 45,
    Severity.LOW: 20,
    Severity.INFO: 5,
}
_CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.85, "low": 0.6}

# default remediation SLA (days) by severity
SLA_DAYS = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFO: 365,
}


def risk_score(finding: Finding) -> int:
    """0-100 risk score from severity, confidence, and known-exploit/exposure signals."""
    base = _SEVERITY_SCORE[finding.severity]
    score = base * _CONFIDENCE_FACTOR.get(finding.confidence, 0.85)
    meta = finding.metadata or {}
    if meta.get("advisory") or meta.get("aliases"):   # a real CVE/advisory
        score = min(100.0, score * 1.1)
    if "exposed" in finding.metadata.get("rule", "") or "exposed" in finding.title.lower():
        score = min(100.0, score + 5)
    if meta.get("verified"):                          # confirmed by pen-test
        score = min(100.0, score + 8)
    return int(round(score))


@dataclass
class VulnEntry:
    fingerprint: str
    finding: dict
    status: str = "open"
    risk: int = 0
    first_seen: str = ""
    last_seen: str = ""
    times_seen: int = 1
    note: str = ""
    changed_by: str = ""

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "status": self.status,
            "risk": self.risk,
            "severity": self.finding.get("severity"),
            "title": self.finding.get("title"),
            "location": self.finding.get("location"),
            "capability": self.finding.get("capability"),
            "controls": self.finding.get("controls", []),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "times_seen": self.times_seen,
            "note": self.note,
            "finding": self.finding,
        }


class VulnerabilityRegister:
    def __init__(self, path: str | Path, log_path: str | Path | None = None):
        self.path = Path(path)
        self.log_path = Path(log_path) if log_path else self.path.with_suffix(".log.jsonl")
        self._entries: dict[str, VulnEntry] = {}
        if self.path.exists():
            for fp, d in json.loads(self.path.read_text(encoding="utf-8")).items():
                self._entries[fp] = VulnEntry(
                    fingerprint=fp, finding=d["finding"], status=d["status"],
                    risk=d["risk"], first_seen=d["first_seen"], last_seen=d["last_seen"],
                    times_seen=d.get("times_seen", 1), note=d.get("note", ""),
                    changed_by=d.get("changed_by", ""),
                )

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({fp: e.to_dict() for fp, e in self._entries.items()},
                       indent=2, sort_keys=True, default=str),
            encoding="utf-8")

    def _log(self, event: dict) -> None:
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": utcnow(), **event}, default=str) + "\n")

    # -- ingest findings ----------------------------------------------------

    def sync(self, findings: list[Finding]) -> dict:
        """Merge a scan's findings into the register.

        New fingerprints are added as ``open``. Re-observed ones update
        ``last_seen``/``times_seen`` and re-open anything previously
        ``resolved`` (the issue came back). Returns a summary.
        """
        now = utcnow()
        added, reobserved, reopened = 0, 0, 0
        for finding in findings:
            fp = finding.fingerprint
            entry = self._entries.get(fp)
            if entry is None:
                self._entries[fp] = VulnEntry(
                    fingerprint=fp, finding=finding.to_dict(), status="open",
                    risk=risk_score(finding), first_seen=now, last_seen=now,
                )
                added += 1
                self._log({"event": "discovered", "fingerprint": fp,
                           "severity": finding.severity.value, "title": finding.title})
            else:
                entry.last_seen = now
                entry.times_seen += 1
                entry.risk = risk_score(finding)
                entry.finding = finding.to_dict()
                reobserved += 1
                if entry.status == "resolved":
                    entry.status = "open"
                    reopened += 1
                    self._log({"event": "reopened", "fingerprint": fp,
                               "title": finding.title})
        self._save()
        return {"added": added, "reobserved": reobserved, "reopened": reopened,
                "total": len(self._entries)}

    # -- lifecycle ----------------------------------------------------------

    def set_status(self, fingerprint: str, status: str, actor: str, note: str = "") -> VulnEntry:
        if status not in STATES:
            raise ValueError(f"invalid status '{status}'; must be one of {sorted(STATES)}")
        if fingerprint not in self._entries:
            raise KeyError(f"unknown vulnerability: {fingerprint}")
        entry = self._entries[fingerprint]
        old = entry.status
        entry.status = status
        entry.note = note
        entry.changed_by = actor
        self._save()
        self._log({"event": "status_change", "fingerprint": fingerprint,
                   "from": old, "to": status, "actor": actor, "note": note})
        return entry

    # -- queries ------------------------------------------------------------

    def entries(self, status: str | None = None, open_only: bool = False) -> list[VulnEntry]:
        out = list(self._entries.values())
        if status:
            out = [e for e in out if e.status == status]
        if open_only:
            out = [e for e in out if e.status in OPEN_STATES]
        return sorted(out, key=lambda e: (-e.risk, e.fingerprint))

    def overdue(self, as_of: str | None = None) -> list[VulnEntry]:
        """Open entries past their severity SLA."""
        from datetime import datetime
        now = datetime.fromisoformat(as_of) if as_of else datetime.fromisoformat(utcnow())
        out = []
        for e in self.entries(open_only=True):
            sev = Severity(e.finding["severity"])
            first = datetime.fromisoformat(e.first_seen)
            age_days = (now - first).days
            if age_days > SLA_DAYS[sev]:
                out.append(e)
        return sorted(out, key=lambda e: -e.risk)

    def summary(self) -> dict:
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        open_risk = 0
        for e in self._entries.values():
            by_status[e.status] = by_status.get(e.status, 0) + 1
            sev = e.finding["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
            if e.status in OPEN_STATES:
                open_risk = max(open_risk, e.risk)
        return {
            "total": len(self._entries),
            "by_status": by_status,
            "by_severity": by_severity,
            "open": sum(by_status.get(s, 0) for s in OPEN_STATES),
            "highest_open_risk": open_risk,
            "overdue": len(self.overdue()),
        }
