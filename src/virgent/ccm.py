"""Continuous Control Monitoring (CCM).

Turns the compliance catalog from a static mapping into a live control-test
engine: each monitored control is automatically evaluated on every assessment,
gets a pass / fail / not-assessed status backed by evidence (the findings that
prove it), an owner, and — when failing — a remediation due date driven by an
SLA. State persists, so a control's ``first_failed_at`` and history survive
across runs, and overdue controls surface for escalation.

This is what makes Virgent a GRC *system of record* rather than a scanner:
every control has a current, evidence-backed compliance state, produced
automatically and recorded in the audit chain.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .compliance.frameworks import CONTROLS
from .models import Severity, utcnow

# SLA (days to remediate) by the severity of the worst finding on a control.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}

# Owner mapping: control framework/prefix -> responsible team (from the org model).
def _owner_for(control_id: str) -> str:
    fw = CONTROLS.get(control_id, {}).get("framework", "")
    if control_id.startswith(("CSF:GV", "SOC2:CC1", "PCI", "GDPR", "HIPAA")):
        return "grc"
    if control_id.startswith(("NIST:AC", "NIST:IA", "ISO27001:A.5.15", "ISO27001:A.5.16")):
        return "iam"
    if control_id.startswith(("NIST:SI", "NIST:IR", "ATTACK", "SOC2:CC7")):
        return "soc"
    if control_id.startswith(("CIS:", "NIST:CM", "NIST:SC", "NIST:SR")):
        return "infrastructure"
    return "security-engineering"


# The monitored control set: each control is tested by a capability. A control
# fails if that capability produced findings mapped to it, passes if the
# capability ran clean, and is "not assessed" if the capability didn't run.
# (control_id, assessed_by capability)
MONITORED_CONTROLS: list[tuple[str, str]] = [
    # secrets / cryptography
    ("NIST:IA-5", "secrets"), ("ISO27001:A.8.24", "secrets"), ("SOC2:CC6.1", "secrets"),
    # dependencies / supply chain
    ("NIST:RA-5", "dependencies"), ("OWASP:A06", "dependencies"), ("NIST:SR-3", "dependencies"),
    # IaC / config
    ("NIST:CM-6", "iac"), ("SOC2:CC8.1", "iac"), ("OWASP:A05", "iac"),
    # host hardening
    ("CIS:5.2", "host"), ("CIS:1.4", "host"), ("CIS:3.3", "host"), ("CIS:4.4", "host"),
    # runtime / detection
    ("NIST:SI-4", "runtime"), ("ISO27001:A.8.16", "runtime"),
    # file integrity
    ("NIST:SI-7", "fim"),
    # cloud posture
    ("NIST:AC-3", "cloud"), ("NIST:SC-7", "cloud"), ("NIST:SC-28", "cloud"), ("NIST:AC-2", "cloud"),
    # identity
    ("NIST:AC-17", "identity"), ("ISO27001:A.5.16", "identity"), ("ISO27001:A.5.15", "identity"),
    # SOC / IR
    ("NIST:IR-4", "soc"), ("SOC2:CC7.2", "soc"),
]


@dataclass
class ControlResult:
    control_id: str
    framework: str
    title: str
    status: str                    # pass | fail | not_assessed
    owner: str
    assessed_by: str
    finding_ids: list = field(default_factory=list)
    severity: str = "info"
    first_failed_at: str = ""
    due_at: str = ""
    last_assessed_at: str = field(default_factory=utcnow)

    @property
    def overdue(self) -> bool:
        if self.status != "fail" or not self.due_at:
            return False
        try:
            return datetime.now(timezone.utc) > datetime.fromisoformat(self.due_at)
        except ValueError:
            return False

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["overdue"] = self.overdue
        return d


class ControlMonitor:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._state: dict = {}
        if self.path.exists():
            try:
                self._state = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._state = {}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._state, indent=2, sort_keys=True), encoding="utf-8")

    def assess(self, findings: list, active_capabilities: list) -> list[ControlResult]:
        """Evaluate every monitored control against current findings."""
        active = set(active_capabilities)
        # control_id -> findings referencing it
        by_control: dict[str, list] = {}
        for f in findings:
            for cid in f.controls:
                by_control.setdefault(cid, []).append(f)

        results: list[ControlResult] = []
        now = datetime.now(timezone.utc)
        for control_id, cap in MONITORED_CONTROLS:
            meta = CONTROLS.get(control_id, {"framework": "?", "title": control_id})
            prior = self._state.get(control_id, {})
            hits = by_control.get(control_id, [])
            if cap not in active:
                status = "not_assessed"
            elif hits:
                status = "fail"
            else:
                status = "pass"

            worst = "info"
            first_failed = prior.get("first_failed_at", "")
            due = prior.get("due_at", "")
            if status == "fail":
                worst = min((f.severity.value for f in hits),
                            key=lambda s: Severity(s).rank, default="info")
                if not first_failed:
                    first_failed = utcnow()
                    due = (now + timedelta(days=SLA_DAYS.get(worst, 90))).isoformat()
            else:
                first_failed = ""      # cleared
                due = ""

            self._state[control_id] = {
                "status": status, "first_failed_at": first_failed, "due_at": due,
                "last_assessed_at": utcnow(),
            }
            results.append(ControlResult(
                control_id=control_id, framework=meta["framework"], title=meta["title"],
                status=status, owner=_owner_for(control_id), assessed_by=cap,
                finding_ids=[f.id for f in hits], severity=worst,
                first_failed_at=first_failed, due_at=due,
            ))
        self._save()
        return results

    def summary(self, results: list[ControlResult]) -> dict:
        by_status: dict[str, int] = {}
        by_framework: dict[str, dict[str, int]] = {}
        overdue = []
        for r in results:
            by_status[r.status] = by_status.get(r.status, 0) + 1
            fw = by_framework.setdefault(r.framework, {})
            fw[r.status] = fw.get(r.status, 0) + 1
            if r.overdue:
                overdue.append(r.control_id)
        assessed = sum(v for k, v in by_status.items() if k in ("pass", "fail"))
        passing = by_status.get("pass", 0)
        return {
            "controls_monitored": len(results),
            "by_status": by_status,
            "by_framework": by_framework,
            "compliance_pct": round(100 * passing / assessed, 1) if assessed else 0.0,
            "overdue": overdue,
        }
