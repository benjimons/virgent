"""SOC data models: Alert and Incident."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Severity, sha256_hex, canonical_json, utcnow

# monitoring / incident-response control bundle
SOC_CONTROLS = ["NIST:SI-4", "NIST:AU-6", "NIST:IR-5", "SOC2:CC7.2", "ISO27001:A.8.16"]
BRUTE_CONTROLS = SOC_CONTROLS + ["NIST:AC-7"]

PRIORITY_BY_SEVERITY = {
    Severity.CRITICAL: "P1",
    Severity.HIGH: "P2",
    Severity.MEDIUM: "P3",
    Severity.LOW: "P4",
    Severity.INFO: "P4",
}


@dataclass
class Alert:
    id: str
    rule: str
    title: str
    severity: Severity
    entities: dict = field(default_factory=dict)
    description: str = ""
    event_evidence_ids: list[str] = field(default_factory=list)
    count: int = 1
    controls: list[str] = field(default_factory=lambda: list(SOC_CONTROLS))
    created_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity.value,
            "entities": self.entities,
            "description": self.description,
            "event_evidence_ids": self.event_evidence_ids,
            "count": self.count,
            "controls": self.controls,
            "created_at": self.created_at,
        }
        return d

    @staticmethod
    def from_dict(d: dict) -> "Alert":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        return Alert(**d)


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    entities: dict = field(default_factory=dict)
    alert_ids: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    status: str = "new"          # new | triaged | contained | resolved
    priority: str = "P4"
    summary: str = ""
    notes: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "entities": self.entities,
            "alert_ids": self.alert_ids,
            "rules": self.rules,
            "status": self.status,
            "priority": self.priority,
            "summary": self.summary,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "Incident":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        return Incident(**d)


def incident_id(entities: dict) -> str:
    """Stable incident ID derived from its entity set (survives re-runs)."""
    pairs = []
    for k, v in entities.items():
        values = v if isinstance(v, (list, tuple, set)) else [v]
        for item in values:
            pairs.append(f"{k}={item}")
    key = canonical_json(sorted(pairs))
    return "inc-" + sha256_hex(key)[:12]


def alert_id(rule: str, entities: dict) -> str:
    """Stable alert ID from rule + entities, so recurring alerts dedup."""
    pairs = sorted(f"{k}={v}" for k, v in entities.items())
    return "alt-" + sha256_hex(canonical_json([rule, pairs]))[:12]
