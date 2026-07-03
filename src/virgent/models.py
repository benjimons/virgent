"""Shared data models for Virgent.

Every object that flows through the agent is identifiable, hashable, and
timestamped so it can be referenced from the audit log, the provenance
store, and compliance reports.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> str:
    """RFC 3339 UTC timestamp used everywhere in Virgent."""
    return datetime.now(timezone.utc).isoformat()


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON serialization used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


@dataclass(frozen=True)
class Actor:
    """Who performed an action: a human operator, the agent, or a subsystem."""

    id: str
    type: str = "agent"  # agent | human | system

    def to_dict(self) -> dict:
        return {"id": self.id, "type": self.type}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


@dataclass
class Evidence:
    """A unit of ingested information with a stable identity.

    ``id`` is assigned by the provenance store; ``sha256`` binds the identity
    to the exact bytes that were ingested.
    """

    id: str
    source: str            # URI-ish locator: file path, git commit, URL, ...
    kind: str              # code | config | log | data | text | commit | advisory | ...
    content: str
    sha256: str
    collected_at: str
    collector: dict = field(default_factory=dict)   # Actor.to_dict()
    metadata: dict = field(default_factory=dict)

    def to_dict(self, include_content: bool = False) -> dict:
        d = {
            "id": self.id,
            "source": self.source,
            "kind": self.kind,
            "sha256": self.sha256,
            "collected_at": self.collected_at,
            "collector": self.collector,
            "metadata": self.metadata,
        }
        if include_content:
            d["content"] = self.content
        return d


@dataclass
class Finding:
    """A security finding, always traceable back to evidence and controls."""

    id: str
    capability: str
    title: str
    description: str
    severity: Severity
    evidence_ids: list[str] = field(default_factory=list)
    location: str = ""             # e.g. "path/to/file:42"
    controls: list[str] = field(default_factory=list)  # control catalog IDs
    confidence: str = "high"       # high | medium | low
    remediation: str = ""
    metadata: dict = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow)

    @property
    def fingerprint(self) -> str:
        """Stable identity for dedup across runs (independent of timestamps)."""
        return sha256_hex(canonical_json({
            "capability": self.capability,
            "title": self.title,
            "location": self.location,
            "evidence": sorted(self.evidence_ids),
        }))[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["fingerprint"] = self.fingerprint
        return d

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        d = dict(d)
        d.pop("fingerprint", None)
        d["severity"] = Severity(d["severity"])
        return Finding(**d)


def new_finding_id(capability: str, seq: int) -> str:
    return f"fnd-{capability}-{seq:05d}"
