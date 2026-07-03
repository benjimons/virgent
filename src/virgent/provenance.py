"""Provenance store.

Records where every piece of information came from, when it was collected,
by whom, and what it was derived from — a lightweight W3C-PROV-style model:

    entity   -> Evidence (identified by content hash)
    activity -> collection/derivation method
    agent    -> Actor (collector)

Provenance records are persisted as JSONL next to the audit log; evidence
content is stored content-addressed under ``evidence/`` so a report reader
can re-verify any hash.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Actor, Evidence, sha256_hex, utcnow


@dataclass
class ProvenanceRecord:
    evidence_id: str
    source: str
    method: str                    # e.g. ingest.file, ingest.git, collect.web, derive.llm
    kind: str
    sha256: str
    size_bytes: int
    collected_at: str
    collector: dict
    derived_from: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "method": self.method,
            "kind": self.kind,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "collected_at": self.collected_at,
            "collector": self.collector,
            "derived_from": self.derived_from,
            "metadata": self.metadata,
        }


class ProvenanceStore:
    def __init__(self, path: str | Path, content_dir: str | Path | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.content_dir = Path(content_dir) if content_dir else self.path.parent / "evidence"
        self.content_dir.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, ProvenanceRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                self._records[d["evidence_id"]] = ProvenanceRecord(**d)

    def _persist(self, record: ProvenanceRecord) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

    # -- public API ---------------------------------------------------------

    def register(
        self,
        *,
        source: str,
        method: str,
        kind: str,
        content: str,
        collector: Actor,
        derived_from: Iterable[str] = (),
        metadata: dict | None = None,
    ) -> Evidence:
        """Register content and return provenance-stamped Evidence."""
        digest = sha256_hex(content)
        collected_at = utcnow()
        evidence_id = f"ev-{len(self._records) + 1:06d}-{digest[:12]}"
        derived = list(derived_from)
        for parent in derived:
            if parent not in self._records:
                raise KeyError(f"derived_from references unknown evidence: {parent}")
        record = ProvenanceRecord(
            evidence_id=evidence_id,
            source=source,
            method=method,
            kind=kind,
            sha256=digest,
            size_bytes=len(content.encode("utf-8", errors="replace")),
            collected_at=collected_at,
            collector=collector.to_dict(),
            derived_from=derived,
            metadata=metadata or {},
        )
        self._records[evidence_id] = record
        self._persist(record)
        (self.content_dir / evidence_id).write_text(content, encoding="utf-8")
        return Evidence(
            id=evidence_id,
            source=source,
            kind=kind,
            content=content,
            sha256=digest,
            collected_at=collected_at,
            collector=collector.to_dict(),
            metadata=metadata or {},
        )

    def get(self, evidence_id: str) -> ProvenanceRecord:
        return self._records[evidence_id]

    def get_content(self, evidence_id: str) -> str:
        return (self.content_dir / evidence_id).read_text(encoding="utf-8")

    def load_evidence(self, evidence_id: str) -> Evidence:
        rec = self.get(evidence_id)
        return Evidence(
            id=rec.evidence_id,
            source=rec.source,
            kind=rec.kind,
            content=self.get_content(evidence_id),
            sha256=rec.sha256,
            collected_at=rec.collected_at,
            collector=rec.collector,
            metadata=rec.metadata,
        )

    def all_ids(self) -> list[str]:
        return list(self._records.keys())

    def lineage(self, evidence_id: str) -> list[ProvenanceRecord]:
        """Full ancestry of a piece of evidence, nearest parent first."""
        out: list[ProvenanceRecord] = []
        seen: set[str] = set()
        frontier = list(self.get(evidence_id).derived_from)
        while frontier:
            parent_id = frontier.pop(0)
            if parent_id in seen:
                continue
            seen.add(parent_id)
            parent = self.get(parent_id)
            out.append(parent)
            frontier.extend(parent.derived_from)
        return out

    def verify_content(self, evidence_id: str) -> bool:
        """Re-hash stored content and compare with the registered digest."""
        rec = self.get(evidence_id)
        return sha256_hex(self.get_content(evidence_id)) == rec.sha256
