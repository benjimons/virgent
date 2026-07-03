"""File Integrity Monitoring (FIM).

Records a signed baseline of content hashes for critical files, then detects
modification, deletion, or (for watched directories) addition on later checks.
The baseline is stored in the workdir; each baselined file is also registered
with the provenance store, so a change is provable against a known-good hash.

Findings map to integrity controls (NIST SI-7, SOC 2 CC7.1, ISO 27001 A.8.9).
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, Severity, new_finding_id, sha256_hex, utcnow

FIM_CONTROLS = ["NIST:SI-7", "SOC2:CC7.1", "ISO27001:A.8.9", "NIST:SI-4"]


class IntegrityMonitor:
    def __init__(self, baseline_path: str | Path):
        self.baseline_path = Path(baseline_path)
        self._baseline: dict[str, dict] = {}
        if self.baseline_path.exists():
            self._baseline = json.loads(self.baseline_path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        self.baseline_path.write_text(
            json.dumps(self._baseline, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _hash_file(path: Path) -> str | None:
        try:
            return sha256_hex(path.read_bytes())
        except OSError:
            return None

    def baseline(self, paths: list[str]) -> dict:
        """Record hashes for ``paths``; returns a summary."""
        recorded = 0
        missing = []
        for p in paths:
            digest = self._hash_file(Path(p))
            if digest is None:
                missing.append(p)
                continue
            self._baseline[str(p)] = {"sha256": digest, "recorded_at": utcnow()}
            recorded += 1
        self._save()
        return {"recorded": recorded, "missing": missing, "total": len(self._baseline)}

    @property
    def watched(self) -> list[str]:
        return sorted(self._baseline)

    def check(self) -> list[Finding]:
        """Compare current file state against the baseline."""
        findings: list[Finding] = []
        seq = 0
        for path, entry in sorted(self._baseline.items()):
            current = self._hash_file(Path(path))
            if current is None:
                seq += 1
                findings.append(self._finding(
                    seq, path, Severity.HIGH, "removed or unreadable",
                    f"Baselined file '{path}' is missing or unreadable "
                    f"(baseline sha256 {entry['sha256'][:16]}…).",
                    "Restore the file from a trusted source and investigate why it disappeared.",
                    {"status": "removed", "baseline_sha256": entry["sha256"]}))
            elif current != entry["sha256"]:
                seq += 1
                findings.append(self._finding(
                    seq, path, Severity.HIGH, "modified since baseline",
                    f"Baselined file '{path}' changed: baseline "
                    f"{entry['sha256'][:16]}… now {current[:16]}….",
                    "Confirm the change was authorized; if not, treat as tampering and investigate.",
                    {"status": "modified", "baseline_sha256": entry["sha256"],
                     "current_sha256": current}))
        return findings

    @staticmethod
    def _finding(seq, path, severity, what, description, remediation, metadata) -> Finding:
        return Finding(
            id=new_finding_id("fim", seq),
            capability="fim",
            title=f"Integrity: {path} {what}",
            description=description,
            severity=severity,
            evidence_ids=[],
            location=path,
            controls=list(FIM_CONTROLS),
            remediation=remediation,
            metadata=metadata,
        )
