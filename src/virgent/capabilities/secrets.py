"""Secret scanning capability.

Reuses the redaction pattern catalog so detection and DLP never drift apart.
Findings contain redacted excerpts only — never the secret value.
"""
from __future__ import annotations

from typing import Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from ..redaction import find_secrets
from . import Capability

CONTROLS = ["SOC2:CC6.1", "ISO27001:A.8.24", "NIST:IA-5", "OWASP:A07"]

CRITICAL_KINDS = {"private-key", "aws-access-key", "aws-secret-key", "stripe-key"}


class SecretScanCapability(Capability):
    name = "secrets"
    description = "Detect hardcoded credentials, tokens, and private keys in code, configs, and history"

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            if ev.kind not in ("code", "config", "text", "commit", "log", "data"):
                continue
            for match in find_secrets(ev.content):
                seq += 1
                severity = Severity.CRITICAL if match.kind in CRITICAL_KINDS else Severity.HIGH
                findings.append(Finding(
                    id=new_finding_id(self.name, seq),
                    capability=self.name,
                    title=f"Hardcoded secret ({match.kind}) in {ev.source}",
                    description=(
                        f"A credential of type '{match.kind}' was found at line {match.line}. "
                        f"Redacted excerpt: {match.excerpt}"
                    ),
                    severity=severity,
                    evidence_ids=[ev.id],
                    location=f"{ev.source}:{match.line}",
                    controls=list(CONTROLS),
                    remediation=(
                        "Revoke and rotate the credential immediately, remove it from the "
                        "source (including git history), and move it to a secret manager."
                    ),
                    metadata={"secret_kind": match.kind, "line": match.line},
                ))
        return findings
