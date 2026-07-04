"""Container image supply-chain scanning.

Complements the IaC Dockerfile checks (which cover USER/curl-pipe/secrets/base
pinning) by focusing on *package supply-chain hygiene inside the image*:
unpinned OS/language package installs, remote ADD, and disabled integrity
checks — the ways a build silently pulls in unverified or drifting software.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from . import Capability

SUPPLY_CONTROLS = ["NIST:SR-3", "OWASP:A06", "ISO27001:A.8.9"]
INTEGRITY_CONTROLS = ["NIST:SR-3", "OWASP:A08", "ISO27001:A.8.9"]


def _line(content: str, idx: int) -> int:
    return content.count("\n", 0, idx) + 1


def check_image(content: str) -> list[dict]:
    issues = []

    # apt/apk install without version pin (pkg=version / pkg=~version)
    for m in re.finditer(r"(?im)\b(?:apt-get|apt|apk)\s+(?:add|install)\b([^\n&|]*)", content):
        pkgs = m.group(1)
        names = [t for t in pkgs.split() if not t.startswith("-")]
        if names and not any("=" in t for t in names):
            issues.append(("image-unpinned-os-package",
                           "OS packages installed without a pinned version",
                           Severity.LOW, SUPPLY_CONTROLS, _line(content, m.start()),
                           "Pin package versions (pkg=version) for reproducible, auditable builds."))

    # pip install without ==  (and not from a pinned requirements file)
    for m in re.finditer(r"(?im)\bpip3?\s+install\b([^\n&|]*)", content):
        spec = m.group(1)
        if "-r" in spec or "==" in spec or "requirement" in spec.lower():
            continue
        if re.search(r"[A-Za-z0-9_.\-]", spec.replace("-", "")):
            issues.append(("image-unpinned-pip",
                           "pip install without a pinned version",
                           Severity.LOW, SUPPLY_CONTROLS, _line(content, m.start()),
                           "Pin to == versions or install from a hashed requirements file."))

    # remote ADD (fetches over the network into the image, unverified)
    for m in re.finditer(r"(?im)^\s*ADD\s+https?://", content):
        issues.append(("image-remote-add",
                       "ADD fetches a remote URL into the image (unverified)",
                       Severity.MEDIUM, INTEGRITY_CONTROLS, _line(content, m.start()),
                       "Download, checksum-verify, then COPY; ADD does not verify integrity."))

    # disabled integrity/cert checks in the build
    for m in re.finditer(r"(?i)--(?:no-check-certificate|trusted-host|allow-unauthenticated|insecure)\b|--break-system-packages", content):
        issues.append(("image-integrity-check-disabled",
                       "Package/transport integrity check disabled in build",
                       Severity.HIGH, INTEGRITY_CONTROLS, _line(content, m.start()),
                       "Never disable certificate/signature checks; fix the root trust issue."))

    return issues


class ImageScanCapability(Capability):
    name = "image"
    description = "Container image supply-chain hygiene: unpinned packages, remote ADD, disabled integrity checks"

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            name = ev.metadata.get("filename", ev.source).lower()
            if "dockerfile" not in name and "containerfile" not in name:
                continue
            for rule, title, severity, controls, line, remediation in check_image(ev.content):
                seq += 1
                findings.append(Finding(
                    id=new_finding_id(self.name, seq), capability=self.name,
                    title=f"{title} ({ev.source}:{line})",
                    description=f"Image rule '{rule}' matched at {ev.source}:{line}.",
                    severity=severity, evidence_ids=[ev.id],
                    location=f"{ev.source}:{line}", controls=list(controls),
                    remediation=remediation, metadata={"rule": rule}))
        return findings
