"""Dependency and supply-chain audit.

Parses dependency manifests (requirements.txt, package.json) into an
inventory, flags unpinned dependencies, and — when an OSV query function is
provided (network permitted by policy) — reports known vulnerabilities with
their advisory IDs.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from . import Capability

VULN_CONTROLS = ["SOC2:CC7.1", "ISO27001:A.8.8", "NIST:RA-5", "NIST:SI-2", "OWASP:A06"]
PIN_CONTROLS = ["SOC2:CC8.1", "ISO27001:A.8.9", "NIST:SR-3", "OWASP:A08"]

# osv_query(package, ecosystem, version) -> list of vulnerability dicts
OsvQuery = Callable[[str, str, str | None], list[dict]]

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._\-\[\]]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9.*+!\-]+)?")


def parse_requirements(content: str) -> list[dict]:
    deps = []
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = m.group(1).split("[", 1)[0]
        deps.append({
            "name": name,
            "ecosystem": "PyPI",
            "operator": m.group(2) or "",
            "version": m.group(3) or "",
            "pinned": m.group(2) == "==",
        })
    return deps


def parse_package_json(content: str) -> list[dict]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+[\w.\-]*", spec))
            version = spec.lstrip("^~>=<")
            deps.append({
                "name": name,
                "ecosystem": "npm",
                "operator": "" if pinned else spec[:1],
                "version": version,
                "pinned": pinned,
                "dev": section == "devDependencies",
            })
    return deps


def _vuln_severity(vuln: dict) -> Severity:
    text = json.dumps(vuln).upper()
    if "CRITICAL" in text:
        return Severity.CRITICAL
    if "HIGH" in text:
        return Severity.HIGH
    if "MODERATE" in text or "MEDIUM" in text:
        return Severity.MEDIUM
    return Severity.MEDIUM


class DependencyAuditCapability(Capability):
    name = "dependencies"
    description = "Inventory dependencies, flag unpinned specs, and check known vulnerabilities (OSV)"

    def __init__(self, osv_query: OsvQuery | None = None):
        self.osv_query = osv_query

    def _parse(self, ev: Evidence) -> list[dict]:
        filename = ev.metadata.get("filename", ev.source).lower()
        if filename.endswith("requirements.txt"):
            return parse_requirements(ev.content)
        if filename.endswith("package.json"):
            return parse_package_json(ev.content)
        return []

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            deps = self._parse(ev)
            if not deps:
                continue
            for dep in deps:
                if not dep["pinned"]:
                    seq += 1
                    findings.append(Finding(
                        id=new_finding_id(self.name, seq),
                        capability=self.name,
                        title=f"Unpinned dependency '{dep['name']}' in {ev.source}",
                        description=(
                            f"'{dep['name']}' ({dep['ecosystem']}) is not pinned to an exact "
                            f"version (spec: '{dep['operator']}{dep['version']}' ). Unpinned "
                            "dependencies allow silent supply-chain drift between builds."
                        ),
                        severity=Severity.LOW,
                        evidence_ids=[ev.id],
                        location=ev.source,
                        controls=list(PIN_CONTROLS),
                        remediation="Pin to an exact version and manage upgrades via lockfiles/PRs.",
                        metadata={"package": dep["name"], "ecosystem": dep["ecosystem"]},
                    ))
                if self.osv_query:
                    vulns = self.osv_query(dep["name"], dep["ecosystem"], dep["version"] or None)
                    for vuln in vulns:
                        seq += 1
                        aliases = ", ".join(vuln.get("aliases", [])) or vuln.get("id", "unknown")
                        findings.append(Finding(
                            id=new_finding_id(self.name, seq),
                            capability=self.name,
                            title=f"Known vulnerability {vuln.get('id', 'unknown')} in {dep['name']} {dep['version']}",
                            description=(
                                f"{dep['name']} {dep['version']} ({dep['ecosystem']}) matches advisory "
                                f"{vuln.get('id', 'unknown')} ({aliases}): {vuln.get('summary', 'no summary')}"
                            ),
                            severity=_vuln_severity(vuln),
                            evidence_ids=[ev.id],
                            location=ev.source,
                            controls=list(VULN_CONTROLS),
                            remediation="Upgrade to a fixed version per the advisory.",
                            metadata={
                                "advisory": vuln.get("id"),
                                "aliases": vuln.get("aliases", []),
                                "package": dep["name"],
                                "version": dep["version"],
                            },
                        ))
        return findings
