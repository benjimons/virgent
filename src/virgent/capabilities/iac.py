"""Infrastructure-as-code and CI pipeline misconfiguration checks.

Covers the highest-signal, lowest-false-positive rules for Dockerfiles,
GitHub Actions workflows, and Kubernetes manifests.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from . import Capability

MISCONFIG_CONTROLS = ["SOC2:CC6.6", "ISO27001:A.8.9", "NIST:CM-6", "OWASP:A05"]
INTEGRITY_CONTROLS = ["SOC2:CC8.1", "NIST:SR-3", "OWASP:A08"]


def _line_of(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def check_dockerfile(content: str) -> list[dict]:
    issues = []
    has_user = re.search(r"(?im)^\s*USER\s+(?!root\b)\S+", content)
    if re.search(r"(?im)^\s*FROM\s+\S+", content) and not has_user:
        issues.append({
            "rule": "docker-runs-as-root",
            "title": "Container runs as root (no USER instruction)",
            "severity": Severity.MEDIUM,
            "line": 1,
            "controls": MISCONFIG_CONTROLS,
            "remediation": "Add a non-root USER instruction after installing dependencies.",
        })
    for m in re.finditer(r"(?im)^\s*FROM\s+([^\s:@]+)(?::latest)?\s*(?:AS\s+\w+)?\s*$", content):
        if ":" not in m.group(0).replace("FROM", "", 1).strip().split()[0] or ":latest" in m.group(0):
            issues.append({
                "rule": "docker-unpinned-base-image",
                "title": f"Base image '{m.group(1)}' is not pinned to a version/digest",
                "severity": Severity.LOW,
                "line": _line_of(content, m.start()),
                "controls": INTEGRITY_CONTROLS,
                "remediation": "Pin the base image to a specific tag or, better, a digest.",
            })
    for m in re.finditer(r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b", content):
        issues.append({
            "rule": "docker-curl-pipe-sh",
            "title": "Remote script piped directly to a shell",
            "severity": Severity.HIGH,
            "line": _line_of(content, m.start()),
            "controls": INTEGRITY_CONTROLS,
            "remediation": "Download, checksum-verify, then execute installation scripts.",
        })
    for m in re.finditer(r"(?im)^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY)\w*\s*[= ]\s*\S+", content):
        issues.append({
            "rule": "docker-secret-in-env",
            "title": "Secret-looking value baked into image via ENV/ARG",
            "severity": Severity.HIGH,
            "line": _line_of(content, m.start()),
            "controls": ["SOC2:CC6.1", "NIST:IA-5", "OWASP:A07"],
            "remediation": "Inject secrets at runtime (secret manager / orchestrator), never at build time.",
        })
    return issues


def check_github_actions(content: str) -> list[dict]:
    issues = []
    if re.search(r"(?m)^\s*pull_request_target\s*:", content) and re.search(r"actions/checkout", content):
        issues.append({
            "rule": "gha-pull-request-target-checkout",
            "title": "pull_request_target workflow checks out untrusted PR code",
            "severity": Severity.CRITICAL,
            "line": 1,
            "controls": ["SOC2:CC8.1", "NIST:SR-3", "OWASP:A08", "SOC2:CC6.6"],
            "remediation": (
                "Do not combine pull_request_target with a checkout of the PR head; "
                "untrusted code runs with repository secrets."
            ),
        })
    for m in re.finditer(r"(?m)^\s*(?:-\s+)?uses:\s*([\w.\-]+/[\w.\-/]+)@([\w.\-]+)", content):
        action, ref = m.group(1), m.group(2)
        if action.startswith(("actions/", "github/")):
            continue
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            issues.append({
                "rule": "gha-unpinned-action",
                "title": f"Third-party action '{action}' not pinned to a commit SHA (uses @{ref})",
                "severity": Severity.MEDIUM,
                "line": _line_of(content, m.start()),
                "controls": INTEGRITY_CONTROLS,
                "remediation": "Pin third-party actions to a full-length commit SHA.",
            })
    for m in re.finditer(r"(?i)echo\s+[^\n]*\$\{\{\s*secrets\.", content):
        issues.append({
            "rule": "gha-secret-echoed",
            "title": "Workflow echoes a secret to the build log",
            "severity": Severity.HIGH,
            "line": _line_of(content, m.start()),
            "controls": ["SOC2:CC6.1", "NIST:IA-5", "NIST:AU-2"],
            "remediation": "Never print secrets; pass them via env with masking.",
        })
    return issues


def check_kubernetes(content: str) -> list[dict]:
    issues = []
    for rule, pattern, title, severity in [
        ("k8s-privileged", r"(?m)^\s*privileged:\s*true", "Privileged container", Severity.HIGH),
        ("k8s-host-network", r"(?m)^\s*hostNetwork:\s*true", "Pod uses host network", Severity.MEDIUM),
        ("k8s-allow-priv-esc", r"(?m)^\s*allowPrivilegeEscalation:\s*true", "Privilege escalation allowed", Severity.MEDIUM),
        ("k8s-run-as-root", r"(?m)^\s*runAsUser:\s*0\b", "Container runs as UID 0", Severity.MEDIUM),
    ]:
        for m in re.finditer(pattern, content):
            issues.append({
                "rule": rule,
                "title": title,
                "severity": severity,
                "line": _line_of(content, m.start()),
                "controls": MISCONFIG_CONTROLS,
                "remediation": "Apply least-privilege pod security settings.",
            })
    return issues


def check_terraform(content: str) -> list[dict]:
    issues = []
    for m in re.finditer(r'(?i)cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', content):
        issues.append({
            "rule": "tf-open-ingress",
            "title": "Security group allows ingress from 0.0.0.0/0",
            "severity": Severity.HIGH,
            "line": _line_of(content, m.start()),
            "controls": ["SOC2:CC6.6", "NIST:SC-7", "CIS:4.4", "OWASP:A05", "PCI:1"],
            "remediation": "Restrict ingress CIDRs to known networks; never expose management ports to the internet.",
        })
    for m in re.finditer(r'(?i)acl\s*=\s*"public-read(?:-write)?"', content):
        issues.append({
            "rule": "tf-public-bucket",
            "title": "Object storage bucket has a public ACL",
            "severity": Severity.HIGH,
            "line": _line_of(content, m.start()),
            "controls": ["SOC2:CC6.1", "NIST:AC-3", "ISO27001:A.5.15", "OWASP:A01"],
            "remediation": "Make the bucket private and use signed URLs or explicit policies for access.",
        })
    for m in re.finditer(r'(?i)(?:password|secret|token|access_key)\s*=\s*"[^"$][^"]{6,}"', content):
        value = m.group(0)
        if "var." in value or "${" in value:
            continue
        issues.append({
            "rule": "tf-hardcoded-secret",
            "title": "Hardcoded secret in Terraform",
            "severity": Severity.HIGH,
            "line": _line_of(content, m.start()),
            "controls": ["SOC2:CC6.1", "NIST:IA-5", "ISO27001:A.8.24", "OWASP:A07"],
            "remediation": "Move secrets to a secret manager or injected variables; never commit them.",
        })
    if re.search(r"(?i)\bresource\s+\"aws_s3_bucket\"", content) and \
            not re.search(r"(?i)server_side_encryption", content):
        issues.append({
            "rule": "tf-unencrypted-storage",
            "title": "S3 bucket without server-side encryption configured",
            "severity": Severity.MEDIUM,
            "line": 1,
            "controls": ["SOC2:CC6.1", "NIST:SC-28", "ISO27001:A.8.24", "OWASP:A02", "PCI:3"],
            "remediation": "Enable default server-side encryption on the bucket.",
        })
    return issues


class IaCCapability(Capability):
    name = "iac"
    description = "Detect misconfigurations in Dockerfiles, CI workflows, Kubernetes, and Terraform"

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            filename = ev.metadata.get("filename", ev.source).lower()
            source_lower = ev.source.lower().replace("\\", "/")
            issues: list[dict] = []
            if "dockerfile" in filename:
                issues = check_dockerfile(ev.content)
            elif filename.endswith(".tf"):
                issues = check_terraform(ev.content)
            elif filename.endswith((".yml", ".yaml")):
                if "/.github/workflows/" in source_lower or ".github/workflows" in source_lower:
                    issues = check_github_actions(ev.content)
                elif re.search(r"(?m)^kind:\s*(Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob)\b", ev.content):
                    issues = check_kubernetes(ev.content)
            for issue in issues:
                seq += 1
                findings.append(Finding(
                    id=new_finding_id(self.name, seq),
                    capability=self.name,
                    title=issue["title"],
                    description=f"Rule '{issue['rule']}' matched in {ev.source} at line {issue['line']}.",
                    severity=issue["severity"],
                    evidence_ids=[ev.id],
                    location=f"{ev.source}:{issue['line']}",
                    controls=list(issue["controls"]),
                    remediation=issue["remediation"],
                    metadata={"rule": issue["rule"]},
                ))
        return findings
