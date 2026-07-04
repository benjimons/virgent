"""Cloud posture (CSPM) checks.

Consumes ``cloud-asset`` evidence (normalized cloud resources) and flags the
highest-signal misconfigurations: public object storage, unencrypted data
stores, security groups open to the internet on sensitive ports, and IAM
hygiene (stale keys, missing MFA, over-broad admin grants). Findings map to
access-control, boundary-protection, and cryptography controls.
"""
from __future__ import annotations

import json
from typing import Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from . import Capability

PUBLIC_CONTROLS = ["SOC2:CC6.1", "NIST:AC-3", "ISO27001:A.5.15", "OWASP:A01"]
CRYPTO_CONTROLS = ["NIST:SC-28", "ISO27001:A.8.24", "OWASP:A02"]
BOUNDARY_CONTROLS = ["SOC2:CC6.6", "NIST:SC-7", "CIS:4.4", "OWASP:A05", "PCI:1"]
IAM_CONTROLS = ["SOC2:CC6.1", "NIST:AC-2", "NIST:IA-5", "ISO27001:A.5.15"]

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                   6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 23: "Telnet"}
MAX_KEY_AGE_DAYS = 90


def _port_in(rule: dict, port: int) -> bool:
    frm, to = rule.get("from"), rule.get("to")
    if frm is None or to is None:   # all ports
        return True
    try:
        return int(frm) <= port <= int(to)
    except (TypeError, ValueError):
        return False


def check_bucket(r: dict) -> list[dict]:
    cfg = r["config"]
    issues = []
    if cfg.get("public"):
        issues.append(("cloud-s3-public", f"S3 bucket '{r['id']}' is publicly accessible",
                       Severity.CRITICAL, PUBLIC_CONTROLS,
                       "Enable Block Public Access and remove public ACLs/policies."))
    if not cfg.get("encrypted", True):
        issues.append(("cloud-s3-unencrypted", f"S3 bucket '{r['id']}' has no default encryption",
                       Severity.MEDIUM, CRYPTO_CONTROLS,
                       "Enable default SSE (SSE-S3 or SSE-KMS) on the bucket."))
    if not cfg.get("public_access_block", True) and not cfg.get("public"):
        issues.append(("cloud-s3-no-pab", f"S3 bucket '{r['id']}' has no full Block Public Access",
                       Severity.MEDIUM, PUBLIC_CONTROLS,
                       "Turn on all four Block Public Access settings."))
    return issues


def check_security_group(r: dict) -> list[dict]:
    cfg = r["config"]
    issues = []
    for rule in cfg.get("open_ingress", []):
        if rule.get("from") is None:   # an all-ports rule is the worst case
            issues.append((
                "cloud-sg-open-all",
                f"Security group '{r['id']}' allows 0.0.0.0/0 to all ports",
                Severity.HIGH, BOUNDARY_CONTROLS,
                "Replace the all-ports rule with least-privilege port ranges from known sources."))
            continue
        hit = [name for port, name in SENSITIVE_PORTS.items() if _port_in(rule, port)]
        if hit:
            issues.append((
                "cloud-sg-open-sensitive",
                f"Security group '{r['id']}' allows 0.0.0.0/0 to {', '.join(hit)}",
                Severity.HIGH, BOUNDARY_CONTROLS,
                "Restrict ingress to known CIDRs; never expose management/database ports to the internet."))
    return issues


def check_rds(r: dict) -> list[dict]:
    cfg = r["config"]
    issues = []
    if cfg.get("publicly_accessible"):
        issues.append(("cloud-rds-public", f"RDS instance '{r['id']}' is publicly accessible",
                       Severity.HIGH, BOUNDARY_CONTROLS,
                       "Set PubliclyAccessible=false and place the DB in a private subnet."))
    if not cfg.get("encrypted", True):
        issues.append(("cloud-rds-unencrypted", f"RDS instance '{r['id']}' storage is not encrypted",
                       Severity.MEDIUM, CRYPTO_CONTROLS,
                       "Enable storage encryption (KMS); recreate from an encrypted snapshot if needed."))
    return issues


def check_iam_user(r: dict) -> list[dict]:
    cfg = r["config"]
    issues = []
    if cfg.get("console_access") and not cfg.get("mfa_enabled"):
        issues.append(("cloud-iam-no-mfa", f"IAM user '{r['id']}' has console access without MFA",
                       Severity.HIGH, IAM_CONTROLS,
                       "Require MFA for all console users."))
    age = cfg.get("max_access_key_age_days")
    if isinstance(age, int) and age > MAX_KEY_AGE_DAYS:
        issues.append(("cloud-iam-stale-key",
                       f"IAM user '{r['id']}' has an access key {age} days old (> {MAX_KEY_AGE_DAYS})",
                       Severity.MEDIUM, IAM_CONTROLS,
                       "Rotate access keys regularly; prefer short-lived role credentials."))
    if cfg.get("admin_policy"):
        issues.append(("cloud-iam-admin", f"IAM user '{r['id']}' has AdministratorAccess attached",
                       Severity.HIGH, IAM_CONTROLS,
                       "Apply least privilege; scope permissions to what the user needs."))
    return issues


_DISPATCH = {
    ("s3", "bucket"): check_bucket,
    ("ec2", "security_group"): check_security_group,
    ("rds", "db_instance"): check_rds,
    ("iam", "user"): check_iam_user,
}


class CloudPostureCapability(Capability):
    name = "cloud"
    description = "Cloud posture (CSPM): public storage, open security groups, unencrypted data, IAM hygiene"

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            if ev.kind != "cloud-asset":
                continue
            try:
                r = json.loads(ev.content)
            except json.JSONDecodeError:
                continue
            check = _DISPATCH.get((r.get("service"), r.get("rtype")))
            if not check:
                continue
            for rule, title, severity, controls, remediation in check(r):
                seq += 1
                findings.append(Finding(
                    id=new_finding_id(self.name, seq),
                    capability=self.name,
                    title=title,
                    description=(f"Cloud posture rule '{rule}' matched on "
                                 f"{r.get('provider')} {r.get('service')}:{r.get('rtype')} "
                                 f"'{r.get('id')}' ({r.get('region')})."),
                    severity=severity,
                    evidence_ids=[ev.id],
                    location=f"{r.get('provider')}:{r.get('region')}:{r.get('id')}",
                    controls=list(controls),
                    remediation=remediation,
                    metadata={"rule": rule, "service": r.get("service"),
                              "resource": r.get("id")},
                ))
        return findings
