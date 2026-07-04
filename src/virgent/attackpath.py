"""Attack-path correlation.

Individual findings are risk in isolation; an *attack path* is what turns two
medium issues into a breach. This correlates existing findings into toxic
combinations — an internet-exposed resource plus an over-privileged identity,
or public exposure plus unencrypted sensitive data — and raises a single,
higher-severity path finding that names the chain.

This is heuristic correlation over findings, not a full resource-relationship
graph (which needs relationship data Virgent doesn't yet collect); paths are
labelled as correlations for a human to confirm.
"""
from __future__ import annotations

from .models import Finding, Severity, new_finding_id

PATH_CONTROLS = ["NIST:SC-7", "NIST:AC-6", "NIST:CA-8", "OWASP:A01"]

# rule buckets that make up a path
EXPOSURE_RULES = {
    "cloud-s3-public", "cloud-rds-public", "cloud-sg-open-sensitive", "cloud-sg-open-all",
    "tf-open-ingress", "tf-public-bucket", "k8s-host-network",
}
PRIVILEGE_RULES = {
    "cloud-iam-admin", "cloud-iam-no-mfa", "ciem-admin-no-mfa", "ciem-privileged-svc",
    "identity-no-mfa", "account-uid0-nonroot",
}
DATA_RULES = {"cloud-s3-unencrypted", "cloud-rds-unencrypted", "tf-unencrypted-storage"}
EXPOSURE_RUNTIME = {"exposed-service-redis", "exposed-service-mysql", "exposed-service-postgresql",
                    "exposed-service-mongodb", "exposed-service-elasticsearch",
                    "exposed-service-telnet", "exposed-service-docker-api"}


def _rule(f: Finding) -> str:
    return f.metadata.get("rule", "")


def correlate_attack_paths(findings: list[Finding]) -> list[Finding]:
    exposure = [f for f in findings if _rule(f) in EXPOSURE_RULES | EXPOSURE_RUNTIME]
    privilege = [f for f in findings if _rule(f) in PRIVILEGE_RULES]
    data = [f for f in findings if _rule(f) in DATA_RULES]

    paths: list[Finding] = []
    seq = 0

    def add(title, desc, severity, members):
        nonlocal seq
        seq += 1
        evidence_ids = sorted({e for f in members for e in f.evidence_ids})
        paths.append(Finding(
            id=new_finding_id("attackpath", seq), capability="attackpath",
            title=title, description=desc, severity=severity,
            evidence_ids=evidence_ids, controls=list(PATH_CONTROLS),
            confidence="medium",
            remediation="Break the chain at the cheapest link — remove the public "
                        "exposure or the excess privilege — then address the rest.",
            metadata={"rule": "attack-path", "members": [f.id for f in members]}))

    # exposure + privilege = internet-reachable path to full control
    if exposure and privilege:
        add(f"Attack path: internet exposure + over-privileged identity "
            f"({len(exposure)} exposure, {len(privilege)} privilege finding(s))",
            "A publicly reachable resource co-exists with an over-privileged or "
            "unprotected identity. An attacker reaching the exposed surface can "
            "pivot to the excess privilege — chained, this is a full-control path. "
            f"Exposure: {', '.join(_rule(f) for f in exposure[:4])}; "
            f"privilege: {', '.join(_rule(f) for f in privilege[:4])}.",
            Severity.CRITICAL, exposure[:5] + privilege[:5])

    # public exposure + unencrypted data = exposed sensitive data at rest
    if exposure and data:
        add(f"Attack path: public exposure + unencrypted data at rest",
            "A publicly reachable resource sits alongside unencrypted storage; "
            "exposure of the surface risks direct disclosure of unprotected data. "
            f"Exposure: {', '.join(_rule(f) for f in exposure[:4])}; "
            f"data: {', '.join(_rule(f) for f in data[:4])}.",
            Severity.HIGH, exposure[:5] + data[:5])
    return paths
