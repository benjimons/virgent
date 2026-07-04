"""CIEM — Cloud Infrastructure Entitlement Management.

Aggregate privilege analysis across cloud IAM and the identity provider:
surfaces privilege *concentration* and *toxic combinations* that per-resource
CSPM rules miss — e.g. too large an admin population, admins without MFA, and
privileged service accounts. Operates on the normalized identity evidence
(cloud ``iam``/``service_account`` resources and ``identity-account`` records).
"""
from __future__ import annotations

import json
from typing import Iterable

from .models import Evidence, Finding, Severity, new_finding_id

CIEM_CONTROLS = ["NIST:AC-6", "NIST:AC-2", "ISO27001:A.5.15", "SOC2:CC6.1"]

ADMIN_CONCENTRATION_PCT = 20   # admins as a share of identities considered excessive


def _identities(evidence: Iterable[Evidence]) -> list[dict]:
    ids = []
    for ev in evidence:
        if ev.kind == "identity-account":
            try:
                a = json.loads(ev.content)
                ids.append({"id": a.get("id"), "admin": a.get("admin"),
                            "mfa": a.get("mfa_enabled"), "svc": a.get("service_account"),
                            "source": ev.id, "kind": "idp"})
            except json.JSONDecodeError:
                continue
        elif ev.kind == "cloud-asset":
            try:
                r = json.loads(ev.content)
            except json.JSONDecodeError:
                continue
            if r.get("rtype") in ("user", "service_account"):
                cfg = r.get("config", {})
                ids.append({"id": r.get("id"), "admin": cfg.get("admin_policy"),
                            "mfa": cfg.get("mfa_enabled", True),
                            "svc": r.get("rtype") == "service_account",
                            "source": ev.id, "kind": "cloud"})
    return ids


def analyze_entitlements(evidence: Iterable[Evidence]) -> list[Finding]:
    identities = _identities(evidence)
    findings: list[Finding] = []
    seq = 0
    if not identities:
        return findings

    admins = [i for i in identities if i["admin"]]
    total = len(identities)
    pct = round(100 * len(admins) / total, 1) if total else 0

    def add(title, desc, severity, evidence_ids, rule):
        nonlocal seq
        seq += 1
        findings.append(Finding(
            id=new_finding_id("ciem", seq), capability="ciem", title=title,
            description=desc, severity=severity, evidence_ids=evidence_ids,
            controls=list(CIEM_CONTROLS), remediation=(
                "Apply least privilege: reduce standing admin, require MFA on all "
                "privileged identities, and prefer just-in-time elevation."),
            metadata={"rule": rule}))

    # privilege concentration
    if total >= 5 and pct >= ADMIN_CONCENTRATION_PCT:
        add(f"Excessive admin concentration: {pct}% of identities are privileged "
            f"({len(admins)}/{total})",
            f"{len(admins)} of {total} identities hold admin/owner privileges "
            f"({pct}%, threshold {ADMIN_CONCENTRATION_PCT}%). A large admin blast "
            "radius magnifies any single compromise.",
            Severity.HIGH if pct >= 40 else Severity.MEDIUM,
            [i["source"] for i in admins][:50], "ciem-admin-concentration")

    # toxic combination: privileged identity without MFA
    for i in admins:
        if not i["mfa"] and not i["svc"]:
            add(f"Privileged identity '{i['id']}' has admin without MFA",
                "An admin identity lacking MFA is a single-factor path to full control.",
                Severity.HIGH, [i["source"]], "ciem-admin-no-mfa")

    # privileged service accounts (non-interactive, hard to rotate/monitor)
    for i in admins:
        if i["svc"]:
            add(f"Privileged service account '{i['id']}'",
                "Service accounts with admin rights are high-value, non-interactive "
                "targets; scope them down and rotate their credentials.",
                Severity.HIGH, [i["source"]], "ciem-privileged-svc")
    return findings
