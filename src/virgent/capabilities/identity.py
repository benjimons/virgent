"""Identity posture (IdP hygiene) checks.

Consumes ``identity-account`` evidence and flags the classic identity
weaknesses: privileged accounts without MFA, dormant accounts, over-broad
admin, stale credentials, and lingering disabled accounts. Mapped to
account-management and authentication controls.
"""
from __future__ import annotations

import json
from typing import Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from . import Capability

IAM_CONTROLS = ["NIST:AC-2", "NIST:IA-5", "SOC2:CC6.1", "ISO27001:A.5.16"]
ACCESS_CONTROLS = ["NIST:AC-6", "NIST:AC-2", "ISO27001:A.5.15"]
AUTH_CONTROLS = ["NIST:IA-5", "SOC2:CC6.1", "ISO27001:A.8.5"]

DORMANT_DAYS = 90
STALE_CRED_DAYS = 365


def check_account(a: dict) -> list[dict]:
    issues = []
    admin = a.get("admin")
    mfa = a.get("mfa_enabled")
    status = a.get("status", "active")
    last = a.get("last_login_days")
    cred = a.get("credential_age_days")

    if status == "active" and not mfa and not a.get("service_account"):
        sev = Severity.HIGH if admin else Severity.MEDIUM
        issues.append(("identity-no-mfa",
                       f"Account '{a['email'] or a['id']}' has no MFA" + (" (admin)" if admin else ""),
                       sev, AUTH_CONTROLS, "Enforce MFA; require it for all users, mandatory for admins."))
    if admin and a.get("service_account"):
        issues.append(("identity-privileged-svc-account",
                       f"Service account '{a['email'] or a['id']}' holds admin privileges",
                       Severity.HIGH, ACCESS_CONTROLS,
                       "Scope service accounts to least privilege; avoid admin roles."))
    if status == "active" and isinstance(last, int) and last > DORMANT_DAYS:
        issues.append(("identity-dormant",
                       f"Account '{a['email'] or a['id']}' dormant for {last} days",
                       Severity.HIGH if admin else Severity.MEDIUM, IAM_CONTROLS,
                       f"Disable or remove accounts idle > {DORMANT_DAYS} days."))
    if status in ("suspended", "deprovisioned"):
        issues.append(("identity-disabled-present",
                       f"Disabled account '{a['email'] or a['id']}' ({status}) still present",
                       Severity.MEDIUM, IAM_CONTROLS,
                       "Complete deprovisioning; remove residual disabled accounts."))
    if isinstance(cred, int) and cred > STALE_CRED_DAYS:
        issues.append(("identity-stale-credential",
                       f"Account '{a['email'] or a['id']}' credential is {cred} days old",
                       Severity.MEDIUM, AUTH_CONTROLS,
                       "Rotate credentials; enforce a maximum credential age."))
    return issues


class IdentityPostureCapability(Capability):
    name = "identity"
    description = "Identity posture (IdP hygiene): MFA coverage, dormant/disabled accounts, admin sprawl, stale creds"

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            if ev.kind != "identity-account":
                continue
            try:
                a = json.loads(ev.content)
            except json.JSONDecodeError:
                continue
            for rule, title, severity, controls, remediation in check_account(a):
                seq += 1
                findings.append(Finding(
                    id=new_finding_id(self.name, seq),
                    capability=self.name, title=title,
                    description=f"Identity rule '{rule}' matched on {a.get('provider')} "
                                f"account '{a.get('id')}'.",
                    severity=severity, evidence_ids=[ev.id],
                    location=f"{a.get('provider')}:{a.get('id')}",
                    controls=list(controls), remediation=remediation,
                    metadata={"rule": rule, "provider": a.get("provider"),
                              "account": a.get("id")}))
        return findings
