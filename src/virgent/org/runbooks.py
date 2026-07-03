"""Runbook / playbook library.

Structured, human-readable procedures the org follows for common situations.
Each runbook declares the triggers (detection rules or finding capabilities)
that select it, the owning roles, ordered steps, and the controls it
satisfies. The SOC uses these to attach guidance to incidents.
"""
from __future__ import annotations

RUNBOOKS: dict[str, dict] = {
    "ir-ssh-brute-force": {
        "title": "SSH brute force / password spray",
        "triggers": ["ssh-brute-force", "password-spray"],
        "owner": "soc-analyst",
        "controls": ["NIST:IR-4", "NIST:AC-7", "CSF:RS.MI-01", "ATTACK:T1110"],
        "steps": [
            "Confirm the source IP and target accounts from the correlated alerts.",
            "Block the source IP at the perimeter/host firewall (respond.block_ip).",
            "Check for any successful authentication from the same IP.",
            "If a success occurred, invoke the compromise runbook.",
            "Enable/verify account lockout and rate limiting.",
            "Record the timeline and close or escalate the incident.",
        ],
    },
    "ir-account-compromise": {
        "title": "Suspected account compromise",
        "triggers": ["successful-login-after-bruteforce"],
        "owner": "incident-responder",
        "controls": ["NIST:IR-4", "CSF:RS.MI-01", "CSF:RS.MI-02", "ATTACK:T1078"],
        "steps": [
            "Treat as an active breach; assign an incident responder.",
            "Disable the affected account(s) (respond.disable_user) — requires approval.",
            "Block the source IP and isolate the host if lateral movement is suspected.",
            "Rotate credentials and revoke active sessions/tokens.",
            "Hunt for persistence (new accounts, cron, systemd, SSH keys).",
            "Preserve evidence; document scope and impact.",
            "Recover: restore trust, re-enable access, monitor closely.",
        ],
    },
    "ir-web-attack": {
        "title": "Web application attack",
        "triggers": ["web-attack-sqli", "web-attack-path_traversal",
                     "web-attack-cmd_injection", "web-attack-xss"],
        "owner": "soc-analyst",
        "controls": ["NIST:IR-4", "OWASP:A03", "CSF:RS.MI-01", "ATTACK:T1190"],
        "steps": [
            "Identify the targeted endpoint and the attack signature.",
            "Block the source IP; consider a WAF rule for the pattern.",
            "Check whether the request succeeded (response codes, data access).",
            "If exploited, invoke the compromise runbook for the web host.",
            "File a vulnerability for the underlying weakness.",
        ],
    },
    "ir-privilege-escalation": {
        "title": "Privilege escalation / suspicious admin activity",
        "triggers": ["privileged-group-change", "sudo-suspicious-command"],
        "owner": "threat-hunter",
        "controls": ["NIST:AC-6", "CSF:DE.CM-03", "ATTACK:T1548"],
        "steps": [
            "Identify the user, command, and host from the alert.",
            "Verify whether the change was authorized (change record).",
            "If unauthorized, revert the change and disable the account.",
            "Hunt for related activity from the same actor.",
        ],
    },
    "vuln-remediation": {
        "title": "Vulnerability triage and remediation",
        "triggers": ["dependencies", "iac", "pentest"],
        "owner": "vuln-manager",
        "controls": ["NIST:RA-5", "NIST:SI-2", "CSF:ID.RA-01", "CSF:ID.RA-06"],
        "steps": [
            "Sync findings into the vulnerability register (vulns sync).",
            "Prioritize by risk score and SLA; acknowledge or accept with justification.",
            "Assign remediation owners; track to closure.",
            "Verify fixes (re-scan / re-test); resolve register entries.",
            "Report overdue items to the security manager.",
        ],
    },
    "secret-exposure": {
        "title": "Exposed credential response",
        "triggers": ["secrets"],
        "owner": "sec-engineer",
        "controls": ["NIST:IA-5", "CSF:PR.AA-01", "ISO27001:A.8.24", "OWASP:A07"],
        "steps": [
            "Treat the credential as compromised the moment it was committed.",
            "Revoke and rotate the credential immediately.",
            "Remove it from source and from git history.",
            "Move the secret to a secret manager; add pre-commit scanning.",
            "Review access logs for misuse of the exposed credential.",
        ],
    },
    "host-hardening": {
        "title": "Host hardening remediation",
        "triggers": ["host"],
        "owner": "sec-engineer",
        "controls": ["NIST:CM-6", "CSF:PR.PS-01", "CIS:5.2"],
        "steps": [
            "Review host findings against the CIS benchmark baseline.",
            "Prioritize SSH, account, and firewall findings.",
            "Apply hardening via configuration management (not ad-hoc).",
            "Re-run the host capability to confirm remediation.",
        ],
    },
    "integrity-response": {
        "title": "File integrity alarm",
        "triggers": ["fim"],
        "owner": "incident-responder",
        "controls": ["NIST:SI-7", "CSF:DE.CM-09", "ISO27001:A.8.9"],
        "steps": [
            "Determine whether the change to the baselined file was authorized.",
            "If unauthorized, treat as tampering and open an incident.",
            "Restore the file from a trusted source; capture the modified version.",
            "Hunt for how the change was made and by whom.",
        ],
    },
}


def select_runbooks(triggers) -> list[dict]:
    """Return runbooks whose triggers intersect the given rule/capability names."""
    wanted = set(triggers)
    out = []
    for name, rb in RUNBOOKS.items():
        if wanted & set(rb["triggers"]):
            out.append({"id": name, **rb})
    return out
