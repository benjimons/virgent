"""Compliance control catalog and finding-to-control mapping.

A deliberately compact catalog covering the controls that Virgent's built-in
capabilities can produce evidence for. Control IDs use the form
``<FRAMEWORK>:<control>``; capabilities attach these IDs to findings, and
reports pivot findings into a per-framework coverage matrix.

Enterprises can extend the catalog at runtime via :func:`register_control`.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

# control id -> {framework, title}
CONTROLS: dict[str, dict] = {
    # SOC 2 Trust Services Criteria (security)
    "SOC2:CC6.1": {"framework": "SOC2", "title": "Logical access security software, infrastructure, and architectures"},
    "SOC2:CC6.6": {"framework": "SOC2", "title": "Protection against threats from outside system boundaries"},
    "SOC2:CC7.1": {"framework": "SOC2", "title": "Detection and monitoring of configuration changes and vulnerabilities"},
    "SOC2:CC7.2": {"framework": "SOC2", "title": "Monitoring for anomalies indicative of malicious acts"},
    "SOC2:CC8.1": {"framework": "SOC2", "title": "Authorized, designed, tested, and approved changes"},
    # ISO/IEC 27001:2022 Annex A
    "ISO27001:A.5.7": {"framework": "ISO27001", "title": "Threat intelligence"},
    "ISO27001:A.8.8": {"framework": "ISO27001", "title": "Management of technical vulnerabilities"},
    "ISO27001:A.8.9": {"framework": "ISO27001", "title": "Configuration management"},
    "ISO27001:A.8.24": {"framework": "ISO27001", "title": "Use of cryptography / key management"},
    "ISO27001:A.8.28": {"framework": "ISO27001", "title": "Secure coding"},
    # NIST SP 800-53 rev5
    "NIST:IA-5": {"framework": "NIST-800-53", "title": "Authenticator management"},
    "NIST:RA-5": {"framework": "NIST-800-53", "title": "Vulnerability monitoring and scanning"},
    "NIST:SI-2": {"framework": "NIST-800-53", "title": "Flaw remediation"},
    "NIST:CM-6": {"framework": "NIST-800-53", "title": "Configuration settings"},
    "NIST:SR-3": {"framework": "NIST-800-53", "title": "Supply chain controls and processes"},
    "NIST:AU-2": {"framework": "NIST-800-53", "title": "Event logging"},
    "NIST:AU-6": {"framework": "NIST-800-53", "title": "Audit record review, analysis, and reporting"},
    "NIST:SI-4": {"framework": "NIST-800-53", "title": "System monitoring"},
    "NIST:SI-7": {"framework": "NIST-800-53", "title": "Software, firmware, and information integrity"},
    "NIST:CA-8": {"framework": "NIST-800-53", "title": "Penetration testing"},
    "NIST:RA-7": {"framework": "NIST-800-53", "title": "Risk response"},
    "NIST:IR-4": {"framework": "NIST-800-53", "title": "Incident handling"},
    "NIST:IR-5": {"framework": "NIST-800-53", "title": "Incident monitoring"},
    "NIST:IR-6": {"framework": "NIST-800-53", "title": "Incident reporting"},
    # OWASP Top 10 (2021)
    "OWASP:A01": {"framework": "OWASP-Top10", "title": "Broken access control"},
    "OWASP:A02": {"framework": "OWASP-Top10", "title": "Cryptographic failures"},
    "OWASP:A05": {"framework": "OWASP-Top10", "title": "Security misconfiguration"},
    "OWASP:A06": {"framework": "OWASP-Top10", "title": "Vulnerable and outdated components"},
    "OWASP:A07": {"framework": "OWASP-Top10", "title": "Identification and authentication failures"},
    "OWASP:A08": {"framework": "OWASP-Top10", "title": "Software and data integrity failures"},
    # CIS Benchmarks (host hardening families)
    "CIS:1.4": {"framework": "CIS", "title": "Secure permissions on critical system files"},
    "CIS:2.2": {"framework": "CIS", "title": "Minimize exposed network services"},
    "CIS:3.3": {"framework": "CIS", "title": "Network kernel parameters (host hardening)"},
    "CIS:4.4": {"framework": "CIS", "title": "Host-based firewall configured"},
    "CIS:5.2": {"framework": "CIS", "title": "SSH server configuration hardening"},
    "CIS:5.4": {"framework": "CIS", "title": "User accounts and access controls"},
    # Additional NIST SP 800-53 controls exercised by host inspection
    "NIST:AC-2": {"framework": "NIST-800-53", "title": "Account management"},
    "NIST:AC-6": {"framework": "NIST-800-53", "title": "Least privilege"},
    "NIST:AC-17": {"framework": "NIST-800-53", "title": "Remote access"},
    "NIST:CM-7": {"framework": "NIST-800-53", "title": "Least functionality"},
    "NIST:SC-7": {"framework": "NIST-800-53", "title": "Boundary protection"},
    # Additional ISO/IEC 27001:2022 Annex A controls
    "ISO27001:A.5.15": {"framework": "ISO27001", "title": "Access control"},
    "ISO27001:A.5.16": {"framework": "ISO27001", "title": "Identity management"},
    "ISO27001:A.8.5": {"framework": "ISO27001", "title": "Secure authentication"},
    "ISO27001:A.8.20": {"framework": "ISO27001", "title": "Networks security"},
    "ISO27001:A.8.16": {"framework": "ISO27001", "title": "Monitoring activities"},
}


def register_control(control_id: str, framework: str, title: str) -> None:
    CONTROLS[control_id] = {"framework": framework, "title": title}


def frameworks() -> list[str]:
    return sorted({c["framework"] for c in CONTROLS.values()})


def controls_for(ids: Iterable[str]) -> list[dict]:
    out = []
    for cid in ids:
        meta = CONTROLS.get(cid, {"framework": "unknown", "title": "(unregistered control)"})
        out.append({"id": cid, **meta})
    return out


def coverage(findings: Iterable) -> dict[str, dict[str, list[str]]]:
    """framework -> control id -> list of finding ids referencing it."""
    matrix: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        for cid in finding.controls:
            fw = CONTROLS.get(cid, {}).get("framework", "unknown")
            matrix[fw][cid].append(finding.id)
    return {fw: dict(controls) for fw, controls in matrix.items()}
