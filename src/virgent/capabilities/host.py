"""Host hardening inspection (CIS-benchmark style).

Consumes ``host-fact`` evidence produced by :class:`HostIngestor` and applies
read-only configuration-review rules covering the highest-signal host
weaknesses: SSH server hardening, privileged/empty-password accounts, kernel
network parameters, host firewall state, exposed network services, and
permissions on sensitive files. Findings map to CIS, NIST 800-53, and ISO
27001 controls.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from . import Capability

# control bundles
SSH_CONTROLS = ["CIS:5.2", "NIST:AC-6", "NIST:AC-17", "ISO27001:A.8.5"]
ACCOUNT_CONTROLS = ["CIS:5.4", "NIST:AC-2", "NIST:IA-5", "ISO27001:A.5.16"]
SYSCTL_CONTROLS = ["CIS:3.3", "NIST:CM-6", "NIST:SC-7", "ISO27001:A.8.9"]
FIREWALL_CONTROLS = ["CIS:4.4", "NIST:SC-7", "ISO27001:A.8.20"]
SERVICE_CONTROLS = ["CIS:2.2", "NIST:CM-7", "NIST:SC-7", "ISO27001:A.8.20"]
PERM_CONTROLS = ["CIS:1.4", "NIST:AC-6", "NIST:CM-6", "ISO27001:A.8.9"]

# expected /proc/sys values; deviation is a finding
SYSCTL_EXPECTED = {
    "kernel.randomize_va_space": ("2", Severity.MEDIUM, "ASLR is not fully enabled"),
    "fs.suid_dumpable": ("0", Severity.LOW, "SUID programs may produce core dumps"),
    "net.ipv4.ip_forward": ("0", Severity.LOW, "IP forwarding is enabled (host acts as a router)"),
    "net.ipv4.tcp_syncookies": ("1", Severity.MEDIUM, "TCP SYN cookies are disabled (SYN-flood exposure)"),
    "net.ipv4.conf.all.accept_redirects": ("0", Severity.LOW, "ICMP redirects are accepted"),
    "net.ipv4.conf.all.send_redirects": ("0", Severity.LOW, "ICMP redirects are sent"),
    "net.ipv4.conf.all.accept_source_route": ("0", Severity.LOW, "Source-routed packets are accepted"),
}

# port -> (service, severity when exposed on all interfaces)
SENSITIVE_PORTS = {
    23: ("telnet", Severity.CRITICAL),
    2375: ("docker-api", Severity.CRITICAL),
    2379: ("etcd", Severity.HIGH),
    3306: ("mysql", Severity.HIGH),
    5432: ("postgresql", Severity.HIGH),
    5984: ("couchdb", Severity.HIGH),
    6379: ("redis", Severity.HIGH),
    9200: ("elasticsearch", Severity.HIGH),
    11211: ("memcached", Severity.HIGH),
    27017: ("mongodb", Severity.HIGH),
}

_ALL_INTERFACES = {"0.0.0.0", "::", "*", "[::]"}
_ADDR_PORT = re.compile(r"^(.*):(\d+)$")


def _sshd_directives(content: str) -> dict[str, str]:
    """Last uncommented value wins, matching sshd's parsing."""
    directives: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            directives[parts[0].lower()] = parts[1].strip().split()[0].lower()
    return directives


def check_sshd(content: str) -> list[dict]:
    d = _sshd_directives(content)
    issues = []

    def add(rule, title, severity, controls=SSH_CONTROLS, remediation=""):
        issues.append({"rule": rule, "title": title, "severity": severity,
                       "controls": controls, "remediation": remediation})

    if d.get("permitemptypasswords") == "yes":
        add("ssh-permit-empty-passwords", "SSH permits empty passwords", Severity.CRITICAL,
            remediation="Set 'PermitEmptyPasswords no'.")
    if d.get("permitrootlogin") in ("yes", "prohibit-password", "without-password") and \
            d.get("permitrootlogin") == "yes":
        add("ssh-permit-root-login", "SSH permits direct root login", Severity.HIGH,
            remediation="Set 'PermitRootLogin no' and use a non-root account with sudo.")
    if d.get("protocol") == "1":
        add("ssh-protocol-1", "SSH protocol 1 enabled (cryptographically broken)", Severity.HIGH,
            remediation="Remove 'Protocol 1'; only SSH protocol 2 is safe.")
    if d.get("passwordauthentication") == "yes":
        add("ssh-password-auth", "SSH password authentication enabled", Severity.MEDIUM,
            remediation="Prefer key-based auth: set 'PasswordAuthentication no'.")
    if d.get("x11forwarding") == "yes":
        add("ssh-x11-forwarding", "SSH X11 forwarding enabled", Severity.LOW,
            remediation="Set 'X11Forwarding no' unless explicitly required.")
    if d.get("permituserenvironment") == "yes":
        add("ssh-permit-user-env", "SSH PermitUserEnvironment enabled", Severity.LOW,
            remediation="Set 'PermitUserEnvironment no' to prevent env-based bypass.")
    return issues


def check_users(content: str) -> list[dict]:
    issues = []
    section = None
    for line in content.splitlines():
        line = line.rstrip("\n")
        if line.startswith("# /etc/passwd"):
            section = "passwd"
            continue
        if line.startswith("# /etc/shadow"):
            section = "shadow"
            continue
        if not line or ":" not in line:
            continue
        fields = line.split(":")
        if section == "passwd" and len(fields) >= 3:
            name = fields[0]
            try:
                uid = int(fields[2])
            except ValueError:
                continue
            if uid == 0 and name != "root":
                issues.append({
                    "rule": "account-uid0-nonroot",
                    "title": f"Non-root account '{name}' has UID 0 (root-equivalent)",
                    "severity": Severity.CRITICAL,
                    "controls": ACCOUNT_CONTROLS,
                    "remediation": "Only 'root' should have UID 0; investigate and remove this account.",
                })
        elif section == "shadow" and len(fields) >= 2:
            name, pw = fields[0], fields[1]
            if pw == "":
                issues.append({
                    "rule": "account-empty-password",
                    "title": f"Account '{name}' has an empty password",
                    "severity": Severity.CRITICAL,
                    "controls": ACCOUNT_CONTROLS,
                    "remediation": "Set a password or lock the account (passwd -l).",
                })
    return issues


def check_sysctl(content: str) -> list[dict]:
    issues = []
    values = {}
    for line in content.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()
    for key, (expected, severity, desc) in SYSCTL_EXPECTED.items():
        actual = values.get(key)
        if actual is not None and actual != expected:
            issues.append({
                "rule": f"sysctl-{key}",
                "title": f"Kernel parameter {key}={actual} (expected {expected})",
                "severity": severity,
                "controls": SYSCTL_CONTROLS,
                "remediation": f"{desc}. Set {key}={expected} in /etc/sysctl.d and reload.",
            })
    return issues


def check_firewall(content: str) -> list[dict]:
    if re.search(r"(?i)status:\s*inactive", content) or "inactive" in content.lower():
        return [{
            "rule": "firewall-inactive",
            "title": "Host firewall is inactive",
            "severity": Severity.MEDIUM,
            "controls": FIREWALL_CONTROLS,
            "remediation": "Enable and configure a host firewall (ufw/nftables) with a default-deny inbound policy.",
        }]
    return []


def check_listening(content: str) -> list[dict]:
    issues = []
    for line in content.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        local = None
        for token in line.split():
            m = _ADDR_PORT.match(token)
            if m and m.group(2).isdigit():
                local = (m.group(1), int(m.group(2)))
                break
        if not local:
            continue
        addr, port = local
        if port not in SENSITIVE_PORTS:
            continue
        service, severity = SENSITIVE_PORTS[port]
        exposed = addr in _ALL_INTERFACES
        if not exposed:
            continue
        issues.append({
            "rule": f"exposed-service-{service}",
            "title": f"{service} exposed on all interfaces ({addr}:{port})",
            "severity": severity,
            "controls": SERVICE_CONTROLS,
            "remediation": (
                f"Bind {service} to localhost or a private interface and restrict it with the firewall; "
                "disable the service if it is not required."
            ),
        })
    return issues


def _mode_int(mode: str) -> int:
    try:
        return int(mode, 8)
    except ValueError:
        return 0o777


def check_file_perms(content: str) -> list[dict]:
    issues = []
    for line in content.splitlines():
        m = re.match(r"^(\S+)\s+mode=(\d+)\s+owner=(\S+)", line.strip())
        if not m:
            continue
        path, mode, owner = m.group(1), m.group(2), m.group(3)
        bits = _mode_int(mode)
        world = bits & 0o007
        group_write = bits & 0o020
        if path in ("/etc/shadow", "/etc/gshadow"):
            if world or group_write:
                issues.append({
                    "rule": "perm-shadow-exposed",
                    "title": f"{path} is accessible beyond owner (mode {mode})",
                    "severity": Severity.HIGH,
                    "controls": PERM_CONTROLS,
                    "remediation": f"Restrict {path}: chmod 0640 root:shadow (or 0000) and verify ownership.",
                })
        elif world & 0o002:  # world-writable
            issues.append({
                "rule": "perm-world-writable",
                "title": f"{path} is world-writable (mode {mode})",
                "severity": Severity.HIGH,
                "controls": PERM_CONTROLS,
                "remediation": f"Remove world-write from {path} (chmod o-w).",
            })
        if owner not in ("root", "0") and path.startswith("/etc/"):
            issues.append({
                "rule": "perm-nonroot-owner",
                "title": f"{path} is owned by '{owner}', not root",
                "severity": Severity.MEDIUM,
                "controls": PERM_CONTROLS,
                "remediation": f"chown root {path}.",
            })
    return issues


_DISPATCH = {
    "sshd_config": check_sshd,
    "users": check_users,
    "sysctl": check_sysctl,
    "firewall": check_firewall,
    "listening": check_listening,
    "file-perms": check_file_perms,
}


class HostInspectionCapability(Capability):
    name = "host"
    description = "Inspect the running host for hardening weaknesses (SSH, accounts, kernel, firewall, exposed services, file permissions)"

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            if ev.kind != "host-fact":
                continue
            fact = ev.metadata.get("fact") or ev.source.rsplit(":", 1)[-1]
            check = _DISPATCH.get(fact)
            if not check:
                continue
            for issue in check(ev.content):
                seq += 1
                findings.append(Finding(
                    id=new_finding_id(self.name, seq),
                    capability=self.name,
                    title=issue["title"],
                    description=(
                        f"Host hardening rule '{issue['rule']}' matched on "
                        f"{ev.metadata.get('host', 'host')} (fact: {fact})."
                    ),
                    severity=issue["severity"],
                    evidence_ids=[ev.id],
                    location=ev.source,
                    controls=list(issue["controls"]),
                    remediation=issue["remediation"],
                    metadata={"rule": issue["rule"], "host": ev.metadata.get("host")},
                ))
        return findings
