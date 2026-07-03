"""Runtime threat inspection for live systems.

Consumes ``runtime-fact`` snapshots and flags indicators of compromise and
risky live state: reverse-shell command lines, execution from world-writable
staging directories, interactive network tools holding connections, remote
root sessions, and legacy cleartext services actually running.

These are heuristics for triage, not proof; findings map to detection and
least-functionality controls and are meant to be reviewed.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from . import Capability

MONITOR_CONTROLS = ["NIST:SI-4", "SOC2:CC7.2", "ISO27001:A.8.16"]
FUNCTION_CONTROLS = ["NIST:CM-7", "NIST:SC-7", "ISO27001:A.8.20"]
ACCESS_CONTROLS = ["NIST:AC-17", "NIST:AC-6", "ISO27001:A.8.5"]

# reverse-shell / live-off-the-land command signatures (checked against argv)
REVSHELL_PATTERNS = [
    (re.compile(r"/dev/tcp/\d", re.I), "bash /dev/tcp reverse shell"),
    (re.compile(r"\bnc\b[^\n]*\s-e\b", re.I), "netcat -e reverse shell"),
    (re.compile(r"\bncat\b[^\n]*--exec\b", re.I), "ncat --exec reverse shell"),
    (re.compile(r"\bsocat\b[^\n]*\bexec:", re.I), "socat exec reverse shell"),
    (re.compile(r"\b(?:ba)?sh\s+-i\b", re.I), "interactive shell spawn (sh -i)"),
    (re.compile(r"python[0-9.]*\b[^\n]*pty\.spawn", re.I), "python pty.spawn shell"),
    (re.compile(r"mkfifo\b[^\n]*\|[^\n]*\b(?:ba)?sh\b", re.I), "mkfifo named-pipe shell"),
    (re.compile(r"perl\b[^\n]*-e[^\n]*socket", re.I), "perl socket reverse shell"),
]

STAGING_DIRS = re.compile(r"(?:^|\s)(/tmp/|/dev/shm/|/var/tmp/|/run/shm/)\S+")
NET_TOOLS = {"nc", "ncat", "netcat", "socat"}

RISKY_SERVICES = {
    "telnet": Severity.HIGH,
    "rsh": Severity.HIGH, "rlogin": Severity.HIGH, "rexec": Severity.HIGH,
    "tftp": Severity.MEDIUM, "vsftpd": Severity.MEDIUM, "ftp": Severity.MEDIUM,
}

_UNIT_SUFFIX = re.compile(r"\.(service|socket|target|timer)$")


def check_processes(content: str) -> list[dict]:
    issues = []
    for line in content.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        pid, user, comm = parts[0], parts[1], parts[2]
        args = parts[3] if len(parts) > 3 else comm
        for pattern, label in REVSHELL_PATTERNS:
            if pattern.search(args):
                issues.append({
                    "rule": "proc-reverse-shell",
                    "title": f"Reverse-shell indicator in PID {pid} ({user}): {label}",
                    "severity": Severity.CRITICAL,
                    "controls": MONITOR_CONTROLS,
                    "remediation": (
                        "Isolate the host, capture the process tree and network state, "
                        "then kill the process and investigate initial access."
                    ),
                })
                break
        else:
            m = STAGING_DIRS.search(args)
            if m:
                issues.append({
                    "rule": "proc-staging-dir-exec",
                    "title": f"PID {pid} ({user}) executing from a world-writable path: {m.group(1)}",
                    "severity": Severity.HIGH,
                    "controls": MONITOR_CONTROLS,
                    "remediation": "Verify the binary; execution from /tmp or /dev/shm is a common malware pattern.",
                })
            elif comm in NET_TOOLS:
                issues.append({
                    "rule": "proc-network-tool",
                    "title": f"Interactive network tool '{comm}' running (PID {pid}, {user})",
                    "severity": Severity.MEDIUM,
                    "controls": FUNCTION_CONTROLS,
                    "remediation": "Confirm this is expected; nc/ncat/socat are frequently used for tunneling and shells.",
                })
    return issues


def check_connections(content: str) -> list[dict]:
    issues = []
    for line in content.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        if not m:
            continue
        proc = m.group(1)
        if proc in NET_TOOLS or proc in ("bash", "sh", "python", "python3", "perl", "ruby"):
            issues.append({
                "rule": "conn-suspicious-process",
                "title": f"Network connection held by '{proc}' (shells/net-tools should not normally hold sockets)",
                "severity": Severity.HIGH,
                "controls": MONITOR_CONTROLS,
                "remediation": "Inspect the connection's remote endpoint and the owning process.",
            })
    return issues


def check_sessions(content: str) -> list[dict]:
    issues = []
    for line in content.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        user, tty = fields[0], fields[1]
        remote = bool(re.search(r"\(?\b\d{1,3}(?:\.\d{1,3}){3}\b", line))
        if user == "root" and (tty.startswith("pts/") or remote):
            issues.append({
                "rule": "session-remote-root",
                "title": f"Interactive/remote root session active on {tty}",
                "severity": Severity.MEDIUM,
                "controls": ACCESS_CONTROLS,
                "remediation": "Prefer non-root logins with sudo; verify this session is authorized.",
            })
    return issues


def check_services(content: str) -> list[dict]:
    issues = []
    for line in content.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        unit = line.split()[0] if line.split() else ""
        base = _UNIT_SUFFIX.sub("", unit.lower())
        for name, severity in RISKY_SERVICES.items():
            if base == name:
                issues.append({
                    "rule": f"service-risky-{name}",
                    "title": f"Legacy/cleartext service running: {unit}",
                    "severity": severity,
                    "controls": FUNCTION_CONTROLS,
                    "remediation": f"Disable {unit} and replace with an encrypted equivalent (e.g. SSH/SFTP).",
                })
                break
    return issues


_DISPATCH = {
    "processes": check_processes,
    "connections": check_connections,
    "sessions": check_sessions,
    "services": check_services,
}


class RuntimeInspectionCapability(Capability):
    name = "runtime"
    description = "Inspect a live system for indicators of compromise (reverse shells, staging dirs, exposed sessions/services)"

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            if ev.kind != "runtime-fact":
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
                        f"Runtime rule '{issue['rule']}' matched on "
                        f"{ev.metadata.get('host', 'host')} (snapshot: {fact}, "
                        f"observed {ev.collected_at})."
                    ),
                    severity=issue["severity"],
                    evidence_ids=[ev.id],
                    location=ev.source,
                    controls=list(issue["controls"]),
                    confidence="medium",
                    remediation=issue["remediation"],
                    metadata={"rule": issue["rule"], "host": ev.metadata.get("host")},
                ))
        return findings
