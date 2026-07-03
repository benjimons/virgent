"""Host inspection ingestion.

Collects *read-only* facts about the machine the agent runs on — OS release,
kernel/sysctl parameters, local accounts, SSH server configuration, listening
sockets, host firewall state, and permissions on sensitive files — and turns
each into provenance-stamped evidence for the host-inspection capability.

Safety properties:
  * Commands are restricted to a fixed allowlist (``ALLOWED_COMMANDS``);
    anything else is refused. No shell is used.
  * File reads and command execution go through injectable ``reader`` /
    ``runner`` / ``stat_fn`` callables, so tests and air-gapped audits never
    touch the real host, and a deployer can further sandbox them.
  * Every collector is best-effort: a missing file or a command that needs
    privileges the agent doesn't have is recorded as absent, never fatal.
"""
from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path
from typing import Callable, Iterator

from . import Ingestor, RawItem

# Injectable primitives -------------------------------------------------------

Reader = Callable[[str], "str | None"]
Runner = Callable[[list], "str | None"]
StatFn = Callable[[str], "dict | None"]

# Exact argv tuples the default runner is permitted to execute. Read-only,
# no shell, no arguments derived from untrusted input.
ALLOWED_COMMANDS: set[tuple[str, ...]] = {
    ("ss", "-tulnH"),
    ("ss", "-tuln"),
    ("netstat", "-tuln"),
    ("ufw", "status"),
    ("uname", "-a"),
}

SENSITIVE_FILES = [
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/group",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/crontab",
]

# Selected /proc/sys entries (read directly instead of invoking sysctl).
SYSCTL_KEYS = [
    "kernel/randomize_va_space",
    "fs/suid_dumpable",
    "net/ipv4/ip_forward",
    "net/ipv4/tcp_syncookies",
    "net/ipv4/conf/all/accept_redirects",
    "net/ipv4/conf/all/send_redirects",
    "net/ipv4/conf/all/accept_source_route",
]


def _default_reader(path: str) -> str | None:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def _default_runner(argv: list) -> str | None:
    if tuple(argv) not in ALLOWED_COMMANDS:
        return None
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 and not result.stdout:
        return None
    return result.stdout


def _default_stat(path: str) -> dict | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    owner = str(st.st_uid)
    try:
        import pwd
        owner = pwd.getpwuid(st.st_uid).pw_name
    except (ImportError, KeyError):
        pass
    return {
        "mode": oct(st.st_mode & 0o777)[2:].zfill(3),
        "owner": owner,
        "uid": st.st_uid,
    }


class HostIngestor(Ingestor):
    name = "host"

    def __init__(
        self,
        reader: Reader | None = None,
        runner: Runner | None = None,
        stat_fn: StatFn | None = None,
        hostname: str | None = None,
    ):
        self.reader = reader or _default_reader
        self.runner = runner or _default_runner
        self.stat_fn = stat_fn or _default_stat
        self.hostname = hostname or socket.gethostname()

    # -- individual collectors (each returns content or None) --------------

    def _os_release(self) -> str | None:
        return self.reader("/etc/os-release")

    def _sysctl(self) -> str | None:
        lines = []
        for key in SYSCTL_KEYS:
            value = self.reader(f"/proc/sys/{key}")
            if value is not None:
                lines.append(f"{key.replace('/', '.')} = {value.strip()}")
        return "\n".join(lines) if lines else None

    def _users(self) -> str | None:
        passwd = self.reader("/etc/passwd")
        if passwd is None:
            return None
        parts = [f"# /etc/passwd\n{passwd.strip()}"]
        shadow = self.reader("/etc/shadow")
        if shadow is not None:
            parts.append(f"# /etc/shadow\n{shadow.strip()}")
        return "\n".join(parts)

    def _sshd_config(self) -> str | None:
        return self.reader("/etc/ssh/sshd_config")

    def _listening(self) -> str | None:
        for argv in (["ss", "-tulnH"], ["ss", "-tuln"], ["netstat", "-tuln"]):
            out = self.runner(argv)
            if out:
                return f"# {' '.join(argv)}\n{out.strip()}"
        return None

    def _firewall(self) -> str | None:
        out = self.runner(["ufw", "status"])
        return f"# ufw status\n{out.strip()}" if out else None

    def _file_perms(self) -> str | None:
        lines = []
        for path in SENSITIVE_FILES:
            info = self.stat_fn(path)
            if info is not None:
                lines.append(f"{path} mode={info['mode']} owner={info['owner']}")
        return "\n".join(lines) if lines else None

    def _collectors(self) -> list[tuple[str, Callable[[], "str | None"]]]:
        return [
            ("os-release", self._os_release),
            ("sysctl", self._sysctl),
            ("users", self._users),
            ("sshd_config", self._sshd_config),
            ("listening", self._listening),
            ("firewall", self._firewall),
            ("file-perms", self._file_perms),
        ]

    def collect(self, target: str = "localhost") -> Iterator[RawItem]:
        for fact, collector in self._collectors():
            try:
                content = collector()
            except Exception:  # a collector must never crash the run
                content = None
            if not content:
                continue
            yield RawItem(
                source=f"host:{self.hostname}:{fact}",
                kind="host-fact",
                content=content,
                metadata={"fact": fact, "host": self.hostname},
            )
