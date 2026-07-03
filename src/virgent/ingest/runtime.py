"""Runtime (live-system) ingestion.

Captures the *dynamic* state of a running system — processes, active network
connections, logged-in sessions, and running services — as point-in-time
snapshots. Each snapshot is provenance-stamped, so a monitor can compare
snapshots over time and every observation is attributable to a moment and a
collection method.

Same safety model as :mod:`virgent.ingest.host`: a fixed command allowlist,
no shell, injectable ``runner`` for tests/air-gapped audits, and best-effort
collectors that degrade gracefully when a command is unavailable or needs
privileges the agent lacks.
"""
from __future__ import annotations

import socket
import subprocess
from typing import Callable, Iterator

from . import Ingestor, RawItem

Runner = Callable[[list], "str | None"]

# Command families tried per fact, in order of preference (first that yields
# output wins). Every tuple here is read-only.
RUNTIME_COMMANDS: dict[str, list[list[str]]] = {
    "processes": [
        ["ps", "-eo", "pid,user,comm,args", "--no-headers"],
        ["ps", "-eo", "pid,user,comm,args"],
    ],
    "connections": [
        ["ss", "-tunp"],
        ["ss", "-tun"],
        ["netstat", "-tunp"],
    ],
    "sessions": [
        ["who"],
    ],
    "services": [
        ["systemctl", "list-units", "--type=service", "--state=running",
         "--no-legend", "--no-pager"],
    ],
}

ALLOWED_COMMANDS: set[tuple[str, ...]] = {
    tuple(argv) for variants in RUNTIME_COMMANDS.values() for argv in variants
}


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


class RuntimeIngestor(Ingestor):
    name = "runtime"

    def __init__(self, runner: Runner | None = None, hostname: str | None = None):
        self.runner = runner or _default_runner
        self.hostname = hostname or socket.gethostname()

    def _collect_fact(self, fact: str) -> str | None:
        for argv in RUNTIME_COMMANDS[fact]:
            out = self.runner(argv)
            if out and out.strip():
                return f"# {' '.join(argv)}\n{out.strip()}"
        return None

    def collect(self, target: str = "localhost") -> Iterator[RawItem]:
        for fact in RUNTIME_COMMANDS:
            try:
                content = self._collect_fact(fact)
            except Exception:
                content = None
            if not content:
                continue
            yield RawItem(
                source=f"runtime:{self.hostname}:{fact}",
                kind="runtime-fact",
                content=content,
                metadata={"fact": fact, "host": self.hostname},
            )
