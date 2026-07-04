"""Autonomous asset discovery.

The agent finds its own work instead of waiting to be pointed at a target —
but only within a **declared scope**, and every discovered asset is
provenance-stamped and audited like any other input. This is what makes the
"actively seeks out information" behaviour safe: discovery is bounded by
policy, not by trust.

Two modes:

* **Local discovery** (``discover.local``, OBSERVE / autonomous) enumerates
  what is worth ingesting *on the machine the agent runs on*: git repositories
  under configured roots, log files, and the host/runtime state itself. This
  is read-only and always safe, so it runs without approval.

* **Network discovery** (``discover.network``, ACTIVE / gated) sweeps declared
  CIDRs for live services to build an asset inventory. Because it reaches out
  to other machines it is scope-limited (only ranges in ``discover`` →
  ``network_scope``) and requires approval, exactly like pen testing. The
  sweep is injectable so it is testable and can be swapped for an existing
  asset source (CMDB, cloud API) without changing the pipeline.

A discoverer returns :class:`Target` objects; the engine routes each to the
right ingestor. Discovery decides *candidates*; policy decides what is
allowed; ingestion records provenance. No layer is skipped.
"""
from __future__ import annotations

import fnmatch
import glob as globmod
import ipaddress
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# High-level, injectable finders so discovery is testable offline.
RepoFinder = Callable[[list], list]       # (roots) -> [repo dir, ...]
LogFinder = Callable[[list], list]        # (globs) -> [log path, ...]
Sweeper = Callable[[str, list], list]     # (cidr, ports) -> [(host, port), ...]

DEFAULT_ROOTS = ["/workspace", "/srv", "/opt", "/home"]
DEFAULT_LOG_GLOBS = ["/var/log/*.log", "/var/log/*/*.log"]
DEFAULT_SWEEP_PORTS = [22, 80, 443, 3306, 5432, 6379, 9200, 27017, 2375]
_EXCLUDE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".virgent"}


@dataclass
class Target:
    """A candidate the agent discovered and can act on."""

    kind: str            # repo | log | host | runtime | service
    locator: str         # path, "localhost", or "10.0.0.5:5432"
    ingestor: str        # which ingestor consumes it ("" = inventory only)
    sensitivity: str     # observe | active
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "locator": self.locator,
                "ingestor": self.ingestor, "sensitivity": self.sensitivity,
                "metadata": self.metadata}


# -- default finders ----------------------------------------------------------

def _default_repo_finder(roots: list, max_depth: int = 4) -> list:
    found: list[str] = []
    for root in roots:
        rp = Path(root)
        if not rp.is_dir():
            continue
        base_depth = len(rp.parts)
        stack = [rp]
        while stack:
            d = stack.pop()
            if len(d.parts) - base_depth > max_depth:
                continue
            try:
                if (d / ".git").exists():
                    found.append(str(d))
                    continue  # don't descend into a repo
                for child in d.iterdir():
                    if child.is_dir() and child.name not in _EXCLUDE_DIRS:
                        stack.append(child)
            except OSError:
                continue
    return sorted(set(found))


def _default_log_finder(globs: list) -> list:
    found: list[str] = []
    for pattern in globs:
        try:
            found.extend(p for p in globmod.glob(pattern) if Path(p).is_file())
        except OSError:
            continue
    return sorted(set(found))


def _default_sweeper(cidr: str, ports: list) -> list:
    """Non-destructive TCP-connect sweep. Only ever called for in-scope CIDRs."""
    live: list[tuple[str, int]] = []
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return live
    hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
    for host in hosts[:1024]:  # bound the sweep
        for port in ports:
            try:
                with socket.create_connection((str(host), port), timeout=0.3):
                    live.append((str(host), port))
            except OSError:
                continue
    return live


def _in_scope(host: str, scope: list) -> bool:
    for entry in scope or []:
        if entry.startswith(".") and host.endswith(entry):
            return True
        if host == entry:
            return True
        try:
            if "/" in entry and ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
        if fnmatch.fnmatch(host, entry):
            return True
    return False


class AssetDiscoverer:
    def __init__(
        self,
        roots: list | None = None,
        log_globs: list | None = None,
        network_scope: list | None = None,
        sweep_ports: list | None = None,
        include_host: bool = True,
        repo_finder: RepoFinder | None = None,
        log_finder: LogFinder | None = None,
        sweeper: Sweeper | None = None,
    ):
        self.roots = roots if roots is not None else list(DEFAULT_ROOTS)
        self.log_globs = log_globs if log_globs is not None else list(DEFAULT_LOG_GLOBS)
        self.network_scope = network_scope or []
        self.sweep_ports = sweep_ports or list(DEFAULT_SWEEP_PORTS)
        self.include_host = include_host
        self.repo_finder = repo_finder or _default_repo_finder
        self.log_finder = log_finder or _default_log_finder
        self.sweeper = sweeper or _default_sweeper

    @classmethod
    def from_policy(cls, policy: dict, **overrides) -> "AssetDiscoverer":
        cfg = (policy or {}).get("discover") or {}
        return cls(
            roots=cfg.get("roots"),
            log_globs=cfg.get("log_globs"),
            network_scope=cfg.get("network_scope"),
            sweep_ports=cfg.get("sweep_ports"),
            include_host=cfg.get("include_host", True),
            **overrides,
        )

    def discover_local(self) -> list[Target]:
        targets: list[Target] = []
        if self.include_host:
            targets.append(Target("host", "localhost", "host", "observe"))
            targets.append(Target("runtime", "localhost", "runtime", "observe"))
        for repo in self.repo_finder(self.roots):
            targets.append(Target("repo", repo, "file", "observe", {"git": True}))
        for log in self.log_finder(self.log_globs):
            targets.append(Target("log", log, "tail", "observe"))
        return targets

    def discover_network(self) -> list[Target]:
        """Scope-limited service inventory. Only sweeps declared CIDRs."""
        targets: list[Target] = []
        for cidr in self.network_scope:
            for host, port in self.sweeper(cidr, self.sweep_ports):
                if not _in_scope(host, self.network_scope):
                    continue  # defence in depth: never record out-of-scope
                targets.append(Target(
                    "service", f"{host}:{port}", "", "active",
                    {"host": host, "port": port, "cidr": cidr}))
        return targets
