"""Real response executors (behind the dry-run interface).

These are the connectors that actually change another system's state — block
an IP at a firewall, disable a user in IAM, isolate a host via an EDR/SOAR
webhook. They implement the same :class:`ResponseExecutor` protocol as
:class:`DryRunExecutor`, so the SOC and the access model treat them
identically: **an executor is only ever invoked after the engine has cleared
the action through the Graduated-Autonomy access model** (auto/notify tiers,
or an approved human decision). Swapping the executor never widens what is
allowed — only how an allowed action is carried out.

Safety:
  * Action parameters (ip/user/host) are derived from log-parsed entities, so
    they are treated as untrusted: each is validated against a strict pattern
    before use, and commands run with **no shell** and a fixed argv template.
  * Command templates and webhook URLs come from policy (operator-controlled),
    not from the model or the incident.
  * An executor that has no route for an action falls back to dry-run rather
    than guessing.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from ..access import Sensitivity
from .response import ACTIONS, DryRunExecutor

Runner = Callable[[list], "tuple[int, str]"]
Fetcher = Callable[[str, bytes], str]

_SAFE_USER = re.compile(r"^[A-Za-z0-9._@\-]{1,64}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9._\-]{1,253}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9./_\-]{1,4096}$")


def _valid(action: str, params: dict) -> tuple[bool, str]:
    """Validate model/log-derived params before they reach a real system."""
    if action == "block_ip":
        ip = params.get("ip", "")
        try:
            ipaddress.ip_address(ip)
            return True, ""
        except ValueError:
            return False, f"invalid IP: {ip!r}"
    if action == "disable_user":
        u = params.get("user", "")
        return (bool(_SAFE_USER.match(u)), "" if _SAFE_USER.match(u) else f"invalid user: {u!r}")
    if action == "isolate_host":
        h = params.get("host", "")
        return (bool(_SAFE_HOST.match(h)), "" if _SAFE_HOST.match(h) else f"invalid host: {h!r}")
    if action == "quarantine_file":
        p = params.get("path", "")
        return (bool(_SAFE_PATH.match(p)), "" if _SAFE_PATH.match(p) else f"invalid path: {p!r}")
    return True, ""


def _default_runner(argv: list) -> tuple[int, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, f"{type(e).__name__}: {e}"
    return r.returncode, (r.stdout + r.stderr).strip()


def _default_fetcher(url: str, data: bytes) -> str:
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (allowlist enforced by caller)
        return resp.read().decode("utf-8", errors="replace")


@dataclass
class CommandExecutor:
    """Runs an operator-defined, no-shell command per action.

    ``templates`` maps an action to an argv list with ``{ip}`` / ``{user}`` /
    ``{host}`` / ``{path}`` placeholders, e.g.::

        {"block_ip": ["nft", "add", "element", "inet", "f", "blocked", "{ip}"]}

    Unmapped actions fall back to dry-run.
    """

    templates: dict[str, list]
    runner: Runner = _default_runner
    fallback: object = field(default_factory=DryRunExecutor)
    name: str = "command"

    def execute(self, action: str, params: dict) -> dict:
        template = self.templates.get(action)
        if template is None:
            return self.fallback.execute(action, params)
        ok, why = _valid(action, params)
        if not ok:
            return {"action": action, "status": "rejected", "detail": why, "params": params}
        argv = [str(tok).format(**params) for tok in template]
        code, output = self.runner(argv)
        _, sensitivity = ACTIONS.get(action, (action, Sensitivity.RESPOND))
        return {
            "action": action,
            "status": "executed" if code == 0 else "failed",
            "sensitivity": sensitivity.value,
            "return_code": code,
            "detail": output[:2000],
            "params": params,
            "executor": self.name,
        }


@dataclass
class WebhookExecutor:
    """POSTs the action to an external orchestrator / SOAR endpoint."""

    url: str
    fetcher: Fetcher = _default_fetcher
    domain_check: Callable[[str], bool] | None = None
    fallback: object = field(default_factory=DryRunExecutor)
    name: str = "webhook"

    def execute(self, action: str, params: dict) -> dict:
        from urllib.parse import urlparse
        ok, why = _valid(action, params)
        if not ok:
            return {"action": action, "status": "rejected", "detail": why, "params": params}
        host = urlparse(self.url).hostname or ""
        if self.domain_check and not self.domain_check(host):
            return {"action": action, "status": "blocked",
                    "detail": f"domain '{host}' not in policy allowlist", "params": params}
        body = json.dumps({"action": action, "params": params}).encode("utf-8")
        try:
            resp = self.fetcher(self.url, body)
            return {"action": action, "status": "executed", "detail": resp[:2000],
                    "params": params, "executor": self.name}
        except Exception as e:  # noqa: BLE001
            return {"action": action, "status": "failed",
                    "detail": f"{type(e).__name__}: {e}", "params": params, "executor": self.name}


def build_executor(policy: dict, runner: Runner | None = None,
                   fetcher: Fetcher | None = None,
                   domain_check: Callable[[str], bool] | None = None):
    """Construct a ResponseExecutor from the ``response.executor`` policy block.

    Returns ``None`` (engine then uses the dry-run default) unless the policy
    explicitly configures a real executor — real actions are never on by
    accident.
    """
    cfg = ((policy or {}).get("response") or {}).get("executor") or {}
    etype = cfg.get("type")
    if etype == "command":
        return CommandExecutor(templates=cfg.get("templates") or {},
                               runner=runner or _default_runner)
    if etype == "webhook" and cfg.get("url"):
        return WebhookExecutor(url=cfg["url"], fetcher=fetcher or _default_fetcher,
                               domain_check=domain_check)
    if etype in (None, "dryrun", "dry-run"):
        return None
    return None
