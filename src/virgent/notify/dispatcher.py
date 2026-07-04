"""Notification dispatch.

Turns noteworthy events — a decision awaiting a human, an escalation, a new
high-severity incident — into messages on one or more channels (stdout, a
local JSONL file, a generic webhook, or Slack). This is the "tell a human it
happened / a human is needed" hook the access model and SOC rely on.

Design rules:
  * Dispatch is **best-effort and must never break the pipeline** — every
    channel error is caught and returned as a result, never raised. A failed
    Slack post must not stop a decision from being recorded.
  * Network channels (webhook, Slack) are **domain-allowlisted** by policy and
    go through an injectable fetcher, so tests and air-gapped runs never touch
    the network.
  * Message bodies are redacted by the caller (the engine) before dispatch, so
    secrets never leave on a notification.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from ..models import Severity, utcnow

# fetcher(url, data: bytes) -> str ; raises on transport failure
Fetcher = Callable[[str, bytes], str]
DomainCheck = Callable[[str], bool]


def _default_fetcher(url: str, data: bytes) -> str:
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "virgent/0.1"},
        method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (allowlist enforced by caller)
        return resp.read().decode("utf-8", errors="replace")


@dataclass
class Notification:
    kind: str                 # decision.requested | decision.escalated | incident | test
    title: str
    severity: Severity = Severity.INFO
    body: str = ""
    data: dict = field(default_factory=dict)
    ts: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "title": self.title, "severity": self.severity.value,
            "body": self.body, "data": self.data, "ts": self.ts,
        }


class Notifier(Protocol):
    name: str
    def send(self, n: Notification) -> dict: ...


@dataclass
class StdoutNotifier:
    name: str = "stdout"

    def send(self, n: Notification) -> dict:
        print(f"[virgent:notify] {n.severity.value.upper()} {n.kind}: {n.title}")
        return {"channel": self.name, "status": "sent"}


@dataclass
class FileNotifier:
    path: str
    name: str = "file"

    def send(self, n: Notification) -> dict:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(n.to_dict(), ensure_ascii=False) + "\n")
        return {"channel": self.name, "status": "sent", "path": str(p)}


@dataclass
class WebhookNotifier:
    url: str
    fetcher: Fetcher = _default_fetcher
    domain_check: DomainCheck | None = None
    name: str = "webhook"

    def send(self, n: Notification) -> dict:
        from urllib.parse import urlparse
        host = urlparse(self.url).hostname or ""
        if self.domain_check and not self.domain_check(host):
            return {"channel": self.name, "status": "blocked",
                    "detail": f"domain '{host}' not in policy allowlist"}
        payload = json.dumps(n.to_dict()).encode("utf-8")
        try:
            self.fetcher(self.url, payload)
            return {"channel": self.name, "status": "sent", "url": self.url}
        except Exception as e:  # noqa: BLE001 - notifications never raise
            return {"channel": self.name, "status": "error", "detail": f"{type(e).__name__}: {e}"}


@dataclass
class SlackNotifier:
    url: str
    fetcher: Fetcher = _default_fetcher
    domain_check: DomainCheck | None = None
    name: str = "slack"

    def send(self, n: Notification) -> dict:
        from urllib.parse import urlparse
        host = urlparse(self.url).hostname or ""
        if self.domain_check and not self.domain_check(host):
            return {"channel": self.name, "status": "blocked",
                    "detail": f"domain '{host}' not in policy allowlist"}
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(n.severity.value, "🔵")
        text = f"{emoji} *{n.title}*\n{n.body}" if n.body else f"{emoji} *{n.title}*"
        payload = json.dumps({"text": text}).encode("utf-8")
        try:
            self.fetcher(self.url, payload)
            return {"channel": self.name, "status": "sent"}
        except Exception as e:  # noqa: BLE001
            return {"channel": self.name, "status": "error", "detail": f"{type(e).__name__}: {e}"}


class NotificationDispatcher:
    def __init__(self, notifiers: list[Notifier] | None = None,
                 min_severity: Severity = Severity.HIGH, enabled: bool = True):
        self.notifiers = notifiers or []
        self.min_severity = min_severity
        self.enabled = enabled

    def dispatch(self, n: Notification) -> list[dict]:
        """Send to every channel that meets the severity threshold. Never raises."""
        if not self.enabled or not self.notifiers:
            return []
        # decision/escalation events always notify; incident/test gate on severity
        gate = n.kind in ("incident",) and n.severity.rank > self.min_severity.rank
        if gate:
            return []
        results = []
        for notifier in self.notifiers:
            try:
                results.append(notifier.send(n))
            except Exception as e:  # noqa: BLE001 - a broken channel can't break dispatch
                results.append({"channel": getattr(notifier, "name", "?"),
                                "status": "error", "detail": f"{type(e).__name__}: {e}"})
        return results


def build_dispatcher(policy: dict, fetcher: Fetcher | None = None,
                     domain_check: DomainCheck | None = None,
                     workdir: str | Path = ".") -> NotificationDispatcher:
    """Construct a dispatcher from the ``notify`` block of a policy."""
    cfg = (policy or {}).get("notify") or {}
    enabled = cfg.get("enabled", True)
    try:
        min_sev = Severity(cfg.get("min_severity", "high"))
    except ValueError:
        min_sev = Severity.HIGH
    fetcher = fetcher or _default_fetcher
    workdir = Path(workdir)
    notifiers: list[Notifier] = []
    for ch in cfg.get("channels") or []:
        ctype = ch.get("type")
        if ctype == "stdout":
            notifiers.append(StdoutNotifier())
        elif ctype == "file":
            path = ch.get("path", "notifications.jsonl")
            if not Path(path).is_absolute():
                path = str(workdir / path)
            notifiers.append(FileNotifier(path=path))
        elif ctype == "webhook" and ch.get("url"):
            notifiers.append(WebhookNotifier(url=ch["url"], fetcher=fetcher, domain_check=domain_check))
        elif ctype == "slack" and ch.get("url"):
            notifiers.append(SlackNotifier(url=ch["url"], fetcher=fetcher, domain_check=domain_check))
    return NotificationDispatcher(notifiers=notifiers, min_severity=min_sev, enabled=enabled)
