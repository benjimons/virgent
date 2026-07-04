"""Ticketing / workflow integrations.

Turns findings and incidents into tickets in the systems a security program
actually runs on — Jira, ServiceNow, or a Slack channel — so remediation has
an owner and an SLA outside Virgent. Connectors are injectable (a fake fetcher
in tests, a local file connector offline), and network targets are
domain-allowlisted by policy. Ticket references are recorded in the audit log.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

Fetcher = Callable[[str, bytes, dict], str]   # (url, body, headers) -> response


def _default_fetcher(url: str, body: bytes, headers: dict) -> str:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (allowlist enforced upstream)
        return resp.read().decode("utf-8", errors="replace")


class Ticketer(Protocol):
    name: str
    def create(self, kind: str, item: dict) -> dict: ...


def _summarize(kind: str, item: dict) -> tuple[str, str]:
    title = f"[virgent:{kind}] {item.get('title', 'security finding')}"
    body = (f"Severity: {item.get('severity', '?')}\n"
            f"Source: {item.get('location') or item.get('id', '')}\n"
            f"Controls: {', '.join(item.get('controls', []))}\n\n"
            f"{item.get('description', '')}\n\n"
            f"Remediation: {item.get('remediation', '')}")
    return title, body


@dataclass
class FileTicketer:
    path: str
    name: str = "file"

    def create(self, kind: str, item: dict) -> dict:
        title, body = _summarize(kind, item)
        from .models import sha256_hex, utcnow
        tid = "TCK-" + sha256_hex(title + body)[:10].upper()
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"id": tid, "kind": kind, "title": title,
                                "body": body, "created_at": utcnow()}) + "\n")
        return {"ticket_id": tid, "status": "created", "connector": self.name}


@dataclass
class JiraTicketer:
    url: str          # https://<org>.atlassian.net
    project: str
    email: str = ""
    token: str = ""
    fetcher: Fetcher = _default_fetcher
    domain_check: Callable[[str], bool] | None = None
    name: str = "jira"

    def create(self, kind: str, item: dict) -> dict:
        from urllib.parse import urlparse
        import base64
        host = urlparse(self.url).hostname or ""
        if self.domain_check and not self.domain_check(host):
            return {"status": "blocked", "detail": f"domain '{host}' not allowlisted"}
        title, body = _summarize(kind, item)
        payload = json.dumps({"fields": {
            "project": {"key": self.project}, "summary": title[:250],
            "description": body, "issuetype": {"name": "Bug"}}}).encode("utf-8")
        auth = base64.b64encode(f"{self.email}:{self.token}".encode()).decode()
        headers = {"Content-Type": "application/json", "Authorization": f"Basic {auth}"}
        try:
            resp = json.loads(self.fetcher(f"{self.url}/rest/api/2/issue", payload, headers) or "{}")
            return {"ticket_id": resp.get("key", "?"), "status": "created", "connector": self.name}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "detail": f"{type(e).__name__}: {e}", "connector": self.name}


@dataclass
class SlackTicketer:
    url: str          # incoming webhook
    fetcher: Fetcher = _default_fetcher
    domain_check: Callable[[str], bool] | None = None
    name: str = "slack"

    def create(self, kind: str, item: dict) -> dict:
        from urllib.parse import urlparse
        host = urlparse(self.url).hostname or ""
        if self.domain_check and not self.domain_check(host):
            return {"status": "blocked", "detail": f"domain '{host}' not allowlisted"}
        title, body = _summarize(kind, item)
        payload = json.dumps({"text": f"*{title}*\n{body}"}).encode("utf-8")
        try:
            self.fetcher(self.url, payload, {"Content-Type": "application/json"})
            return {"ticket_id": "slack", "status": "created", "connector": self.name}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "detail": f"{type(e).__name__}: {e}", "connector": self.name}


def build_ticketer(policy: dict, workdir: str | Path = ".", fetcher: Fetcher | None = None,
                   domain_check: Callable[[str], bool] | None = None) -> "Ticketer | None":
    cfg = (policy or {}).get("ticketing") or {}
    if not cfg.get("enabled"):
        return None
    fetcher = fetcher or _default_fetcher
    kind = cfg.get("connector", "file")
    if kind == "file":
        path = cfg.get("path", "tickets.jsonl")
        if not Path(path).is_absolute():
            path = str(Path(workdir) / path)
        return FileTicketer(path=path)
    if kind == "jira" and cfg.get("url"):
        return JiraTicketer(url=cfg["url"], project=cfg.get("project", "SEC"),
                            email=cfg.get("email", ""), token=cfg.get("token", ""),
                            fetcher=fetcher, domain_check=domain_check)
    if kind == "slack" and cfg.get("url"):
        return SlackTicketer(url=cfg["url"], fetcher=fetcher, domain_check=domain_check)
    return None
