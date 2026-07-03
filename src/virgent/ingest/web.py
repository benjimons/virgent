"""Active web collection: advisory feeds and allowlisted HTTP sources.

All network access is domain-allowlisted by policy and requires approval
under the default policy (action ``collect.web``). The HTTP transport is an
injectable callable so tests and air-gapped environments never touch the
network.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Callable, Iterator
from urllib.parse import urlparse

from . import Ingestor, RawItem

# fetcher(url, data: bytes | None) -> str
Fetcher = Callable[[str, bytes | None], str]


def _default_fetcher(url: str, data: bytes | None = None) -> str:
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "virgent-security-agent/0.1",
            "Content-Type": "application/json",
        },
        method="POST" if data else "GET",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (allowlist enforced by caller)
        return resp.read().decode("utf-8", errors="replace")


class DomainNotAllowed(PermissionError):
    pass


class WebCollector(Ingestor):
    name = "web"

    def __init__(self, allowed_domains: list[str] | None = None, fetcher: Fetcher | None = None):
        self.allowed_domains = [d.lower() for d in (allowed_domains or [])]
        self.fetcher = fetcher or _default_fetcher

    def _check_domain(self, url: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        for entry in self.allowed_domains:
            if host == entry or host.endswith("." + entry):
                return
        raise DomainNotAllowed(f"domain '{host}' is not in the policy allowlist")

    def fetch(self, url: str, data: bytes | None = None) -> str:
        self._check_domain(url)
        return self.fetcher(url, data)

    def collect(self, target: str) -> Iterator[RawItem]:
        body = self.fetch(target)
        yield RawItem(source=target, kind="web", content=body, metadata={"url": target})


OSV_API = "https://api.osv.dev/v1/query"


def query_osv(
    package: str,
    ecosystem: str,
    version: str | None,
    collector: WebCollector,
) -> list[dict]:
    """Query the OSV vulnerability database for a package.

    Returns the list of vulnerability records (possibly empty). Network
    access goes through the collector, so the allowlist applies.
    """
    payload: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    body = collector.fetch(OSV_API, json.dumps(payload).encode("utf-8"))
    data = json.loads(body or "{}")
    return data.get("vulns", []) or []
