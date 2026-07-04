"""Identity providers: normalized, read-only account enumeration."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class IdentityAccount:
    provider: str                  # okta | entra | google
    id: str
    email: str = ""
    status: str = "active"         # active | suspended | deprovisioned
    mfa_enabled: bool = False
    admin: bool = False            # holds a privileged/admin role
    last_login_days: int | None = None   # days since last login (None = never)
    credential_age_days: int | None = None  # oldest active credential age
    groups: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    service_account: bool = False

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class IdentityProvider(Protocol):
    name: str
    def enumerate(self) -> list[IdentityAccount]: ...


@dataclass
class MockIdentityProvider:
    accounts: list = field(default_factory=list)
    name: str = "mock"

    def enumerate(self) -> list[IdentityAccount]:
        return list(self.accounts)


def _age_days(ts) -> int | None:
    if ts is None:
        return None
    try:
        from datetime import datetime, timezone
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - ts).days
    except (ValueError, TypeError):
        return None


class OktaProvider:
    """Read-only Okta enumeration via the Okta API.

    Uses an SSWS API token (read-only admin) or OAuth; only GET/list calls are
    made. The HTTP transport is injectable so this is testable offline.
    """

    name = "okta"

    def __init__(self, org_url: str = "", token: str = "", fetcher=None):
        self.org_url = org_url.rstrip("/")
        self.token = token
        self.fetcher = fetcher or self._default_fetcher

    def _default_fetcher(self, path: str) -> list:  # pragma: no cover - needs network
        import json
        import urllib.request
        req = urllib.request.Request(
            f"{self.org_url}{path}",
            headers={"Authorization": f"SSWS {self.token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    def enumerate(self) -> list[IdentityAccount]:
        accounts: list[IdentityAccount] = []
        users = self.fetcher("/api/v1/users?limit=200") or []
        for u in users:
            profile = u.get("profile", {})
            factors = self.fetcher(f"/api/v1/users/{u['id']}/factors") or []
            roles = self.fetcher(f"/api/v1/users/{u['id']}/roles") or []
            admin = any("ADMIN" in (r.get("type", "")) for r in roles)
            accounts.append(IdentityAccount(
                provider="okta", id=u.get("id", "?"),
                email=profile.get("email", ""),
                status="active" if u.get("status") == "ACTIVE" else u.get("status", "").lower(),
                mfa_enabled=len(factors) > 0,
                admin=admin,
                last_login_days=_age_days(u.get("lastLogin")),
                credential_age_days=_age_days(u.get("passwordChanged")),
                roles=[r.get("type") for r in roles],
                service_account=profile.get("userType", "") == "Service",
            ))
        return accounts


def build_identity_provider(policy: dict, fetcher=None):
    """Construct an identity provider from the ``identity`` policy block.

    Returns None unless explicitly enabled — reaching into an IdP is never on
    by accident.
    """
    cfg = (policy or {}).get("identity") or {}
    if not cfg.get("enabled"):
        return None
    provider = cfg.get("provider", "okta")
    if provider == "okta":
        return OktaProvider(org_url=cfg.get("org_url", ""), token=cfg.get("token", ""),
                            fetcher=fetcher)
    return None
