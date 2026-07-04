"""Access reviews (recertification campaigns).

Turns enumerated identity accounts into review items a control owner must
certify — the core of an IGA recertification cycle. Each privileged or unusual
grant becomes a line item with a recommendation; the reviewer approves or
revokes, and the decision is auditable through the engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import sha256_hex, utcnow

DORMANT_DAYS = 90


@dataclass
class AccessReview:
    id: str
    account: str
    provider: str
    item: str                 # what is being certified
    recommendation: str       # keep | revoke | investigate
    reason: str
    risk: str = "medium"
    created_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def generate_access_reviews(accounts: list) -> list[AccessReview]:
    reviews: list[AccessReview] = []

    def add(acc, item, rec, reason, risk):
        rid = "rev-" + sha256_hex(f"{acc.provider}:{acc.id}:{item}")[:12]
        reviews.append(AccessReview(
            id=rid, account=acc.email or acc.id, provider=acc.provider,
            item=item, recommendation=rec, reason=reason, risk=risk))

    for acc in accounts:
        if acc.status in ("suspended", "deprovisioned"):
            add(acc, "disabled account still present", "revoke",
                f"account status is '{acc.status}' — should be removed", "medium")
            continue
        if acc.admin:
            add(acc, "privileged/admin role", "investigate",
                "admin access should be recertified every cycle", "high")
        if acc.last_login_days is not None and acc.last_login_days > DORMANT_DAYS:
            add(acc, f"dormant account ({acc.last_login_days}d idle)", "revoke",
                f"no login in {acc.last_login_days} days (> {DORMANT_DAYS})",
                "high" if acc.admin else "medium")
        elif acc.last_login_days is None and not acc.service_account:
            add(acc, "account never logged in", "revoke",
                "provisioned but never used", "medium")
        if acc.service_account and acc.admin:
            add(acc, "privileged service account", "investigate",
                "service accounts with admin rights are high-value targets", "high")
    return reviews
