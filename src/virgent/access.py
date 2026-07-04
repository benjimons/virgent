"""Access & autonomy model — Graduated Autonomy with Escalation (GAE).

The problem: a "total" security agent must be able to reach into many systems
and, in a SOC, sometimes *act* — but a human must be able to intervene at any
decision point, and high-stakes actions must be escalated to the right person.

The model has three moving parts:

1. **Sensitivity tier** — every action the agent can take is classified:
       OBSERVE < ENRICH < ACTIVE < RESPOND < DESTRUCTIVE
   (read a log → enrich with threat intel → probe a port → block an IP →
   isolate a host). Higher tiers carry more consequence.

2. **Autonomy level per tier** — configured in policy (`access.autonomy`):
       AUTO      proceed without a human
       NOTIFY    proceed, but tell a human it happened
       CONFIRM   a human at the required role must approve first
       ESCALATE  raise a decision to a human (with full context) and wait;
                 unresolved or high-risk decisions climb the role chain
       DENY      never allowed
   Defaults: OBSERVE/ENRICH→AUTO, ACTIVE/RESPOND→CONFIRM, DESTRUCTIVE→ESCALATE.

3. **Role chain** — an ordered privilege ladder (`access.roles`, default
   agent < analyst < responder < admin). Each tier needs a minimum role to
   authorize it; risk can bump the requirement up the chain. A responder who
   tries to resolve a decision above their role escalates it further instead
   of resolving it.

Every request and resolution is persisted and audited, so the full decision
trail — who was asked, who decided, when, and why — is reconstructable.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from .models import canonical_json, sha256_hex, utcnow


class EscalationRequired(Exception):
    """Raised when an action needs a human decision before it can proceed.

    Carries the :class:`DecisionRequest` so callers can surface it to a human
    (queue, UI, chat) and resume once resolved.
    """

    def __init__(self, request: "DecisionRequest"):
        self.request = request
        super().__init__(
            f"human decision required for '{request.action}' "
            f"(sensitivity={request.sensitivity}, needs role >= {request.required_role}); "
            f"decision id: {request.id}")


class Sensitivity(str, Enum):
    OBSERVE = "observe"        # read-only collection
    ENRICH = "enrich"          # derive/correlate/lookup (may use allowlisted net)
    ACTIVE = "active"          # active but non-destructive probing
    RESPOND = "respond"        # changes another system's state, reversible
    DESTRUCTIVE = "destructive"  # hard-to-reverse containment

    @property
    def rank(self) -> int:
        return ["observe", "enrich", "active", "respond", "destructive"].index(self.value)


class Autonomy(str, Enum):
    AUTO = "auto"
    NOTIFY = "notify"
    CONFIRM = "confirm"
    ESCALATE = "escalate"
    DENY = "deny"


DEFAULT_ROLES = ["agent", "analyst", "responder", "admin"]

DEFAULT_AUTONOMY = {
    Sensitivity.OBSERVE: Autonomy.AUTO,
    Sensitivity.ENRICH: Autonomy.AUTO,
    Sensitivity.ACTIVE: Autonomy.CONFIRM,
    Sensitivity.RESPOND: Autonomy.CONFIRM,
    Sensitivity.DESTRUCTIVE: Autonomy.ESCALATE,
}

DEFAULT_MIN_ROLE = {
    Sensitivity.OBSERVE: "agent",
    Sensitivity.ENRICH: "agent",
    Sensitivity.ACTIVE: "analyst",
    Sensitivity.RESPOND: "responder",
    Sensitivity.DESTRUCTIVE: "admin",
}

# risk score (0-100) at/above which the required role is bumped one rung
RISK_ESCALATION_THRESHOLD = 80

# Declarative sensitivity tier for every action the agent can take. Longest
# matching prefix wins. This is the single place that classifies the
# consequence of an action, so the autonomy model applies uniformly — humans
# can be inserted at any decision point by tuning the autonomy for its tier.
ACTION_SENSITIVITY: dict[str, Sensitivity] = {
    "agent.init": Sensitivity.OBSERVE,
    "ingest.": Sensitivity.OBSERVE,
    "collect.host": Sensitivity.OBSERVE,
    "collect.runtime": Sensitivity.OBSERVE,
    "collect.tail": Sensitivity.OBSERVE,
    "collect.web": Sensitivity.ENRICH,
    "discover.local": Sensitivity.OBSERVE,
    "discover.ingest": Sensitivity.OBSERVE,
    "discover.network": Sensitivity.ACTIVE,
    "discover.cloud": Sensitivity.ENRICH,
    "notify.": Sensitivity.ENRICH,
    "scan.": Sensitivity.OBSERVE,
    "report.": Sensitivity.OBSERVE,
    "audit.": Sensitivity.OBSERVE,
    "fim.baseline": Sensitivity.OBSERVE,
    "fim.check": Sensitivity.OBSERVE,
    "monitor.": Sensitivity.OBSERVE,
    "vulns.": Sensitivity.OBSERVE,
    "soc.detect": Sensitivity.OBSERVE,
    "soc.plan": Sensitivity.OBSERVE,
    "soc.list": Sensitivity.OBSERVE,
    "soc.triage": Sensitivity.ENRICH,
    "llm.": Sensitivity.ENRICH,
    "pentest.": Sensitivity.ACTIVE,
    "remediate.": Sensitivity.RESPOND,
    "respond.isolate_host": Sensitivity.DESTRUCTIVE,
    "respond.quarantine_file": Sensitivity.RESPOND,
    "respond.": Sensitivity.RESPOND,
}


def sensitivity_for(action: str) -> Sensitivity:
    """Classify an action by its most specific matching prefix."""
    best = ""
    for prefix in ACTION_SENSITIVITY:
        if action == prefix or action.startswith(prefix):
            if len(prefix) > len(best):
                best = prefix
    return ACTION_SENSITIVITY.get(best, Sensitivity.RESPOND)


class AutonomyPolicy:
    def __init__(self, roles: list[str] | None = None,
                 autonomy: dict | None = None, min_role: dict | None = None,
                 risk_threshold: int = RISK_ESCALATION_THRESHOLD):
        self.roles = roles or list(DEFAULT_ROLES)
        self.autonomy = {**DEFAULT_AUTONOMY, **(autonomy or {})}
        self.min_role = {**DEFAULT_MIN_ROLE, **(min_role or {})}
        self.risk_threshold = risk_threshold

    @classmethod
    def from_policy(cls, policy: dict) -> "AutonomyPolicy":
        access = (policy or {}).get("access") or {}
        roles = access.get("roles") or list(DEFAULT_ROLES)
        autonomy = {}
        for k, v in (access.get("autonomy") or {}).items():
            try:
                autonomy[Sensitivity(k)] = Autonomy(v)
            except ValueError:
                continue
        min_role = {}
        for k, v in (access.get("min_role") or {}).items():
            try:
                min_role[Sensitivity(k)] = v
            except ValueError:
                continue
        return cls(roles=roles, autonomy=autonomy, min_role=min_role,
                   risk_threshold=access.get("risk_threshold", RISK_ESCALATION_THRESHOLD))

    def role_rank(self, role: str) -> int:
        return self.roles.index(role) if role in self.roles else -1

    def evaluate(self, sensitivity: Sensitivity, context: dict | None = None) -> tuple[Autonomy, str]:
        """Return (autonomy level, required role) for a sensitivity + context."""
        context = context or {}
        level = self.autonomy.get(sensitivity, Autonomy.CONFIRM)
        role = self.min_role.get(sensitivity, "responder")
        risk = context.get("risk", 0) or 0
        # risk only escalates consequential (ACTIVE+) actions; observing and
        # enriching stay autonomous no matter how hot the incident is
        if (sensitivity.rank >= Sensitivity.ACTIVE.rank
                and risk >= self.risk_threshold
                and self.role_rank(role) < len(self.roles) - 1):
            role = self.roles[self.role_rank(role) + 1]
            if level in (Autonomy.AUTO, Autonomy.NOTIFY):
                level = Autonomy.CONFIRM
        return level, role


@dataclass
class DecisionRequest:
    id: str
    action: str
    sensitivity: str
    autonomy: str
    required_role: str
    context: dict = field(default_factory=dict)
    status: str = "pending"          # pending | approved | denied
    created_at: str = field(default_factory=utcnow)
    resolved_by: str = ""
    resolved_role: str = ""
    resolution_note: str = ""
    resolved_at: str = ""
    escalations: list = field(default_factory=list)
    consumed: bool = False

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @staticmethod
    def from_dict(d: dict) -> "DecisionRequest":
        return DecisionRequest(**d)


class DecisionBroker:
    """Persistent human-decision queue with role-based escalation."""

    def __init__(self, path: str | Path, autonomy_policy: AutonomyPolicy,
                 audit: Callable[..., None] | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.autonomy_policy = autonomy_policy
        self._audit = audit
        self._requests: dict[str, DecisionRequest] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            for did, d in json.loads(self.path.read_text(encoding="utf-8")).items():
                self._requests[did] = DecisionRequest.from_dict(d)

    def _save(self) -> None:
        self.path.write_text(json.dumps(
            {k: v.to_dict() for k, v in self._requests.items()},
            indent=2, sort_keys=True, default=str), encoding="utf-8")

    def _record(self, event: str, **params) -> None:
        if self._audit:
            self._audit(event, params=params)

    def open(self, action: str, sensitivity: Sensitivity, context: dict,
             required_role: str, autonomy: Autonomy) -> DecisionRequest:
        did = "dec-" + sha256_hex(canonical_json(
            [action, context, utcnow()]))[:12]
        req = DecisionRequest(
            id=did, action=action, sensitivity=sensitivity.value,
            autonomy=autonomy.value, required_role=required_role, context=context,
        )
        self._requests[did] = req
        self._save()
        self._record("decision.requested", id=did, action=action,
                     sensitivity=sensitivity.value, required_role=required_role)
        return req

    def pending(self) -> list[DecisionRequest]:
        return [r for r in self._requests.values() if r.status == "pending"]

    def get(self, did: str) -> DecisionRequest:
        return self._requests[did]

    def approved_for(self, action: str, incident_id: str | None = None) -> DecisionRequest | None:
        """Find an approved, unconsumed decision authorizing ``action``.

        This is what lets a human's approval in one process authorize the
        action in a later one — the persisted decision *is* the grant.
        """
        for r in self._requests.values():
            if r.status != "approved" or r.consumed or r.action != action:
                continue
            if incident_id is not None and r.context.get("incident") not in (None, incident_id):
                continue
            return r
        return None

    def mark_consumed(self, did: str) -> None:
        if did in self._requests:
            self._requests[did].consumed = True
            self._save()
            self._record("decision.consumed", id=did, action=self._requests[did].action)

    def resolve(self, did: str, decision: str, resolver: str, role: str,
                note: str = "") -> DecisionRequest:
        """Approve or deny a pending decision.

        If ``role`` is below the request's required role, the decision is not
        resolved — it is escalated (required role raised) and remains pending.
        """
        if did not in self._requests:
            raise KeyError(f"unknown decision: {did}")
        req = self._requests[did]
        if req.status != "pending":
            raise ValueError(f"decision {did} already {req.status}")
        if decision not in ("approve", "deny"):
            raise ValueError("decision must be 'approve' or 'deny'")

        ap = self.autonomy_policy
        if decision == "approve" and ap.role_rank(role) < ap.role_rank(req.required_role):
            req.escalations.append({
                "at": utcnow(), "by": resolver, "role": role,
                "reason": f"role '{role}' below required '{req.required_role}'",
            })
            self._save()
            self._record("decision.escalated", id=did, by=resolver, role=role,
                         required_role=req.required_role)
            return req

        req.status = "approved" if decision == "approve" else "denied"
        req.resolved_by = resolver
        req.resolved_role = role
        req.resolution_note = note
        req.resolved_at = utcnow()
        self._save()
        self._record("decision.resolved", id=did, decision=req.status,
                     by=resolver, role=role, note=note)
        return req
