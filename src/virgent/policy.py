"""Policy engine.

Deny-by-default action policy loaded from YAML. Every action the agent
attempts is evaluated here before execution; the decision (and the rule
that produced it) is recorded in the audit log by the engine.

Effects, in order of precedence:  deny > require_approval > allow > default.

Approvals are explicit, per-run grants tied to an approver identity, so a
human-in-the-loop step is itself auditable.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Actor

DEFAULT_POLICY: dict = {
    "version": 1,
    "actions": {
        "default": "deny",
        "allow": [
            "agent.init",
            "ingest.*",
            "collect.host",
            "collect.runtime",
            "collect.tail",
            "discover.local",
            "scan.*",
            "report.*",
            "audit.*",
            "fim.*",
            "monitor.*",
            "vulns.*",
            "soc.*",
            "notify.*",
            "llm.complete",
        ],
        "require_approval": [
            "collect.web",
            "discover.network",
            "pentest.*",
            "remediate.*",
            "respond.*",
        ],
        "deny": [],
    },
    "network": {
        "allowed_domains": ["api.osv.dev"],
    },
    # Autonomous asset discovery. Local discovery is read-only and runs
    # unattended; network discovery is scope-limited (only these CIDRs/hosts
    # are ever swept) and requires approval.
    "discover": {
        "roots": ["/workspace", "/srv", "/opt", "/home"],
        "log_globs": ["/var/log/*.log", "/var/log/*/*.log"],
        "include_host": True,
        "network_scope": [],   # e.g. ["10.0.0.0/24"]; empty = no network sweep
    },
    "pentest": {
        # explicit target allowlist; empty means no host may be probed
        "scope": [],
    },
    "llm": {
        "enabled": True,
        "redact_before_send": True,
        "max_input_chars": 400_000,
    },
    # Graduated Autonomy with Escalation (see virgent.access). Every action is
    # classified into a sensitivity tier; this block decides how much human
    # oversight each tier gets and who may authorize it.
    "access": {
        "roles": ["agent", "analyst", "responder", "admin"],
        "autonomy": {
            "observe": "auto",          # read-only collection/analysis
            "enrich": "auto",           # derive/correlate/allowlisted lookups
            "active": "confirm",        # non-destructive active probing
            "respond": "confirm",       # reversible changes to other systems
            "destructive": "escalate",  # hard-to-reverse containment
        },
        "min_role": {
            "observe": "agent",
            "enrich": "agent",
            "active": "analyst",
            "respond": "responder",
            "destructive": "admin",
        },
        "risk_threshold": 80,
    },
    # Notifications: where "a human is needed / something happened" goes.
    # Webhook/Slack hosts must also be in network.allowed_domains.
    "notify": {
        "enabled": True,
        "min_severity": "high",
        "channels": [
            {"type": "file", "path": "notifications.jsonl"},
            # {"type": "stdout"},
            # {"type": "slack", "url": "https://hooks.slack.com/services/…"},
            # {"type": "webhook", "url": "https://soc.example.com/hook"},
        ],
    },
    # Response executor: how an *already-authorized* action touches production.
    # Default (omitted / "dryrun") changes nothing. A real executor never
    # widens what is allowed — the access model still gates every action.
    "response": {
        "executor": {
            "type": "dryrun",
            # "type": "command",
            # "templates": {"block_ip": ["nft", "add", "element", "inet", "fw", "blocked", "{ip}"]},
            # "type": "webhook",
            # "url": "https://soar.example.com/execute",
        },
    },
}


@dataclass
class PolicyDecision:
    action: str
    effect: str          # allow | deny | require_approval
    rule: str            # the matching pattern or "default"
    reason: str
    approved_by: str | None = None

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "effect": self.effect,
            "rule": self.rule,
            "reason": self.reason,
            "approved_by": self.approved_by,
        }


class PolicyViolation(PermissionError):
    def __init__(self, decision: PolicyDecision):
        self.decision = decision
        super().__init__(f"policy {decision.effect} for action '{decision.action}' (rule: {decision.rule})")


@dataclass
class _Approval:
    pattern: str
    approver: Actor


class PolicyEngine:
    def __init__(self, policy: dict | None = None):
        self.policy = policy or DEFAULT_POLICY
        self._approvals: list[_Approval] = []

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        with open(path, "r", encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    # -- approvals ----------------------------------------------------------

    def grant_approval(self, action_pattern: str, approver: Actor) -> _Approval:
        """Record a human approval for actions matching ``action_pattern``."""
        grant = _Approval(pattern=action_pattern, approver=approver)
        self._approvals.append(grant)
        return grant

    def _find_approval(self, action: str) -> _Approval | None:
        for grant in self._approvals:
            if fnmatch.fnmatch(action, grant.pattern):
                return grant
        return None

    # -- evaluation ---------------------------------------------------------

    @staticmethod
    def _match(action: str, patterns: list[str] | None) -> str | None:
        for pattern in patterns or []:
            if fnmatch.fnmatch(action, pattern):
                return pattern
        return None

    def evaluate(self, action: str) -> PolicyDecision:
        actions = self.policy.get("actions", {})
        rule = self._match(action, actions.get("deny"))
        if rule:
            return PolicyDecision(action, "deny", rule, "explicitly denied by policy")
        rule = self._match(action, actions.get("require_approval"))
        if rule:
            grant = self._find_approval(action)
            if grant:
                return PolicyDecision(
                    action, "allow", rule,
                    "approval requirement satisfied",
                    approved_by=grant.approver.id,
                )
            return PolicyDecision(action, "require_approval", rule, "human approval required")
        rule = self._match(action, actions.get("allow"))
        if rule:
            return PolicyDecision(action, "allow", rule, "allowed by policy")
        default = actions.get("default", "deny")
        return PolicyDecision(action, default, "default", f"no rule matched; default is {default}")

    def enforce(self, action: str) -> PolicyDecision:
        """Evaluate and raise :class:`PolicyViolation` unless allowed."""
        decision = self.evaluate(action)
        if not decision.allowed:
            raise PolicyViolation(decision)
        return decision

    # -- network ------------------------------------------------------------

    def domain_allowed(self, host: str) -> bool:
        allowed = (self.policy.get("network") or {}).get("allowed_domains") or []
        host = host.lower()
        for entry in allowed:
            entry = entry.lower()
            if host == entry or host.endswith("." + entry):
                return True
        return False

    def pentest_allowed(self, host: str) -> bool:
        """True if ``host`` is inside the authorized penetration-testing scope.

        Scope entries may be exact hostnames/IPs, ``.suffix`` domain matches,
        or CIDR ranges (e.g. ``10.0.0.0/24``).
        """
        import ipaddress
        scope = (self.policy.get("pentest") or {}).get("scope") or []
        host_l = host.lower()
        for entry in scope:
            entry = str(entry).strip().lower()
            if not entry:
                continue
            if entry.startswith(".") and host_l.endswith(entry):
                return True
            if host_l == entry:
                return True
            if "/" in entry:
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                        return True
                except ValueError:
                    continue
        return False

    # -- llm ----------------------------------------------------------------

    @property
    def llm(self) -> dict:
        merged = dict(DEFAULT_POLICY["llm"])
        merged.update(self.policy.get("llm") or {})
        return merged


def write_default_policy(path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(DEFAULT_POLICY, sort_keys=False), encoding="utf-8")
    return path
