"""Response playbooks and actions.

Response actions are the agent's hands. They are **dry-run by default** and
every real action is gated (the engine enforces a ``respond.<action>``
approval) and executed through an injectable :class:`ResponseExecutor`, so a
deployment decides exactly how — or whether — an action touches production.

Each action declares a sensitivity tier consumed by the access model
(``virgent.access``) to decide the required level of human oversight.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..access import Sensitivity
from .models import Incident

# action -> (description, sensitivity)
ACTIONS: dict[str, tuple[str, Sensitivity]] = {
    "notify": ("Notify responders / open a ticket", Sensitivity.ENRICH),
    "review": ("Flag for human review", Sensitivity.OBSERVE),
    "block_ip": ("Block a source IP at the firewall", Sensitivity.RESPOND),
    "disable_user": ("Disable a user account", Sensitivity.RESPOND),
    "quarantine_file": ("Quarantine a file", Sensitivity.RESPOND),
    "isolate_host": ("Network-isolate a host", Sensitivity.DESTRUCTIVE),
}

# which rules recommend which actions
_RULE_PLAYBOOK: dict[str, list[str]] = {
    "ssh-brute-force": ["block_ip", "notify"],
    "password-spray": ["block_ip", "notify"],
    "successful-login-after-bruteforce": ["block_ip", "disable_user", "isolate_host", "notify"],
    "web-attack-sqli": ["block_ip", "notify"],
    "web-attack-path_traversal": ["block_ip", "notify"],
    "web-attack-xss": ["notify", "review"],
    "web-attack-cmd_injection": ["block_ip", "isolate_host", "notify"],
    "privileged-group-change": ["notify", "review"],
    "sudo-suspicious-command": ["notify", "review"],
}


def recommend_actions(incident: Incident) -> list[str]:
    """Ordered, de-duplicated response actions recommended for an incident."""
    seen: list[str] = []
    for rule in incident.rules:
        for action in _RULE_PLAYBOOK.get(rule, ["notify"]):
            if action not in seen:
                seen.append(action)
    return seen


class ResponseExecutor(Protocol):
    def execute(self, action: str, params: dict) -> dict: ...


@dataclass
class DryRunExecutor:
    """Default executor: records intent, changes nothing."""

    def execute(self, action: str, params: dict) -> dict:
        desc, sensitivity = ACTIONS.get(action, (action, Sensitivity.RESPOND))
        return {
            "action": action,
            "status": "dry-run",
            "sensitivity": sensitivity.value,
            "detail": f"[dry-run] would {desc.lower()} with {params}",
            "params": params,
        }


def action_params(action: str, incident: Incident) -> dict:
    """Derive action parameters from an incident's entities."""
    ent = incident.entities
    if action == "block_ip":
        return {"ip": ent.get("ip", [""])[0] if ent.get("ip") else ""}
    if action == "disable_user":
        return {"user": ent.get("user", [""])[0] if ent.get("user") else ""}
    if action == "isolate_host":
        return {"host": ent.get("host", [""])[0] if ent.get("host") else ""}
    return {"incident": incident.id}
