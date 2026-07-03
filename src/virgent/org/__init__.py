"""A security organization, modeled inside the agent.

Virgent doesn't just run tools — it embodies the structure of a security
program: the NIST CSF functions, the teams and roles that own them, a RACI
matrix, a library of runbooks/playbooks, escalation chains, and a
program-posture view that ties the agent's live findings back to that
structure. This lets one agent operate as a whole security org, while keeping
humans in the accountable seats via the access model.
"""
from .model import (
    FUNCTIONS,
    RACI,
    ROLES,
    SECURITY_ORG,
    TEAMS,
    Function,
    Role,
    Team,
    escalation_chain,
)
from .posture import program_posture
from .runbooks import RUNBOOKS, select_runbooks

__all__ = [
    "SECURITY_ORG",
    "FUNCTIONS",
    "TEAMS",
    "ROLES",
    "RACI",
    "Function",
    "Team",
    "Role",
    "escalation_chain",
    "RUNBOOKS",
    "select_runbooks",
    "program_posture",
]
