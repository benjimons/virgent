"""Security-organization model: functions, teams, roles, RACI, escalation."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Role:
    id: str
    title: str
    responsibilities: list[str]
    access_role: str          # maps to the access-model role chain
    reports_to: str = ""


@dataclass
class Team:
    id: str
    name: str
    mission: str
    functions: list[str]      # CSF function codes it owns
    roles: list[str]          # role ids on the team


@dataclass
class Function:
    code: str                 # CSF function code
    name: str
    outcome: str
    owning_team: str
    capabilities: list[str]   # Virgent capabilities that serve this function


# -- roles --------------------------------------------------------------------

ROLES: dict[str, Role] = {
    "ciso": Role("ciso", "Chief Information Security Officer",
                 ["Owns the security program and risk posture",
                  "Accountable to executive leadership and the board",
                  "Approves risk acceptance and destructive response actions"],
                 access_role="admin"),
    "sec-manager": Role("sec-manager", "Security Manager",
                        ["Runs day-to-day security operations",
                         "Approves response actions and prioritization"],
                        access_role="responder", reports_to="ciso"),
    "grc-analyst": Role("grc-analyst", "GRC / Compliance Analyst",
                        ["Maps controls to frameworks and gathers audit evidence",
                         "Tracks control coverage and exceptions"],
                        access_role="analyst", reports_to="sec-manager"),
    "sec-engineer": Role("sec-engineer", "Security Engineer / AppSec",
                         ["Reviews code, dependencies, and IaC",
                          "Builds and tunes detections and guardrails"],
                         access_role="analyst", reports_to="sec-manager"),
    "soc-analyst": Role("soc-analyst", "SOC Analyst (Tier 1/2)",
                        ["Monitors alerts and triages incidents",
                         "Escalates confirmed incidents to IR"],
                        access_role="analyst", reports_to="sec-manager"),
    "incident-responder": Role("incident-responder", "Incident Responder (Tier 3)",
                               ["Leads containment, eradication, and recovery",
                                "Executes response playbooks under approval"],
                               access_role="responder", reports_to="sec-manager"),
    "threat-hunter": Role("threat-hunter", "Threat Hunter",
                          ["Proactively hunts for compromise in live systems",
                           "Develops new detections from findings"],
                          access_role="analyst", reports_to="sec-manager"),
    "vuln-manager": Role("vuln-manager", "Vulnerability Manager",
                         ["Owns the vulnerability register and SLAs",
                          "Drives remediation and risk acceptance decisions"],
                         access_role="responder", reports_to="sec-manager"),
    "red-teamer": Role("red-teamer", "Red Teamer / Pen Tester",
                       ["Runs authorized, scoped penetration tests",
                        "Verifies exposure and validates findings"],
                       access_role="analyst", reports_to="sec-manager"),
    "agent": Role("agent", "Autonomous Security Agent (Virgent)",
                  ["Continuously observes, analyzes, and proposes actions",
                   "Acts autonomously within the Observe/Enrich tiers",
                   "Escalates consequential actions to humans"],
                  access_role="agent", reports_to="sec-manager"),
}

# -- teams --------------------------------------------------------------------

TEAMS: dict[str, Team] = {
    "grc": Team("grc", "Governance, Risk & Compliance",
                "Set policy, manage risk, and prove compliance",
                functions=["GV"], roles=["ciso", "grc-analyst"]),
    "seceng": Team("seceng", "Security Engineering / AppSec",
                   "Identify and reduce risk in code, dependencies, and infrastructure",
                   functions=["ID", "PR"], roles=["sec-engineer", "vuln-manager", "red-teamer"]),
    "soc": Team("soc", "Security Operations Center",
                "Detect and respond to threats in live systems",
                functions=["DE", "RS"], roles=["soc-analyst", "threat-hunter", "agent"]),
    "ir": Team("ir", "Incident Response",
               "Contain, eradicate, and recover from incidents",
               functions=["RS", "RC"], roles=["incident-responder", "sec-manager"]),
}

# -- functions (NIST CSF 2.0) -------------------------------------------------

FUNCTIONS: dict[str, Function] = {
    "GV": Function("GV", "Govern",
                   "Establish, communicate, and monitor the cybersecurity risk strategy",
                   owning_team="grc", capabilities=["dependencies"]),
    "ID": Function("ID", "Identify",
                   "Understand assets, risks, and vulnerabilities",
                   owning_team="seceng",
                   capabilities=["secrets", "dependencies", "iac", "host", "llm-review", "pentest"]),
    "PR": Function("PR", "Protect",
                   "Implement safeguards to ensure delivery of services",
                   owning_team="seceng",
                   capabilities=["secrets", "iac", "host", "fim"]),
    "DE": Function("DE", "Detect",
                   "Identify the occurrence of cybersecurity events",
                   owning_team="soc", capabilities=["runtime", "fim", "soc"]),
    "RS": Function("RS", "Respond",
                   "Take action regarding a detected incident",
                   owning_team="soc", capabilities=["runtime", "soc"]),
    "RC": Function("RC", "Recover",
                   "Restore capabilities impaired by an incident",
                   owning_team="ir", capabilities=["soc"]),
}

# -- RACI (function -> responsibility assignment) -----------------------------
# R=Responsible, A=Accountable, C=Consulted, I=Informed
RACI: dict[str, dict[str, str]] = {
    "GV": {"ciso": "A", "grc-analyst": "R", "sec-manager": "C", "agent": "I"},
    "ID": {"sec-manager": "A", "sec-engineer": "R", "vuln-manager": "R",
           "red-teamer": "C", "agent": "R", "grc-analyst": "I"},
    "PR": {"sec-manager": "A", "sec-engineer": "R", "agent": "R", "ciso": "I"},
    "DE": {"sec-manager": "A", "soc-analyst": "R", "threat-hunter": "R",
           "agent": "R", "incident-responder": "C"},
    "RS": {"sec-manager": "A", "incident-responder": "R", "soc-analyst": "R",
           "agent": "C", "ciso": "I"},
    "RC": {"sec-manager": "A", "incident-responder": "R", "ciso": "I", "agent": "I"},
}

# -- escalation chain ---------------------------------------------------------
# ascending authority; mirrors the access-model role chain
ESCALATION = ["agent", "soc-analyst", "incident-responder", "sec-manager", "ciso"]


def escalation_chain(from_role: str) -> list[str]:
    """The chain of humans to escalate to, starting above ``from_role``."""
    if from_role not in ESCALATION:
        return ESCALATION[1:]
    idx = ESCALATION.index(from_role)
    return ESCALATION[idx + 1:]


SECURITY_ORG = {
    "functions": FUNCTIONS,
    "teams": TEAMS,
    "roles": ROLES,
    "raci": RACI,
    "escalation": ESCALATION,
}
