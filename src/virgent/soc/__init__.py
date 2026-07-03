"""Agentic Security Operations Center (SOC).

A full detect-triage-respond pipeline built on the same audited, provenance-
first substrate as the rest of Virgent:

  log evidence ──► normalize ──► detect ──► correlate ──► triage ──► respond
   (provenance)     events       alerts     incidents     (LLM)     (gated)

- Detection is rule-based (signatures + stateful brute-force/spray/compromise
  logic) and produces alerts mapped to monitoring/incident controls.
- Alerts sharing an entity (IP, user, host) correlate into incidents with
  stable IDs, so status and triage survive re-runs.
- Triage optionally uses the policy-gated, redacted, audited reasoning layer.
- Response playbooks are DRY-RUN by default and every real action is gated
  behind a ``respond.*`` approval and executed via an injectable executor.
"""
from .casebook import Casebook
from .correlation import correlate
from .detection import DetectionEngine
from .events import LogEvent, parse_evidence, parse_line
from .models import Alert, Incident
from .response import DryRunExecutor, ResponseExecutor, recommend_actions
from .soc import SOC

__all__ = [
    "SOC",
    "DetectionEngine",
    "Casebook",
    "correlate",
    "recommend_actions",
    "ResponseExecutor",
    "DryRunExecutor",
    "LogEvent",
    "Alert",
    "Incident",
    "parse_line",
    "parse_evidence",
]
