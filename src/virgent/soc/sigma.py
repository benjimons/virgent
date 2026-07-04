"""Sigma rule import.

Compiles a practical subset of the Sigma detection format (the community
standard for portable detections) into single-event rules the detection engine
can run. Supported: a ``detection`` block with one or more selections of
``field`` / ``field|contains`` / ``field|startswith`` / ``field|endswith``
matchers (string or list = OR), and a ``condition`` combining selections with
``and`` / ``or`` / ``not``. Fields resolve against LogEvent attributes first,
then its ``fields`` dict, then the raw message.

This lets teams bring their existing detection-as-code library to Virgent
without rewriting rules, while every produced alert still flows through the
same correlation, triage, and audit pipeline.
"""
from __future__ import annotations

import re
from typing import Callable

import yaml

from ..models import Severity
from .events import LogEvent
from .models import Alert, SOC_CONTROLS, alert_id

_LEVEL = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
          "medium": Severity.MEDIUM, "low": Severity.LOW, "informational": Severity.INFO}


def _field_value(ev: LogEvent, field: str) -> str:
    if hasattr(ev, field) and isinstance(getattr(ev, field), str):
        return getattr(ev, field)
    if field in ev.fields:
        return str(ev.fields[field])
    return ev.message


def _match_one(ev: LogEvent, field_spec: str, expected) -> bool:
    field, _, mod = field_spec.partition("|")
    actual = _field_value(ev, field)
    values = expected if isinstance(expected, list) else [expected]
    for v in values:
        v = str(v)
        if mod == "contains" and v.lower() in actual.lower():
            return True
        if mod == "startswith" and actual.lower().startswith(v.lower()):
            return True
        if mod == "endswith" and actual.lower().endswith(v.lower()):
            return True
        if mod in ("", "equals") and actual == v:
            return True
    return False


def _selection_matches(ev: LogEvent, selection) -> bool:
    # a selection is a mapping of field->expected; all must match (AND)
    if isinstance(selection, list):   # list of maps = OR
        return any(_selection_matches(ev, s) for s in selection)
    return all(_match_one(ev, f, exp) for f, exp in selection.items())


def _eval_condition(condition: str, sel_results: dict) -> bool:
    # supports: "sel", "sel1 and sel2", "sel1 or sel2", "not sel", "all of them"
    cond = condition.strip().lower()
    if cond in ("all of them", "all of selection*"):
        return all(sel_results.values())
    if cond in ("1 of them", "any of them", "1 of selection*"):
        return any(sel_results.values())
    tokens = cond.replace("(", " ( ").replace(")", " ) ").split()
    expr = []
    for t in tokens:
        if t in ("and", "or", "not", "(", ")"):
            expr.append({"and": "and", "or": "or", "not": "not"}.get(t, t))
        else:
            expr.append(str(bool(sel_results.get(t, False))))
    try:
        return bool(eval(" ".join(expr), {"__builtins__": {}}, {}))  # noqa: S307 - tokens are whitelisted
    except Exception:  # noqa: BLE001
        return False


def compile_sigma(rule: dict) -> Callable[[LogEvent], "Alert | None"]:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    title = rule.get("title", "sigma rule")
    rule_name = "sigma-" + re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    severity = _LEVEL.get(str(rule.get("level", "medium")).lower(), Severity.MEDIUM)

    def _rule(ev: LogEvent) -> "Alert | None":
        sel_results = {name: _selection_matches(ev, sel) for name, sel in selections.items()}
        if not _eval_condition(condition or "all of them", sel_results):
            return None
        a = Alert(id="", rule=rule_name, title=f"{title} ({ev.src_ip or ev.host or 'event'})",
                  severity=severity, entities=ev.entities(),
                  description=(rule.get("description", "") or ev.message)[:300],
                  event_evidence_ids=[ev.evidence_id] if ev.evidence_id else [],
                  controls=list(SOC_CONTROLS))
        a.id = alert_id(a.rule, a.entities)
        return a

    return _rule


def load_sigma_rules(text: str) -> list:
    """Compile one or more Sigma YAML documents into single-event rules."""
    rules = []
    for doc in yaml.safe_load_all(text):
        if isinstance(doc, dict) and doc.get("detection"):
            rules.append(compile_sigma(doc))
    return rules
