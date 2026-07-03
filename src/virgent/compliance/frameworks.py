"""Compliance framework API.

The control data itself lives in :mod:`virgent.compliance.catalog` (fully
populated for all supported frameworks). This module provides the lookup,
coverage, and CSF-crosswalk helpers used by capabilities and reports.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .catalog import CONTROLS  # noqa: F401 (re-exported)

# Which NIST CSF 2.0 functions each Virgent capability contributes evidence
# toward. Used for the program-posture view.
CAPABILITY_CSF = {
    "secrets": ["PR", "ID"],
    "dependencies": ["ID", "PR", "GV"],
    "iac": ["PR", "ID"],
    "host": ["PR", "ID"],
    "runtime": ["DE", "RS"],
    "llm-review": ["ID", "PR"],
    "pentest": ["ID"],
    "fim": ["DE", "PR"],
    "soc": ["DE", "RS", "RC"],
}

CSF_FUNCTIONS = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}


def register_control(control_id: str, framework: str, title: str) -> None:
    CONTROLS[control_id] = {"framework": framework, "title": title}


def frameworks() -> list[str]:
    return sorted({c["framework"] for c in CONTROLS.values()})


def framework_size(framework: str) -> int:
    return sum(1 for c in CONTROLS.values() if c["framework"] == framework)


def controls_for(ids: Iterable[str]) -> list[dict]:
    out = []
    for cid in ids:
        meta = CONTROLS.get(cid, {"framework": "unknown", "title": "(unregistered control)"})
        out.append({"id": cid, **meta})
    return out


def coverage(findings: Iterable) -> dict[str, dict[str, list[str]]]:
    """framework -> control id -> list of finding ids referencing it."""
    matrix: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        for cid in finding.controls:
            fw = CONTROLS.get(cid, {}).get("framework", "unknown")
            matrix[fw][cid].append(finding.id)
    return {fw: dict(controls) for fw, controls in matrix.items()}


def csf_posture(active_capabilities: Iterable[str]) -> dict[str, dict]:
    """Map active capabilities onto NIST CSF 2.0 functions for a posture view."""
    covered: dict[str, list[str]] = defaultdict(list)
    for cap in active_capabilities:
        for fn in CAPABILITY_CSF.get(cap, []):
            covered[fn].append(cap)
    return {
        code: {
            "function": name,
            "covered": bool(covered.get(code)),
            "capabilities": sorted(set(covered.get(code, []))),
        }
        for code, name in CSF_FUNCTIONS.items()
    }
