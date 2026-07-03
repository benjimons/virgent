"""Program posture: tie live agent state back to the org and CSF functions."""
from __future__ import annotations

from ..compliance.frameworks import CONTROLS, csf_posture
from .model import FUNCTIONS, TEAMS


def program_posture(
    active_capabilities,
    findings,
    open_vulns_by_severity: dict,
    open_incidents: int,
    pending_decisions: int,
    audit_ok: bool,
) -> dict:
    """Assemble a security-program posture snapshot.

    Combines CSF function coverage (which capabilities are active), control
    coverage (which controls have evidence), and live operational state
    (open vulns, incidents, decisions, audit integrity) into one view with a
    coarse maturity score.
    """
    csf = csf_posture(active_capabilities)
    functions_covered = sum(1 for f in csf.values() if f["covered"])

    controls_with_evidence = set()
    for f in findings:
        controls_with_evidence.update(f.controls)
    frameworks_touched = {CONTROLS.get(c, {}).get("framework") for c in controls_with_evidence}
    frameworks_touched.discard(None)

    # coarse 0-100 maturity: CSF coverage, control evidence breadth, ops hygiene
    csf_score = functions_covered / len(FUNCTIONS) * 40
    breadth_score = min(len(frameworks_touched) / 8, 1.0) * 20
    integrity_score = 20 if audit_ok else 0
    backlog = (open_vulns_by_severity.get("critical", 0) * 3
               + open_vulns_by_severity.get("high", 0)) + open_incidents * 2
    hygiene_score = max(0, 20 - backlog)
    maturity = int(round(csf_score + breadth_score + integrity_score + hygiene_score))

    return {
        "csf_functions": csf,
        "csf_functions_covered": functions_covered,
        "org": {
            code: {
                "function": fn.name,
                "owning_team": TEAMS[fn.owning_team].name,
                "capabilities": fn.capabilities,
                "covered": csf.get(code, {}).get("covered", False),
            }
            for code, fn in FUNCTIONS.items()
        },
        "controls_with_evidence": len(controls_with_evidence),
        "frameworks_touched": sorted(frameworks_touched),
        "operations": {
            "open_vulnerabilities": open_vulns_by_severity,
            "open_incidents": open_incidents,
            "pending_decisions": pending_decisions,
            "audit_chain_verified": audit_ok,
        },
        "maturity_score": maturity,
        "maturity_band": (
            "leading" if maturity >= 85 else
            "managed" if maturity >= 65 else
            "developing" if maturity >= 40 else
            "initial"
        ),
    }
