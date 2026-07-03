"""Auditor-ready report generation.

Reports are self-verifying: they carry the audit-chain attestation (record
count + head hash + verification status), evidence hashes, and control
coverage, so an auditor holding the workdir can independently re-verify
every claim.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Iterable

from ..models import Finding, Severity, utcnow
from .frameworks import CONTROLS, coverage

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def build_report_data(
    findings: list[Finding],
    provenance_records: Iterable[dict],
    attestation: dict,
    run_info: dict | None = None,
) -> dict:
    prov = list(provenance_records)
    by_severity = Counter(f.severity.value for f in findings)
    return {
        "report": {
            "generated_at": utcnow(),
            "tool": "virgent",
            "run": run_info or {},
        },
        "summary": {
            "findings_total": len(findings),
            "by_severity": {s.value: by_severity.get(s.value, 0) for s in SEVERITY_ORDER},
            "evidence_items": len(prov),
        },
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: f.severity.rank)],
        "control_coverage": coverage(findings),
        "evidence": prov,
        "audit_attestation": attestation,
    }


def render_markdown(data: dict) -> str:
    lines: list[str] = []
    add = lines.append
    add("# Virgent Security Assessment Report")
    add("")
    add(f"- Generated: {data['report']['generated_at']}")
    for key, value in (data["report"].get("run") or {}).items():
        add(f"- {key}: {value}")
    add("")
    add("## Executive Summary")
    add("")
    summary = data["summary"]
    add(f"Total findings: **{summary['findings_total']}** across "
        f"**{summary['evidence_items']}** evidence items.")
    add("")
    add("| Severity | Count |")
    add("|---|---|")
    for sev, count in summary["by_severity"].items():
        add(f"| {sev} | {count} |")
    add("")

    add("## Findings")
    add("")
    if not data["findings"]:
        add("No findings.")
    for f in data["findings"]:
        add(f"### [{f['severity'].upper()}] {f['title']}")
        add("")
        add(f"- ID: `{f['id']}` (fingerprint `{f['fingerprint']}`)")
        add(f"- Capability: {f['capability']} | Confidence: {f['confidence']}")
        if f.get("location"):
            add(f"- Location: `{f['location']}`")
        add(f"- Evidence: {', '.join('`' + e + '`' for e in f['evidence_ids']) or 'n/a'}")
        controls = [f"`{c}` ({CONTROLS.get(c, {}).get('title', '?')})" for c in f["controls"]]
        if controls:
            add(f"- Controls: {'; '.join(controls)}")
        add("")
        add(f["description"])
        if f.get("remediation"):
            add("")
            add(f"**Remediation:** {f['remediation']}")
        add("")

    add("## Compliance Control Coverage")
    add("")
    cov = data["control_coverage"]
    if not cov:
        add("No control mappings produced.")
    for fw in sorted(cov):
        add(f"### {fw}")
        add("")
        add("| Control | Title | Findings |")
        add("|---|---|---|")
        for cid in sorted(cov[fw]):
            title = CONTROLS.get(cid, {}).get("title", "?")
            add(f"| `{cid}` | {title} | {', '.join(cov[fw][cid])} |")
        add("")

    add("## Evidence & Provenance")
    add("")
    add("| Evidence ID | Source | Kind | SHA-256 | Collected | Method |")
    add("|---|---|---|---|---|---|")
    for rec in data["evidence"]:
        add(f"| `{rec['evidence_id']}` | {rec['source']} | {rec['kind']} "
            f"| `{rec['sha256'][:16]}…` | {rec['collected_at']} | {rec['method']} |")
    add("")

    add("## Audit Chain Attestation")
    add("")
    att = data["audit_attestation"]
    add(f"- Records: {att['records']}")
    add(f"- Head hash: `{att['head_hash']}`")
    add(f"- Chain verified: **{att['chain_verified']}**")
    add(f"- HMAC-signed: {att['signed']}")
    add(f"- Verified at: {att['verified_at']}")
    add("")
    add("_Every finding above is traceable to hash-verified evidence via the "
        "provenance store, and every agent action is recorded in the "
        "tamper-evident audit log attested here._")
    return "\n".join(lines)


def generate_report(
    findings: list[Finding],
    provenance_records: Iterable[dict],
    attestation: dict,
    run_info: dict | None = None,
    fmt: str = "markdown",
) -> str:
    data = build_report_data(findings, provenance_records, attestation, run_info)
    if fmt == "json":
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
    if fmt == "markdown":
        return render_markdown(data)
    raise ValueError(f"unknown report format: {fmt}")
