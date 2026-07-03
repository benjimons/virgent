"""The SecurityAgent orchestrator.

This is the single choke point through which everything flows, enforcing the
framework's invariants:

  1. Every action is policy-checked before execution, and the decision —
     including denials and approval grants — is written to the audit log.
  2. Every ingested item is registered with the provenance store before any
     capability may analyze it.
  3. Every LLM call is redacted first, and audited with prompt/response
     hashes and token usage (never raw content).
  4. Every finding is persisted with its evidence references so reports are
     reproducible from the workdir alone.
"""
from __future__ import annotations

import json
import platform
from pathlib import Path

from .audit import AuditLog
from .capabilities import (
    Capability,
    DependencyAuditCapability,
    IaCCapability,
    LLMReviewCapability,
    SecretScanCapability,
)
from .compliance.report import generate_report
from .ingest import FileIngestor, GitHistoryIngestor, Ingestor, WebCollector, query_osv
from .llm.provider import LLMResult, ReasoningProvider
from .models import Actor, Evidence, Finding
from .policy import PolicyEngine, PolicyViolation
from .provenance import ProvenanceStore
from .redaction import redact

__version__ = "0.1.0"

DEFAULT_ACTOR = Actor(id="virgent", type="agent")


class SecurityAgent:
    def __init__(
        self,
        workdir: str | Path = ".virgent",
        policy: PolicyEngine | str | Path | None = None,
        actor: Actor = DEFAULT_ACTOR,
        provider: ReasoningProvider | None = None,
    ):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.actor = actor
        if isinstance(policy, (str, Path)):
            policy = PolicyEngine.from_file(policy)
        self.policy = policy or PolicyEngine()
        self.audit = AuditLog(self.workdir / "audit.jsonl", actor=actor)
        self.provenance = ProvenanceStore(self.workdir / "provenance.jsonl")
        self.findings_path = self.workdir / "findings.jsonl"
        self.provider = provider

        self.ingestors: dict[str, Ingestor] = {
            "file": FileIngestor(),
            "git": GitHistoryIngestor(),
            "web": WebCollector(
                allowed_domains=(self.policy.policy.get("network") or {}).get("allowed_domains") or [],
            ),
        }
        self.capabilities: dict[str, Capability] = {}
        self.register_capability(SecretScanCapability())
        self.register_capability(DependencyAuditCapability())
        self.register_capability(IaCCapability())
        if self.provider is not None:
            self.register_capability(LLMReviewCapability(reason=self.reason))

        self.audit.record("agent.init", params={
            "version": __version__,
            "policy_version": self.policy.policy.get("version"),
            "platform": platform.platform(),
            "provider": getattr(self.provider, "name", None),
        })

    # -- policy enforcement (audited) ----------------------------------------

    def _enforce(self, action: str, params: dict | None = None):
        """Policy-check an action; audit the decision either way."""
        decision = self.policy.evaluate(action)
        if not decision.allowed:
            self.audit.record(
                action,
                params=redactable(params),
                outcome=f"denied:{decision.effect}",
                detail=decision.reason,
            )
            raise PolicyViolation(decision)
        return decision

    def approve(self, action_pattern: str, approver: Actor) -> None:
        """Record a human approval for a restricted action (audited)."""
        self.policy.grant_approval(action_pattern, approver)
        self.audit.record(
            "policy.approval",
            params={"pattern": action_pattern},
            detail=f"approved by {approver.id}",
            actor=approver,
        )

    # -- ingestion -----------------------------------------------------------

    def ingest(self, target: str, ingestor: str = "file") -> list[Evidence]:
        """Ingest a source; every item is provenance-stamped and audited."""
        action = f"ingest.{ingestor}" if ingestor != "web" else "collect.web"
        decision = self._enforce(action, {"target": target})
        reader = self.ingestors[ingestor]
        evidence: list[Evidence] = []
        for item in reader.collect(target):
            ev = self.provenance.register(
                source=item.source,
                method=action,
                kind=item.kind,
                content=item.content,
                collector=self.actor,
                metadata=item.metadata,
            )
            evidence.append(ev)
        self.audit.record(action, params={
            "target": target,
            "items": len(evidence),
            "evidence_ids": [e.id for e in evidence[:50]],
            "policy_rule": decision.rule,
            "approved_by": decision.approved_by,
        })
        return evidence

    # -- reasoning (redacted + audited LLM access) ----------------------------

    def reason(
        self,
        prompt: str,
        system: str | None = None,
        max_tokens: int = 16000,
        purpose: str = "",
    ) -> LLMResult:
        """The only path to the model: policy-gated, redacted, audited."""
        if self.provider is None:
            raise RuntimeError("no reasoning provider configured")
        llm_policy = self.policy.llm
        if not llm_policy.get("enabled", True):
            raise PolicyViolation(self.policy.evaluate("llm.complete"))
        decision = self._enforce("llm.complete", {"purpose": purpose})
        if llm_policy.get("redact_before_send", True):
            prompt, redactions = redact(prompt)
        else:
            redactions = {}
        max_chars = llm_policy.get("max_input_chars")
        if max_chars and len(prompt) > max_chars:
            raise ValueError(
                f"prompt exceeds policy max_input_chars ({len(prompt)} > {max_chars})"
            )
        try:
            result = self.provider.complete(prompt, system=system, max_tokens=max_tokens)
        except Exception as e:
            self.audit.record("llm.complete", params={
                "purpose": purpose,
                "provider": self.provider.name,
            }, outcome="error", detail=f"{type(e).__name__}: {e}")
            raise
        self.audit.record("llm.complete", params={
            "purpose": purpose,
            "provider": self.provider.name,
            "redactions": redactions,
            "policy_rule": decision.rule,
            **result.usage_dict(),
        })
        return result

    # -- capabilities / scanning ----------------------------------------------

    def register_capability(self, capability: Capability) -> None:
        self.capabilities[capability.name] = capability

    def enable_online_dependency_checks(self) -> None:
        """Wire the dependency capability to OSV over the (policy-gated) web collector."""
        self._enforce("collect.web", {"service": "osv"})
        collector: WebCollector = self.ingestors["web"]  # type: ignore[assignment]

        def _osv(package: str, ecosystem: str, version: str | None) -> list[dict]:
            vulns = query_osv(package, ecosystem, version, collector)
            self.audit.record("collect.web", params={
                "service": "osv", "package": package,
                "ecosystem": ecosystem, "version": version,
                "vulns_found": len(vulns),
            })
            return vulns

        self.register_capability(DependencyAuditCapability(osv_query=_osv))

    def load_evidence(self) -> list[Evidence]:
        return [self.provenance.load_evidence(eid) for eid in self.provenance.all_ids()]

    def scan(self, capabilities: list[str] | None = None) -> list[Finding]:
        """Run capabilities over all registered evidence; persist findings."""
        evidence = self.load_evidence()
        names = capabilities or list(self.capabilities)
        all_findings: list[Finding] = []
        for name in names:
            cap = self.capabilities[name]
            self._enforce(f"scan.{name}", {"evidence_items": len(evidence)})
            findings = cap.analyze(evidence)
            all_findings.extend(findings)
            self.audit.record(f"scan.{name}", params={
                "evidence_items": len(evidence),
                "findings": len(findings),
                "finding_ids": [f.id for f in findings[:100]],
            })
        self._persist_findings(all_findings)
        return all_findings

    def _persist_findings(self, findings: list[Finding]) -> None:
        with self.findings_path.open("a", encoding="utf-8") as f:
            for finding in findings:
                f.write(json.dumps(finding.to_dict(), ensure_ascii=False, default=str) + "\n")

    def load_findings(self, dedup: bool = True) -> list[Finding]:
        if not self.findings_path.exists():
            return []
        findings: list[Finding] = []
        seen: set[str] = set()
        with self.findings_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                finding = Finding.from_dict(json.loads(line))
                if dedup:
                    if finding.fingerprint in seen:
                        continue
                    seen.add(finding.fingerprint)
                findings.append(finding)
        return findings

    # -- reporting -------------------------------------------------------------

    def report(self, fmt: str = "markdown") -> str:
        self._enforce("report.generate", {"format": fmt})
        findings = self.load_findings()
        prov_records = [self.provenance.get(eid).to_dict() for eid in self.provenance.all_ids()]
        attestation = self.audit.attestation()
        run_info = {
            "workdir": str(self.workdir),
            "actor": self.actor.id,
            "capabilities": sorted(self.capabilities),
        }
        rendered = generate_report(findings, prov_records, attestation, run_info, fmt=fmt)
        self.audit.record("report.generate", params={
            "format": fmt,
            "findings": len(findings),
            "attestation_head": attestation["head_hash"],
        })
        return rendered

    def verify_audit(self):
        return self.audit.verify()


def redactable(params: dict | None) -> dict:
    """Redact string values in audit params defensively."""
    from .redaction import redact_mapping
    return redact_mapping(params or {})
