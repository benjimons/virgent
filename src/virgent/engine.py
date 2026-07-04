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
    CloudPostureCapability,
    DependencyAuditCapability,
    HostInspectionCapability,
    IaCCapability,
    LLMReviewCapability,
    RuntimeInspectionCapability,
    SecretScanCapability,
)
from .ccm import ControlMonitor
from .cloud import build_cloud_provider
from .compliance.report import generate_report
from .ingest import (
    FileIngestor,
    GitHistoryIngestor,
    HostIngestor,
    Ingestor,
    WebCollector,
    query_osv,
)
from .access import (
    Autonomy,
    AutonomyPolicy,
    DecisionBroker,
    EscalationRequired,
    Sensitivity,
)
from .discovery import AssetDiscoverer
from .ingest.runtime import RuntimeIngestor
from .ingest.tail import TailIngestor
from .integrity import IntegrityMonitor
from .notify import Notification, build_dispatcher
from .pentest import PenTester
from .policy import PolicyDecision
from .soc import SOC
from .soc.executors import build_executor
from .soc.response import ACTIONS as RESPONSE_ACTIONS
from .vulnmgmt import VulnerabilityRegister
from .llm.provider import LLMResult, ReasoningProvider
from .models import Actor, Evidence, Finding, Severity
from .policy import PolicyEngine, PolicyViolation
from .provenance import ProvenanceStore
from .redaction import redact

__version__ = "0.1.0"

DEFAULT_ACTOR = Actor(id="virgent", type="agent")

# ingestor name -> audited action (default is ingest.<name>)
_INGEST_ACTIONS = {
    "web": "collect.web", "host": "collect.host",
    "runtime": "collect.runtime", "tail": "collect.tail",
}


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
            "host": HostIngestor(),
            "runtime": RuntimeIngestor(),
            "tail": TailIngestor(self.workdir / "tail_state.json"),
            "web": WebCollector(
                allowed_domains=(self.policy.policy.get("network") or {}).get("allowed_domains") or [],
            ),
        }
        self.capabilities: dict[str, Capability] = {}
        self.register_capability(SecretScanCapability())
        self.register_capability(DependencyAuditCapability())
        self.register_capability(IaCCapability())
        self.register_capability(HostInspectionCapability())
        self.register_capability(RuntimeInspectionCapability())
        self.register_capability(CloudPostureCapability())
        if self.provider is not None:
            self.register_capability(LLMReviewCapability(reason=self.reason))

        self.integrity = IntegrityMonitor(self.workdir / "fim_baseline.json")
        self.vulns = VulnerabilityRegister(self.workdir / "vuln_register.json")
        self.discoverer = AssetDiscoverer.from_policy(self.policy.policy)
        # cloud provider (None unless policy 'cloud.enabled'); inject for tests
        self.cloud_provider = build_cloud_provider(self.policy.policy)
        self.ccm = ControlMonitor(self.workdir / "ccm_state.json")
        self.pentest_prober = None  # inject a Prober for tests/dry-runs

        # notifications (stdout/file/webhook/slack); network channels are
        # domain-allowlisted by policy and dispatch never breaks the pipeline
        self.notifier = build_dispatcher(
            self.policy.policy, domain_check=self.policy.domain_allowed, workdir=self.workdir)

        # access & autonomy model (Graduated Autonomy with Escalation).
        # Decision events are audited AND surfaced to humans via notifications.
        self.autonomy = AutonomyPolicy.from_policy(self.policy.policy)
        self.broker = DecisionBroker(
            self.workdir / "decisions.json", self.autonomy, audit=self._audit_and_notify)

        # SOC
        soc_reason = self.reason if self.provider is not None else None
        self.soc = SOC(self.workdir / "soc", reason=soc_reason)
        # real response executor from policy (default None -> dry-run); actions
        # are gated by the access model regardless of which executor runs them
        self.response_executor = build_executor(
            self.policy.policy, domain_check=self.policy.domain_allowed)
        self._notified_incidents_path = self.workdir / "notified_incidents.json"

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

    # -- notifications --------------------------------------------------------

    def _audit_and_notify(self, event: str, params: dict | None = None, **kw) -> None:
        """Broker audit callback: record the event, then notify humans of the
        ones that need their attention (a decision waiting, or an escalation)."""
        self.audit.record(event, params=params or {}, **kw)
        params = params or {}
        if event == "decision.requested":
            self._safe_notify(Notification(
                kind="decision.requested",
                title=f"Human decision needed: {params.get('action', '?')}",
                severity=Severity.HIGH,
                body=(f"A '{params.get('sensitivity', '?')}' action requires a "
                      f"'{params.get('required_role', '?')}' to approve. "
                      f"Decision id: {params.get('id', '?')} "
                      f"(virgent decide {params.get('id', '?')} approve --role "
                      f"{params.get('required_role', '?')})"),
                data=params))
        elif event == "decision.escalated":
            self._safe_notify(Notification(
                kind="decision.escalated",
                title=f"Decision escalated: {params.get('id', '?')}",
                severity=Severity.HIGH,
                body=(f"Escalated by {params.get('by', '?')} ({params.get('role', '?')}); "
                      f"now needs role >= {params.get('required_role', '?')}."),
                data=params))

    def _safe_notify(self, notification: Notification) -> list[dict]:
        """Redact then dispatch a notification. Never raises."""
        try:
            notification.body = redact(notification.body)[0]
            return self.notifier.dispatch(notification)
        except Exception:  # noqa: BLE001 - notification must not break anything
            return []

    def _load_notified_incidents(self) -> set[str]:
        if self._notified_incidents_path.exists():
            try:
                return set(json.loads(self._notified_incidents_path.read_text()))
            except (json.JSONDecodeError, OSError):
                return set()
        return set()

    def _notify_new_incidents(self, incidents: list) -> None:
        seen = self._load_notified_incidents()
        changed = False
        for inc in incidents:
            if inc.id in seen:
                continue
            self._safe_notify(Notification(
                kind="incident",
                title=f"[{inc.priority}] {inc.title}",
                severity=inc.severity,
                body=(f"Rules: {', '.join(inc.rules)}. "
                      f"Entities: {inc.entities}. Recommended: "
                      f"{', '.join(a['action'] for a in self.soc.plan(inc.id))}."),
                data={"incident": inc.id, "severity": inc.severity.value}))
            seen.add(inc.id)
            changed = True
        if changed:
            self._notified_incidents_path.write_text(
                json.dumps(sorted(seen)), encoding="utf-8")

    def notify_test(self) -> list[dict]:
        """Send a test notification through every configured channel (audited)."""
        self._enforce("notify.test")
        results = self._safe_notify(Notification(
            kind="test", title="Virgent notification test",
            severity=Severity.HIGH, body="If you can read this, notifications work."))
        self.audit.record("notify.test", params={"channels": len(self.notifier.notifiers),
                                                 "results": results})
        return results

    def approve(self, action_pattern: str, approver: Actor) -> None:
        """Record a human approval for a restricted action (audited)."""
        self.policy.grant_approval(action_pattern, approver)
        self.audit.record(
            "policy.approval",
            params={"pattern": action_pattern},
            detail=f"approved by {approver.id}",
            actor=approver,
        )

    # -- autonomous discovery ------------------------------------------------

    def discover(self, network: bool = False) -> list:
        """Find the agent's own work, bounded by policy scope (audited).

        Local discovery is autonomous (read-only). Network discovery is
        scope-limited and gated — the same ``discover.network`` policy action
        must be allowed (approval + a declared ``network_scope``).
        """
        self._enforce("discover.local")
        targets = self.discoverer.discover_local()
        if network:
            self._enforce("discover.network", {"scope": self.discoverer.network_scope})
            targets += self.discoverer.discover_network()
        self.audit.record("discover.local", params={
            "targets": len(targets),
            "by_kind": {k: sum(1 for t in targets if t.kind == k)
                        for k in {t.kind for t in targets}},
            "network": network,
        })
        return targets

    def discover_cloud(self) -> list:
        """Enumerate the cloud account's own resources (CSPM discovery).

        Uses the configured provider's read-only credentials, so it sees the
        internal/private resources only a credentialed insider can. Each
        resource is registered as provenance-stamped ``cloud-asset`` evidence
        that the cloud posture capability then evaluates. Gated + audited.
        """
        self._enforce("discover.cloud")
        if self.cloud_provider is None:
            raise RuntimeError(
                "no cloud provider configured (set policy 'cloud.enabled: true' "
                "and 'cloud.provider', or inject agent.cloud_provider)")
        resources = self.cloud_provider.enumerate()
        for r in resources:
            self.provenance.register(
                source=f"cloud:{r.provider}:{r.region}:{r.id}",
                method="discover.cloud", kind="cloud-asset",
                content=json.dumps(r.to_dict(), sort_keys=True),
                collector=self.actor,
                metadata={"provider": r.provider, "service": r.service, "rtype": r.rtype})
        self.audit.record("discover.cloud", params={
            "provider": self.cloud_provider.name,
            "resources": len(resources),
            "by_service": {s: sum(1 for r in resources if r.service == s)
                           for s in {r.service for r in resources}},
        })
        return resources

    def autodiscover(self, network: bool = False, cloud: bool = False) -> dict:
        """Discover assets and automatically ingest each through the right
        ingestor — the fully autonomous "find your own work" path. Network
        services and cloud resources are recorded as inventory/asset evidence.
        """
        targets = self.discover(network=network)
        ingested = 0
        inventory = 0
        cloud_resources = 0
        if cloud:
            cloud_resources = len(self.discover_cloud())
        for t in targets:
            if t.ingestor == "file":
                self.ingest(t.locator, ingestor="file")
                ingested += 1
                if t.metadata.get("git"):
                    try:
                        self.ingest(t.locator, ingestor="git")
                    except (RuntimeError, FileNotFoundError):
                        pass
            elif t.ingestor in ("tail", "host", "runtime"):
                loc = "localhost" if t.ingestor in ("host", "runtime") else t.locator
                self.ingest(loc, ingestor=t.ingestor)
                ingested += 1
            elif t.kind == "service":
                # scoped network asset: record as provenance-stamped inventory
                self.provenance.register(
                    source=f"asset:{t.locator}", method="discover.network",
                    kind="asset", content=json.dumps(t.to_dict(), sort_keys=True),
                    collector=self.actor, metadata=t.metadata)
                inventory += 1
        summary = {"targets": len(targets), "ingested": ingested,
                   "inventory": inventory, "cloud_resources": cloud_resources}
        self.audit.record("discover.ingest", params=summary)
        return summary

    # -- ingestion -----------------------------------------------------------

    def ingest(self, target: str, ingestor: str = "file") -> list[Evidence]:
        """Ingest a source; every item is provenance-stamped and audited."""
        action = _INGEST_ACTIONS.get(ingestor, f"ingest.{ingestor}")
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

    # -- file integrity monitoring --------------------------------------------

    def integrity_baseline(self, paths: list[str]) -> dict:
        """Record a known-good hash baseline for critical files (audited)."""
        self._enforce("fim.baseline", {"paths": paths})
        # register each file with provenance so the baseline is provable
        for p in paths:
            try:
                content = Path(p).read_text(errors="replace")
            except OSError:
                continue
            self.provenance.register(
                source=p, method="fim.baseline", kind="baseline",
                content=content, collector=self.actor,
            )
        summary = self.integrity.baseline(paths)
        self.audit.record("fim.baseline", params=summary)
        return summary

    def integrity_check(self) -> list[Finding]:
        """Detect modification/removal of baselined files (audited)."""
        self._enforce("fim.check", {"watched": len(self.integrity.watched)})
        findings = self.integrity.check()
        self._persist_findings(findings)
        self.audit.record("fim.check", params={
            "watched": len(self.integrity.watched),
            "changes": len(findings),
            "finding_ids": [f.id for f in findings],
        })
        return findings

    # -- penetration testing (authorized + scope-gated) -----------------------

    def pentest(self, targets: list[dict]) -> list[Finding]:
        """Run non-destructive active probes against authorized targets.

        Requires an approval for ``pentest.run`` AND every target host must be
        inside the policy ``pentest.scope`` allowlist. Findings are marked
        ``verified`` and fed into the vulnerability register.
        """
        decision = self._enforce("pentest.run", {"hosts": [t.get("host") for t in targets]})
        for target in targets:
            host = target.get("host", "")
            if not self.policy.pentest_allowed(host):
                self.audit.record("pentest.run", params={"host": host},
                                  outcome="denied:scope",
                                  detail="host is not in the authorized pentest scope")
                raise PolicyViolation(PolicyDecision(
                    "pentest.run", "deny", "pentest.scope",
                    f"host '{host}' is not in the authorized pentest scope"))
        tester = PenTester(prober=self.pentest_prober) if self.pentest_prober else PenTester()
        findings, transcript = tester.run(targets)
        ev = self.provenance.register(
            source="pentest:transcript", method="pentest.probe", kind="pentest",
            content=transcript, collector=self.actor,
            metadata={"hosts": [t.get("host") for t in targets]},
        )
        for f in findings:
            f.evidence_ids = [ev.id]
        self._persist_findings(findings)
        self.audit.record("pentest.run", params={
            "hosts": [t.get("host") for t in targets],
            "findings": len(findings),
            "approved_by": decision.approved_by,
            "transcript_sha256": ev.sha256,
        })
        return findings

    # -- vulnerability management ---------------------------------------------

    def sync_vulns(self) -> dict:
        """Merge all findings into the managed vulnerability register (audited)."""
        self._enforce("vulns.sync")
        summary = self.vulns.sync(self.load_findings())
        self.audit.record("vulns.sync", params=summary)
        return summary

    def set_vuln_status(self, fingerprint: str, status: str, note: str = "") -> dict:
        self._enforce("vulns.status", {"fingerprint": fingerprint, "status": status})
        entry = self.vulns.set_status(fingerprint, status, actor=self.actor.id, note=note)
        self.audit.record("vulns.status", params={
            "fingerprint": fingerprint, "status": status, "note": note,
        })
        return entry.to_dict()

    # -- SOC: detect / triage / respond ---------------------------------------

    def soc_detect(self) -> tuple[list, list]:
        """Run detection + correlation over ingested log evidence (audited)."""
        self._enforce("soc.detect")
        evidence = [e for e in self.load_evidence()
                    if e.kind in ("log", "data", "event", "text")]
        alerts, incidents = self.soc.process_evidence(evidence)
        self.audit.record("soc.detect", params={
            "evidence": len(evidence),
            "alerts": len(alerts),
            "incidents": len(incidents),
            "incident_ids": [i.id for i in incidents],
        })
        self._notify_new_incidents(incidents)
        return alerts, incidents

    def soc_triage(self, incident_id: str):
        self._enforce("soc.triage", {"incident": incident_id})
        inc = self.soc.triage(incident_id)
        self.audit.record("soc.triage", params={
            "incident": incident_id, "status": inc.status, "priority": inc.priority,
        })
        return inc

    def soc_plan(self, incident_id: str) -> list[dict]:
        self._enforce("soc.plan", {"incident": incident_id})
        return self.soc.plan(incident_id)

    def soc_respond(self, incident_id: str, action: str):
        """Execute a response action under the Graduated Autonomy model.

        AUTO/NOTIFY tiers (or a standing approval) execute immediately;
        CONFIRM/ESCALATE tiers with no approval open a human decision and
        raise :class:`EscalationRequired`; DENY refuses.
        """
        incident = self.soc.casebook.get_incident(incident_id)
        _desc, sensitivity = RESPONSE_ACTIONS.get(action, (action, Sensitivity.RESPOND))
        from .vulnmgmt import _SEVERITY_SCORE
        context = {
            "incident": incident_id,
            "action": action,
            "severity": incident.severity.value,
            "risk": _SEVERITY_SCORE.get(incident.severity, 45),
            "entities": incident.entities,
        }
        level, required_role = self.autonomy.evaluate(sensitivity, context)
        action_name = f"respond.{action}"

        if level == Autonomy.DENY:
            self.audit.record(action_name, params=context, outcome="denied:autonomy",
                             detail="autonomy policy denies this action")
            raise PolicyViolation(PolicyDecision(
                action_name, "deny", "access.autonomy", "denied by autonomy policy"))

        # a persisted, approved (and not-yet-used) decision authorizes the
        # action across processes — the human's approval is the grant
        approved_decision = self.broker.approved_for(action_name, incident_id)
        standing = self.policy.evaluate(action_name)
        standing_approval = standing.allowed and standing.rule != "default"

        if level in (Autonomy.AUTO, Autonomy.NOTIFY) or approved_decision or standing_approval:
            entry = self.soc.execute_action(incident_id, action, self.response_executor)
            if approved_decision:
                self.broker.mark_consumed(approved_decision.id)
            self.audit.record(action_name, params={
                "incident": incident_id, "action": action,
                "autonomy": level.value,
                "authorized_by": approved_decision.resolved_by if approved_decision
                else ("standing_approval" if standing_approval else "autonomy"),
                "result": entry["result"].get("status"),
            })
            return entry

        # needs a human decision
        req = self.broker.open(action_name, sensitivity, context, required_role, level)
        raise EscalationRequired(req)

    def soc_runbooks(self, incident_id: str) -> list[dict]:
        """Return the org runbooks that apply to an incident's alerts."""
        from .org import select_runbooks
        inc = self.soc.casebook.get_incident(incident_id)
        return select_runbooks(inc.rules)

    # -- continuous control monitoring ----------------------------------------

    def ccm_assess(self) -> dict:
        """Evaluate every monitored control against current findings (audited).

        Returns per-control pass/fail state plus a compliance summary. Each
        failing control gets an owner and an SLA-driven remediation due date.
        """
        self._enforce("ccm.assess")
        findings = self.load_findings()
        active = list(self.capabilities) + ["soc", "fim"]
        results = self.ccm.assess(findings, active)
        summary = self.ccm.summary(results)
        self.audit.record("ccm.assess", params={
            "controls": summary["controls_monitored"],
            "compliance_pct": summary["compliance_pct"],
            "by_status": summary["by_status"],
            "overdue": len(summary["overdue"]),
        })
        return {"summary": summary, "results": [r.to_dict() for r in results]}

    # -- security-program posture ---------------------------------------------

    def program_posture(self) -> dict:
        """Tie live agent state back to the security org and NIST CSF functions."""
        self._enforce("report.posture")
        from .org import program_posture
        findings = self.load_findings()
        vuln_summary = self.vulns.summary().get("by_severity", {})
        open_incidents = sum(
            1 for i in self.soc.casebook.all_incidents()
            if i.status not in ("resolved",))
        # capabilities plus the always-available engine subsystems
        active = list(self.capabilities) + ["soc", "fim", "pentest"]
        posture = program_posture(
            active_capabilities=active,
            findings=findings,
            open_vulns_by_severity=vuln_summary,
            open_incidents=open_incidents,
            pending_decisions=len(self.broker.pending()),
            audit_ok=self.verify_audit().ok,
        )
        self.audit.record("report.posture", params={
            "maturity_score": posture["maturity_score"],
            "maturity_band": posture["maturity_band"],
            "csf_functions_covered": posture["csf_functions_covered"],
        })
        return posture

    # -- human-in-the-loop decisions ------------------------------------------

    def resolve_decision(self, decision_id: str, decision: str, resolver: str,
                         role: str, note: str = "") -> dict:
        """Record a human's approve/deny (or escalate on insufficient role)."""
        req = self.broker.resolve(decision_id, decision, resolver, role, note=note)
        if req.status == "approved":
            # grant the standing approval so the action can now proceed
            self.policy.grant_approval(req.action, Actor(id=resolver, type="human"))
            self.audit.record("policy.approval", params={
                "pattern": req.action, "via_decision": decision_id, "role": role,
            }, actor=Actor(id=resolver, type="human"))
        return req.to_dict()

    def pending_decisions(self) -> list[dict]:
        return [r.to_dict() for r in self.broker.pending()]

    # -- continuous monitoring ------------------------------------------------

    def monitor_tick(self, capabilities: list[str] | None = None) -> list[Finding]:
        """One live snapshot + scan cycle for continuous monitoring.

        Re-ingests live host/runtime state, scans, checks file integrity, and
        records a ``monitor.tick`` audit event. Returns this tick's findings.
        """
        self._enforce("monitor.tick", {"capabilities": capabilities})
        caps = capabilities or ["host", "runtime"]
        if "host" in caps:
            self.ingest("localhost", ingestor="host")
        if "runtime" in caps:
            self.ingest("localhost", ingestor="runtime")
        findings = self.scan(capabilities=caps)
        if self.integrity.watched:
            findings = findings + self.integrity_check()
        self.audit.record("monitor.tick", params={
            "capabilities": caps,
            "findings": len(findings),
        })
        return findings

    def monitor_cycle(
        self,
        capabilities: list[str] | None = None,
        log_sources: list[str] | None = None,
        discover: bool = False,
    ) -> dict:
        """One full always-on monitoring cycle.

        Covers live host/runtime/integrity state plus, if ``log_sources`` are
        given, re-ingestion of those logs and a SOC detection pass. With
        ``discover=True`` it first auto-discovers assets (repos, logs, host)
        and folds any newly found logs into this cycle's detection — so a
        long-running watcher picks up new work on its own. This is the unit a
        ``virgent watch`` service repeats forever; alerts/incidents dedup by
        stable identity, so repeating the cycle doesn't create duplicates.
        """
        caps = list(capabilities or ["host", "runtime"])
        sources = list(log_sources or [])
        if discover:
            repos_found = False
            for t in self.discover(network=False):
                if t.ingestor == "file":  # a discovered repo / code tree
                    self.ingest(t.locator, ingestor="file")
                    repos_found = True
                    if t.metadata.get("git"):
                        try:
                            self.ingest(t.locator, ingestor="git")
                        except (RuntimeError, FileNotFoundError):
                            pass
                elif t.kind == "log" and t.locator not in sources:
                    sources.append(t.locator)   # host/runtime handled by the tick
            if repos_found:  # analyze the code we just found
                for c in ("secrets", "dependencies", "iac"):
                    if c not in caps:
                        caps.append(c)
        findings = self.monitor_tick(capabilities=caps)
        incidents: list = []
        if sources:
            for src in sources:
                try:
                    # offset-tracked: only new lines are ingested each cycle
                    self.ingest(src, ingestor="tail")
                except (FileNotFoundError, OSError):
                    continue
            _, incidents = self.soc_detect()
        return {"findings": findings, "incidents": incidents}

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
