# Virgent Architecture

## The choke point

Everything flows through one object, `SecurityAgent` (`virgent/engine.py`),
which enforces four invariants so the system stays auditable end to end:

1. **Every action is policy-checked before it runs**, and the decision —
   including denials, approvals, and autonomy escalations — is written to the
   audit log.
2. **Every ingested item is registered with the provenance store** before any
   capability may analyze it. Evidence content is stored content-addressed.
3. **Every LLM call is redacted first**, then audited with prompt/response
   hashes and token usage (never raw content).
4. **Every finding carries evidence IDs and control IDs**, so reports are
   reproducible and verifiable from the workdir alone.

```
                         ┌───────────────────────────── SecurityAgent ─────────────────────────────┐
 sources                 │                                                                          │  outputs
                         │  policy check ─► autonomy/decision ─► audit record (always)             │
 files / git ──┐ ingest  │        │                                                                 │  ┌─► findings.jsonl
 host / runtime┼───────► │        ▼                                                                 │  ├─► vuln register
 web / logs ───┘         │  provenance register (hash + lineage) ─► evidence/                       │  ├─► SOC casebook
 (allowlisted,           │        │                                                                 │  ├─► auditor report
  gated, audited)        │        ▼                                                                 │  │   (+ CSF posture,
                         │  capabilities: secrets│deps│iac│host│runtime│llm-review                  │  │    control coverage,
                         │  pentest (scope-gated) │ SOC (detect→correlate→triage→respond)           │  │    attestation)
                         │  fim │ vulns │ org/posture                                                │  └─► decisions queue
                         │        │                                                                 │
                         │        ▼           ReasoningProvider (Claude / Bedrock / mock)           │
                         │  redact ─► llm.complete ─► hash + token usage                            │
                         └──────────────────────────────────────────────────────────────────────────┘
    workdir/: audit.jsonl (hash chain) · provenance.jsonl · evidence/ · findings.jsonl
              vuln_register.json · decisions.json · fim_baseline.json · soc/ · policy.yaml
```

## Modules

| Module | Responsibility |
|---|---|
| `models.py` | Actor, Evidence, Finding, Severity; hashing; semantic fingerprint |
| `audit.py` | SHA-256 hash-chained, HMAC-signable, append-only audit log + verify |
| `provenance.py` | Content-addressed evidence store with derivation lineage |
| `policy.py` | Deny-by-default YAML policy: allow/deny/require_approval, pentest scope, access block |
| `access.py` | Graduated Autonomy with Escalation: sensitivity tiers, autonomy levels, role chain, DecisionBroker |
| `redaction.py` | Secret pattern catalog (shared by DLP and the secret scanner) |
| `ingest/` | file, git history, host, runtime, web collectors (allowlisted, injectable) |
| `capabilities/` | secrets, dependencies, iac, host, runtime, llm-review |
| `pentest.py` | authorized, scope-gated, non-destructive active prober |
| `integrity.py` | file-integrity monitoring (baseline + check) |
| `vulnmgmt.py` | dedup + risk scoring + lifecycle register |
| `soc/` | events → detection → correlation → casebook → triage → response |
| `compliance/` | control catalog (11 frameworks), coverage, CSF crosswalk, reports |
| `org/` | functions, teams, roles, RACI, runbooks, program posture |
| `llm/` | ReasoningProvider interface + Anthropic and mock providers |
| `engine.py` | the orchestrator that ties it all together and enforces the invariants |
| `cli.py` | the `virgent` command-line interface |

## Graduated Autonomy with Escalation (the access model)

The problem: a "total" security agent must reach into many systems and
sometimes *act*, but humans must be able to intervene at any point and
high-stakes actions must reach the right person.

- **Sensitivity** — every action is classified `observe < enrich < active <
  respond < destructive` (`access.ACTION_SENSITIVITY`).
- **Autonomy** — policy maps each tier to `auto | notify | confirm | escalate
  | deny`.
- **Roles** — an ordered chain `agent < analyst < responder < admin`; each
  tier needs a minimum role, and **risk bumps the requirement up the chain**.
- **DecisionBroker** — when a human is required, a `DecisionRequest` is
  persisted. A person resolves it with `virgent decide`; a too-junior approver
  **escalates** it instead of resolving it. An approved decision authorizes the
  action **across processes** and is **consumed once** (replay-protected).

Every request, escalation, resolution, and execution is audited, so the full
decision trail — who was asked, who decided, when, why — is reconstructable.

## Extending

- **New capability** → subclass `capabilities.Capability`, attach control IDs
  from `compliance/catalog.py`, register with `agent.register_capability(...)`.
  It inherits provenance, audit, dedup, reporting, and CSF crosswalk for free.
- **New ingestor** → subclass `ingest.Ingestor`; keep network I/O behind an
  injectable fetcher/runner so it stays testable and policy-enforceable.
- **New detection rule** → add to `soc/detection.py` with an ATT&CK mapping in
  `RULE_ATTACK`; add a runbook in `org/runbooks.py`.
- **New framework/controls** → add to `compliance/catalog.py`.
- **New response action** → add to `soc/response.py` `ACTIONS` with a
  sensitivity tier; the access model gates it automatically.
