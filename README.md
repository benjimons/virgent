# Virgent

**An auditable, provenance-first security agent framework for enterprise product-development environments.**

Virgent is a Python framework and CLI for running security analysis — code and pipeline scanning, dependency/supply-chain auditing, investigation, and compliance evidence gathering — where **every action is provable after the fact**:

- **Tamper-evident audit log.** Every action the agent takes (ingestion, policy decisions, scans, LLM calls, report generation) is appended to a SHA-256 hash-chained JSONL log, optionally HMAC-signed with a key held outside the log (`VIRGENT_AUDIT_KEY`). Editing, deleting, or reordering any record is detectable with `virgent audit verify`.
- **Provenance for everything.** Every piece of information the agent consumes gets a provenance record: source, collection method, collector identity, timestamp, SHA-256 of the exact bytes, and derivation lineage (W3C-PROV-style). Findings reference evidence IDs; evidence content is stored content-addressed so any hash can be re-verified.
- **Deny-by-default policy engine.** Actions are evaluated against a YAML policy (`allow` / `deny` / `require_approval` with glob patterns). Human approvals are explicit, attributed to an approver, and audited. Network access is domain-allowlisted.
- **Data-loss prevention.** Secrets are redacted before anything crosses a trust boundary — LLM prompts, audit parameters, and reports never contain raw credentials.
- **Pluggable reasoning layer.** The Claude API (via the official `anthropic` SDK) is the default reasoning engine behind a small `ReasoningProvider` interface, so it can be swapped for Bedrock/Vertex clients or a deterministic mock for air-gapped audit runs. Every model call is policy-gated, redacted, and audited with prompt/response hashes and token usage.
- **Compliance mapping.** Findings carry control IDs mapped to SOC 2, ISO/IEC 27001:2022, NIST SP 800-53, and OWASP Top 10; reports include a per-framework coverage matrix and an audit-chain attestation.

## Install

```bash
pip install -e .          # core (offline capabilities)
pip install -e '.[llm]'   # + Claude-backed reasoning
```

## Quick start

```bash
export VIRGENT_AUDIT_KEY="$(openssl rand -hex 32)"   # enables HMAC-signed audit records

virgent init                          # creates .virgent/ with a default policy
virgent ingest ./my-repo --git-history
virgent scan                          # secrets, dependency, IaC capabilities (offline)
virgent scan --online --approve collect.web   # + OSV vulnerability lookups (audited approval)
virgent scan --llm                    # + Claude-assisted code review (needs ANTHROPIC_API_KEY)
virgent report -o report.md           # auditor-ready report with attestation
virgent audit verify                  # exit 0 iff the chain is intact
```

Ask the (audited, redacted) reasoning layer a question:

```bash
virgent ask "Summarize the riskiest findings in the last scan and what to fix first"
```

## Architecture

```
                       ┌────────────────────────────────────────────┐
   sources             │              SecurityAgent (engine)        │        outputs
                       │                                            │
 files/dirs ──┐        │  policy check ──► audit record (always)    │   ┌─► findings.jsonl
 git history ─┼─ ingest ─► provenance register (hash + lineage)     │   ├─► auditor report
 web feeds  ──┘        │        │                                   │   │   (md / json)
 (allowlisted,         │        ▼                                   │   └─► audit attestation
  approval-gated)      │  capabilities: secrets │ deps │ iac │ llm  │
                       │        │                                   │
                       │        ▼            ReasoningProvider      │
                       │  redact ─► llm.complete ─► hash + usage    │
                       └────────────────────────────────────────────┘
        .virgent/: audit.jsonl (hash chain) · provenance.jsonl · evidence/ · policy.yaml
```

Key invariants, enforced by the engine (the single choke point):

1. No action executes without a policy decision, and the decision — including denials and approvals — is audited.
2. No capability sees data that wasn't first registered with the provenance store.
3. No content reaches a model or a persisted artifact without redaction.
4. Every finding is traceable: finding → evidence IDs → provenance records → content hashes → audit records of collection.

## Capabilities

| Capability | What it does | Network |
|---|---|---|
| `secrets` | Hardcoded credentials, tokens, private keys (with line numbers, redacted excerpts) in code, configs, and git history | none |
| `dependencies` | Dependency inventory, unpinned-spec detection; known-vulnerability lookup against [OSV](https://osv.dev) when explicitly approved | optional |
| `iac` | Dockerfile, GitHub Actions, and Kubernetes misconfigurations (root containers, `pull_request_target` + checkout, unpinned actions, echoed secrets, privileged pods, …) | none |
| `llm-review` | Claude-assisted vulnerability review; model output treated as untrusted (fenced prompts, defensive parsing, `medium` confidence) | Claude API |

Add your own by subclassing `virgent.capabilities.Capability` and calling `agent.register_capability(...)` — findings automatically inherit the provenance/audit/report machinery.

## Policy

`.virgent/policy.yaml` (created by `virgent init`):

```yaml
version: 1
actions:
  default: deny
  allow: [agent.init, ingest.*, scan.*, report.*, audit.*, llm.complete]
  require_approval: [collect.web, remediate.*]
  deny: []
network:
  allowed_domains: [api.osv.dev]
llm:
  enabled: true
  redact_before_send: true
  max_input_chars: 400000
```

Approvals are per-run and attributed: `virgent scan --online --approve collect.web` records a `policy.approval` audit event naming the human who granted it.

## Using it as a library

```python
from virgent import SecurityAgent, Actor
from virgent.llm import AnthropicProvider

agent = SecurityAgent(
    workdir=".virgent",
    actor=Actor(id="ci-pipeline", type="system"),
    provider=AnthropicProvider(),          # or MockProvider() for air-gapped runs
)
agent.ingest("path/to/repo")
findings = agent.scan()
print(agent.report(fmt="markdown"))
assert agent.verify_audit().ok
```

## Verifying an audit trail (for auditors)

Given a `.virgent/` workdir and the HMAC key:

```bash
VIRGENT_AUDIT_KEY=<key> virgent --workdir .virgent audit verify
```

This recomputes every record hash, checks chain continuity and sequence numbers, and validates HMAC signatures. Any modified, deleted, or reordered record is reported with its sequence number. Evidence content can be independently re-hashed against `provenance.jsonl`.

## Development

```bash
pip install -e '.[dev]'
pytest
```

See [SECURITY.md](SECURITY.md) for the threat model and reporting instructions.
