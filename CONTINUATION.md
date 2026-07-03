# Continuation & Handoff Instructions

This document lets anyone (a person or a fresh agent session with **zero prior
context**) resume work on Virgent exactly where it was left off.

## 1. What this project is

**Virgent** is an auditable, provenance-first security agent framework for
enterprise product-development environments, built in Python 3.10+ as both a
library (`import virgent`) and a CLI (`virgent`). It was scoped as an
"all of the above" framework covering three roles:

1. **Code & pipeline security** — scan repos for secrets, vulnerable/unpinned
   dependencies, and IaC/CI misconfigurations.
2. **Security operations / investigation** — ingest arbitrary information
   (files, git history, logs, structured data, allowlisted web feeds) and
   analyze it with pluggable capabilities, including an LLM-assisted review.
3. **Compliance & GRC evidence** — every finding maps to SOC 2 / ISO 27001 /
   NIST 800-53 / OWASP controls; reports are auditor-ready and carry a
   cryptographic attestation of the run.

Design decisions locked in with the user (2026-07-03):
- Role: all-in-one framework (not a single-purpose tool)
- Stack: **Python**
- LLM: **Claude API via the official `anthropic` SDK, behind a pluggable
  `ReasoningProvider` interface** (swap for Bedrock/Vertex/mock)

## 2. Non-negotiable invariants (do not break these when extending)

All four are enforced in `src/virgent/engine.py` (`SecurityAgent`), the single
choke point:

1. **Every action is policy-checked before execution**, and the decision
   (allow / deny / require_approval, plus approvals) is written to the audit
   log — including denials.
2. **Every ingested item is registered with the provenance store** (source,
   method, collector, timestamp, SHA-256, lineage) before any capability may
   analyze it. Evidence content is stored content-addressed in
   `<workdir>/evidence/`.
3. **Every LLM call goes through `SecurityAgent.reason()`**: policy-gated,
   secret-redacted first, audited with prompt/response SHA-256 hashes and
   token usage — never raw content in the log.
4. **Every finding carries evidence IDs and control IDs**, so reports are
   reproducible and verifiable from the workdir alone.

The audit log (`src/virgent/audit.py`) is a SHA-256 hash-chained JSONL with
optional per-record HMAC-SHA256 signatures keyed by env var
`VIRGENT_AUDIT_KEY`. `virgent audit verify` (exit code 0/1) detects any
edit, deletion, or reordering.

## 3. Repository layout

```
pyproject.toml            packaging; extras: [llm] -> anthropic, [dev] -> pytest+anthropic
src/virgent/
  models.py               Actor, Evidence, Finding, Severity, hashing helpers
  audit.py                AuditLog (hash chain + HMAC), VerificationResult
  provenance.py           ProvenanceStore (register/lineage/verify_content)
  policy.py               PolicyEngine (YAML, glob rules, approvals), DEFAULT_POLICY
  redaction.py            SECRET_PATTERNS, redact(), find_secrets(), redact_mapping()
  engine.py               SecurityAgent orchestrator (THE choke point)
  cli.py                  argparse CLI: init/ingest/scan/report/audit/ask
  llm/provider.py         ReasoningProvider ABC; AnthropicProvider (claude-opus-4-8,
                          adaptive thinking, streaming); MockProvider (tests/air-gap)
  ingest/files.py         FileIngestor (binary/size filters, kind classification)
  ingest/git_history.py   GitHistoryIngestor (commits -> evidence)
  ingest/web.py           WebCollector (domain allowlist, injectable fetcher), query_osv
  capabilities/secrets.py       SecretScanCapability (reuses redaction catalog)
  capabilities/dependencies.py  DependencyAuditCapability (requirements.txt,
                                package.json; OSV via injected query fn)
  capabilities/iac.py           IaCCapability (Dockerfile / GitHub Actions / K8s rules)
  capabilities/llm_review.py    LLMReviewCapability (fenced prompts, defensive JSON
                                parse, model output = untrusted, confidence=medium)
  compliance/frameworks.py      control catalog + coverage matrix
  compliance/report.py          markdown/JSON report with audit attestation
tests/                    51 tests, all passing (pytest)
.github/workflows/ci.yml  CI: pytest on 3.10-3.12 + offline CLI smoke test
README.md                 user-facing docs; SECURITY.md = threat model
```

Runtime state lives in a workdir (default `.virgent/`): `audit.jsonl`,
`provenance.jsonl`, `evidence/`, `findings.jsonl`, `policy.yaml`.

## 4. Current status (as of last session)

- **DONE**: everything in section 3; `pip install -e '.[dev]' && pytest`
  → 51 passed. End-to-end CLI run verified manually, including: report
  contains zero raw secrets; clean chain verifies; a tampered audit record is
  detected at the right sequence number with exit code 1.
- **DONE**: committed on branch `claude/enterprise-security-agent-0fa25c`
  (commit "Add Virgent: auditable, provenance-first security agent framework").
- **BLOCKED (only open item)**: `git push -u origin
  claude/enterprise-security-agent-0fa25c` returns **403** from the session's
  git proxy (`git-receive-pack` forbidden), and the GitHub MCP write APIs
  return 403 "Resource not accessible by integration". The upstream repo
  `benjimons/virgent` is empty (no branches). This looks like the GitHub App
  installation lacking/not-yet-propagating **write** permission.

### To finish the push
1. Check the GitHub App / Claude integration has **Read and write → Contents**
   permission for `benjimons/virgent` (github.com → Settings → Applications,
   or https://claude.ai/settings integrations), then simply:
   `git push -u origin claude/enterprise-security-agent-0fa25c`
2. Or from any machine with normal credentials:
   `git remote add gh git@github.com:benjimons/virgent.git && git push -u gh
   claude/enterprise-security-agent-0fa25c`

## 5. How to resume development

```bash
git checkout claude/enterprise-security-agent-0fa25c
pip install -e '.[dev]'
pytest                                   # must stay green: 51 tests
export VIRGENT_AUDIT_KEY=$(openssl rand -hex 32)
virgent init && virgent ingest <repo> --git-history && virgent scan && virgent report
```

## 6. Roadmap (agreed direction, not yet built)

Priority-ordered next steps; each must respect the invariants in section 2:

1. **Alert/log triage capability (secops)** — ingest SIEM/JSON alert exports
   (`ingest` already handles `data`/`log` kinds), add
   `capabilities/triage.py` using `SecurityAgent.reason()` with a structured
   JSON output contract like `llm_review.py`. Map to NIST:AU-2 / SOC2:CC7.2.
2. **Continuous collectors** — a scheduler (`virgent watch`) that re-ingests
   sources and re-runs scans on an interval; advisory-feed polling via
   `WebCollector` (policy `collect.web` stays approval-gated).
3. **More manifests** — poetry/uv lockfiles, go.mod, Cargo.toml, pom.xml in
   `capabilities/dependencies.py` (pure parser additions + tests).
4. **SBOM** — CycloneDX export of the dependency inventory as evidence.
5. **Remediation actions** — PR-creating fixers behind `remediate.*`
   (already `require_approval` in the default policy; keep it that way).
6. **Report signing** — sign the rendered report with the audit HMAC key or
   an asymmetric key so the attestation is portable.
7. **WORM log shipping** — optional hook to mirror `audit.jsonl` records to
   S3 object-lock/immutable storage as they are written.

## 7. Conventions for future agents

- Tests first for any new rule/capability; keep the suite green.
- New capabilities subclass `virgent.capabilities.Capability`, attach control
  IDs from `compliance/frameworks.py` (extend the catalog if needed).
- Never let a capability or ingestor do network I/O directly — inject a
  fetcher/query function so tests stay offline and policy stays enforceable.
- Model output is untrusted input: fence evidence in prompts, parse
  defensively, cap lengths, mark confidence.
- LLM code uses the official `anthropic` SDK, default model
  `claude-opus-4-8`, `thinking={"type": "adaptive"}`, streaming via
  `client.messages.stream(...)` + `get_final_message()`.
- Commit to branch `claude/enterprise-security-agent-0fa25c`; do not push
  elsewhere without explicit permission.
