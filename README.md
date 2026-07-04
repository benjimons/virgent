# Virgent

**An auditable, provenance-first security agent — a whole security organization in one tool.**

Virgent is a Python framework and CLI that runs an entire security program: it
reviews code and infrastructure, inspects and monitors live systems, runs
authorized penetration tests, operates a full detect-triage-respond SOC,
manages vulnerabilities through their lifecycle, and maps everything to the
major compliance frameworks — all on a substrate where **every action is
policy-gated, provenance-stamped, and recorded in a tamper-evident audit
log**, and where **humans can intervene at any decision point**.

It is designed for enterprise product-development environments where you have
to *prove* what the agent did, why, and on whose authority.

## What makes it different

- **Tamper-evident audit log.** Every action (ingestion, policy decisions,
  scans, LLM calls, responses, human approvals) is appended to a SHA-256
  hash-chained JSONL log, optionally HMAC-signed with a key held outside the
  log. `virgent audit verify` detects any edited, deleted, or reordered
  record.
- **Provenance for everything.** Every piece of information the agent consumes
  gets a provenance record — source, method, collector, timestamp, content
  SHA-256, and derivation lineage. Findings reference evidence IDs; content is
  stored content-addressed so any hash can be re-verified independently.
- **Deny-by-default policy + Graduated Autonomy.** Actions are classified into
  sensitivity tiers (observe → enrich → active → respond → destructive); a
  policy maps each tier to an autonomy level (auto / notify / confirm /
  escalate / deny) and a required role on a chain (agent < analyst <
  responder < admin). A human decision queue lets people approve, deny, or be
  escalated to — and an approval in one process authorizes the action in
  another, once, with replay protection.
- **Data-loss prevention.** Secrets are redacted before anything crosses a
  trust boundary — LLM prompts, audit parameters, and reports never contain
  raw credentials.
- **Pluggable reasoning.** The Claude API (official `anthropic` SDK, adaptive
  thinking) is the default reasoning engine behind a small `ReasoningProvider`
  interface — swappable for Bedrock/Vertex or a deterministic mock for
  air-gapped audit runs. Every model call is policy-gated, redacted, and
  audited with prompt/response hashes.
- **Full compliance coverage.** 400+ controls across 11 frameworks: NIST CSF
  2.0, NIST 800-53, ISO/IEC 27001:2022, SOC 2, CIS Controls v8, CIS
  Benchmarks, PCI DSS 4.0, HIPAA, GDPR, OWASP Top 10, and MITRE ATT&CK.

## Install

```bash
pip install -e .          # core (all offline capabilities)
pip install -e '.[llm]'   # + Claude-backed reasoning
```

## Quick start

```bash
export VIRGENT_AUDIT_KEY="$(openssl rand -hex 32)"   # HMAC-signed audit records

virgent init                       # workdir + default policy
virgent list                       # every ingestor, capability, framework
virgent assess ./my-repo --host --runtime --git-history -o report.md
virgent posture                    # security-program posture (CSF + live state)
virgent audit verify               # exit 0 iff the chain is intact
```

## The capabilities

| Area | Command | What it does |
|---|---|---|
| **Code & pipeline** | `scan` | Secrets (code, config, git history), dependency/OSV supply-chain audit, IaC misconfig (Dockerfile, GitHub Actions, Kubernetes, Terraform), LLM-assisted code review |
| **Host** | `host --scan` | Read-only CIS-style hardening: SSH, accounts, kernel/sysctl, firewall, exposed services, file permissions |
| **Live systems** | `runtime --scan` | Processes, connections, sessions, services → reverse-shell/staging/exposed-service indicators (ATT&CK-mapped) |
| **Integrity** | `fim baseline`/`check` | Signed file-integrity baseline and change detection |
| **Continuous** | `watch` | Re-scan live state on an interval; alert only on *new* findings |
| **Pen testing** | `pentest` | Authorized, scope-gated, non-destructive active probing (open ports, HTTP headers, exposed paths, weak TLS) |
| **Vuln management** | `vulns` | Dedup + risk-score findings; lifecycle (open/ack/resolved/accepted); SLA/overdue |
| **SOC** | `soc detect/triage/plan/respond` | Log normalization → detection → correlation into incidents → LLM triage → approval-gated response playbooks |
| **Org & program** | `org`, `posture`, `frameworks` | The security organization, runbooks, and program-posture/maturity view |

## The agentic SOC

```bash
virgent ingest /var/log/auth.log
virgent soc detect                 # normalize -> detect -> correlate into incidents
virgent soc triage inc-abc123      # auto or LLM-assisted
virgent soc plan inc-abc123        # recommended response playbook
virgent soc respond inc-abc123 --action block_ip
# -> if the tier needs a human, it escalates:
virgent decisions                  # see pending human decisions
virgent decide dec-xyz approve --role admin
virgent soc respond inc-abc123 --action block_ip   # now executes (dry-run by default)
```

Detection covers SSH brute force, password spray, successful-login-after-
bruteforce (suspected compromise), suspicious sudo, privileged group changes,
and web attacks (SQLi / traversal / XSS / command injection) — each mapped to
MITRE ATT&CK techniques. Alerts sharing an entity (IP / user / host) correlate
into incidents with stable IDs, so human triage state survives re-runs.

## The access model — Graduated Autonomy with Escalation

Every action carries a **sensitivity tier**. Policy maps each tier to an
**autonomy level** and a **minimum role**:

| Tier | Example | Default autonomy | Min role |
|---|---|---|---|
| observe | read a log, scan code | auto | agent |
| enrich | LLM triage, OSV lookup | auto | agent |
| active | port probe | confirm | analyst |
| respond | block IP, disable user | confirm | responder |
| destructive | isolate host | escalate | admin |

High **risk** bumps the required role up the chain (a CRITICAL incident's
`block_ip` needs an admin). When a human is required, Virgent opens a
**decision** — a person approves/denies via `virgent decide`; a too-junior
approver escalates it further rather than resolving it. Approvals persist and
are consumed once. Everything is audited. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Autonomous operation

Virgent finds its own work — you don't have to name every target. Discovery is
bounded by policy (a declared scope), and every discovered asset is
provenance-stamped and audited like any other input:

```bash
virgent discover                 # list assets it found (repos, logs, host)
virgent auto                     # discover + ingest + scan + detect + report, unattended
virgent watch --discover         # continuous, picking up new assets each tick
```

- **Local discovery** (read-only, autonomous): git repositories under
  configured roots, log files, and the host/runtime itself.
- **Network discovery** (scope-limited, approval-gated): sweeps only the CIDRs
  in the policy `discover.network_scope` to build a service inventory —
  reaching out to other machines is treated like pen testing.
- **Cloud discovery / CSPM** (approval-gated): reaches *into* a cloud account
  with its own read-only credentials (instance role / env / profile) and
  enumerates the internal resources only a credentialed insider can see — S3
  buckets, security groups, IAM users, RDS — then flags public storage, open
  security groups, unencrypted data, and IAM hygiene (stale keys, missing MFA,
  admin grants). Enable in the policy `cloud` block; run with `--cloud`:

  ```bash
  pip install 'virgent[aws]'
  virgent discover --cloud          # enumerate + inventory the account
  virgent auto --cloud              # + CSPM findings mapped to CIS/NIST/PCI/SOC2
  ```

The default is safe-by-design: it discovers within a scope, never outside it,
and the scope is the authorization boundary. Point it at your estate by
editing the `discover` block in `policy.yaml`.

## Running always-on

One process monitors the live system forever — host hardening drift,
runtime indicators (reverse shells, staging dirs, exposed services), file
integrity, and SOC detection over your logs:

```bash
virgent fim baseline /etc/ssh/sshd_config /etc/passwd /etc/sudoers
virgent watch --interval 60 --log /var/log/auth.log     # offset-tracked tailing
```

- **Log tailing** follows growing logs without re-ingesting them, and handles
  rotation/truncation.
- **Notifications** push decisions and new high-severity incidents to
  stdout/file/webhook/Slack (configure the `notify` block; `virgent notify
  test`). Network channels are domain-allowlisted; dispatch never breaks the
  pipeline.
- **Response executors** are dry-run by default. Configure `response.executor`
  (command or webhook/SOAR) to let an *already-authorized* action touch
  production — the access model still gates every action; params are strictly
  validated and run with no shell.

Deploy it as a service with `deploy/virgent-watch.service` (systemd) or
`deploy/docker-compose.yml`. Full topology, durability/WORM guidance, and the
human decision loop are in [deploy/DEPLOYMENT.md](deploy/DEPLOYMENT.md).

## Compliance

```bash
virgent frameworks                        # 401 controls across 11 frameworks
virgent frameworks --framework NIST-CSF-2.0
```

Findings carry control IDs; reports include a per-framework coverage matrix and
an audit-chain attestation, so an auditor holding the workdir can re-verify
every claim. `virgent posture` maps active capabilities onto the six NIST CSF
2.0 functions and produces a maturity score.

## Using it as a library

```python
from virgent import SecurityAgent, Actor
from virgent.llm import AnthropicProvider

agent = SecurityAgent(actor=Actor(id="ci", type="system"), provider=AnthropicProvider())
agent.ingest("path/to/repo")
agent.ingest("localhost", ingestor="host")
findings = agent.scan()
agent.sync_vulns()
print(agent.report())
print(agent.program_posture())
assert agent.verify_audit().ok
```

## Safety & authorization

Virgent is built for **authorized** defensive use. Penetration testing is
off unless you both grant an approval *and* list the target in the policy
`pentest.scope`; response actions are dry-run by default and gated behind
human approval; the agent's reasoning layer has no tool access and its output
is treated as untrusted. See [SECURITY.md](SECURITY.md) for the threat model.

## Development

```bash
pip install -e '.[dev]'
pytest          # 113 tests
```

- [ARCHITECTURE.md](ARCHITECTURE.md) — how the pieces fit and the invariants
- [CONTINUATION.md](CONTINUATION.md) — full handoff notes for resuming work
- [SECURITY.md](SECURITY.md) — threat model and reporting
