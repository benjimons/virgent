# Security Policy

## Threat model

Virgent is designed to run inside enterprise product-development environments and to remain trustworthy under audit. The guarantees and their limits:

| Property | Mechanism | Limit |
|---|---|---|
| Audit integrity | SHA-256 hash chain per record; sequence numbers | An attacker who can rewrite the file can recompute the chain — mitigated by HMAC |
| Audit authenticity | HMAC-SHA256 per record with `VIRGENT_AUDIT_KEY` | Key must be held outside the environment the agent runs in (KMS/secret manager); an attacker holding the key can forge records |
| Audit availability | Append-only writes with fsync | Whole-file deletion is not self-detectable — ship logs to WORM/immutable storage for retention |
| Provenance | Content-addressed evidence (SHA-256), lineage graph | Trust in provenance starts at collection time; it attests what was collected, not that the source itself was honest |
| Least privilege | Deny-by-default action policy, attributed approvals, domain allowlists | Policy is only as strong as its configuration; review changes to `policy.yaml` like code |
| Data-loss prevention | Pattern-based redaction before LLM egress, audit params, and reports | Pattern-based DLP is best-effort; novel secret formats may pass. Entropy heuristics reduce, not eliminate, misses |
| Prompt injection | Evidence fenced in prompts; model output parsed defensively, capped, and marked lower-confidence; model can only produce findings, never actions | LLM findings should be human-reviewed; the model has no tool access through this framework |
| Authorized action / human oversight | Graduated Autonomy with Escalation: sensitivity tiers → autonomy levels → role chain; response actions dry-run by default and gated behind a persisted, replay-protected human decision | Autonomy config is policy — review it like code; a mis-set tier lowers oversight |
| Authorized pen testing | `pentest.*` requires both an approval and a policy `pentest.scope` allowlist match (host / `.suffix` / CIDR); probes are non-destructive and non-exploitative | Only add hosts you are authorized to test to the scope; the scope is the authorization boundary |

## Deployment recommendations

- Generate `VIRGENT_AUDIT_KEY` from a secret manager and never store it alongside the workdir.
- Ship `audit.jsonl` and `provenance.jsonl` to append-only (WORM) storage on a schedule.
- Run the agent with a read-only view of the code under analysis.
- Keep `require_approval` on all network-touching and remediation actions; approvals are audited with the approver's identity.
- Treat `policy.yaml` as code: review and version-control changes.

## Reporting a vulnerability

Please open a private security advisory on the repository (GitHub → Security → Advisories) rather than a public issue. Include reproduction steps and the version/commit. We aim to acknowledge reports within 72 hours.
