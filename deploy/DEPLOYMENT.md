# Running Virgent always-on in an organization

Virgent has two kinds of work: **continuous, autonomous observation** (safe to
run 24/7) and **consequential actions** (gated behind a human). The deployment
model keeps the first always running and routes the second to people.

## The model

```
        per host / workload                    central (optional)              humans
   ┌───────────────────────────┐        ┌──────────────────────────┐    ┌──────────────────┐
   │  virgent watch (service)  │        │  aggregation + console   │    │  virgent decisions│
   │  host + runtime + FIM      │  logs/ │  (sync workdirs, or a    │    │  virgent decide   │
   │  + SOC over local logs      ├──────► │   central node pulling    │◄───┤  approve / deny /  │
   │  → audit.jsonl (WORM)       │ state  │   logs) → posture, report │    │  escalate          │
   │  response = DRY-RUN         │        └──────────────────────────┘    └──────────────────┘
   └───────────────────────────┘
```

- **Autonomous tier (observe/enrich)** runs continuously with no human: it
  ingests, scans, detects, correlates, and writes an audit trail. It never
  blocks an IP or disables a user on its own.
- **Action tier (active/respond/destructive)** is never taken by the loop.
  When the SOC recommends a response, the access model opens a **decision**;
  a human resolves it with `virgent decide`. Until then nothing happens.

## 1. Per-host / per-workload agent (recommended baseline)

Install the CLI and run the continuous monitor as a service. It watches host
hardening drift, live-system indicators (reverse shells, staging dirs, exposed
services), file integrity, and runs SOC detection over local logs — one loop.

**systemd** (`deploy/virgent-watch.service`):

```bash
sudo useradd --system --home-dir /var/lib/virgent --create-home virgent
sudo pip install /path/to/virgent            # or from your internal index
echo "VIRGENT_AUDIT_KEY=$(openssl rand -hex 32)" | sudo tee /etc/virgent/virgent.env
sudo cp deploy/virgent-watch.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now virgent-watch
journalctl -u virgent-watch -f
```

**Container** (`deploy/Dockerfile`, `deploy/docker-compose.yml`): run with
`--pid=host` and `/var/log` mounted read-only to inspect the host.

```bash
VIRGENT_AUDIT_KEY=$(openssl rand -hex 32) \
  docker compose -f deploy/docker-compose.yml up -d
```

Baseline file integrity once, then the loop reports any change:

```bash
virgent --workdir /var/lib/virgent fim baseline \
  /etc/ssh/sshd_config /etc/passwd /etc/sudoers
```

## 2. Code & pipeline (CI, not a daemon)

Repo/dependency/IaC/secret scanning belongs in CI, run per change — add a
`virgent assess . --git-history` step (there's a `SessionStart`-friendly
`.github/workflows/ci.yml` pattern in the repo) and fail the build on
CRITICAL/HIGH. Findings can be synced into the central vuln register.

## 3. Draining the decision queue (the human loop)

The whole point of "always on" without losing control: a person (or a rota)
periodically clears decisions.

```bash
virgent --workdir /var/lib/virgent decisions
virgent --workdir /var/lib/virgent decide dec-abc123 approve --role responder
```

Wire your own notifier by tailing `audit.jsonl` for `decision.requested`
events (Slack/PagerDuty/email) — the `notify` response action is the intended
hook. Until an executor is configured, responses are dry-run, so approving is
safe to practice.

## 4. Durability & integrity (non-negotiable in an org)

- Put the workdir on **append-only / WORM storage**, and ship `audit.jsonl`
  and `provenance.jsonl` to immutable storage (S3 Object Lock, etc.).
- Keep `VIRGENT_AUDIT_KEY` in a **secret manager**, not on the monitored host,
  so an attacker who tampers with the log can't forge signatures.
- Periodically run `virgent audit verify` from a **separate** trusted host
  against the shipped logs; alert on any failure.

## 5. Fleet & central view

Two simple topologies today:

- **Fanned-out agents, synced state.** Each host runs `virgent watch` to its
  own workdir; sync those workdirs (or just the audit/provenance/register
  files) to a central bucket. Run `virgent posture` / `virgent report` there
  for the org-wide view.
- **Central collector.** Ship logs to one node (syslog/Fluent Bit) and run a
  single `virgent watch --log ...` there for SOC detection, plus per-host
  agents for host/runtime/FIM (which need local access).

## What's intentionally not here yet

Virgent is a CLI + service today, not a distributed platform. A built-in
daemon with log *tailing* (vs. re-ingesting a file each cycle), a central
API/console, native notifiers, and real response executors (firewall/EDR/IAM)
are the roadmap (see `CONTINUATION.md` §6). The loop re-ingests named logs
each cycle and dedups by stable identity, which is correct but not
offset-tracked — fine for steady auth/syslog volumes, and the natural next
step for high-volume sources.
