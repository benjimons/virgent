"""Virgent command-line interface.

    virgent init                         create workdir + default policy
    virgent list                         show all ingestors, capabilities, frameworks
    virgent ingest PATH [--git-history]  ingest a source tree (and git log)
    virgent host [--scan]                inspect the running host (read-only)
    virgent runtime [--scan]             capture live-system state (procs/conns/sessions/services)
    virgent fim baseline PATH... | check file integrity monitoring
    virgent watch [--interval N] [--rounds N]  continuous live-system monitoring
    virgent scan [--capability NAME] [--online] [--llm] [--approve PATTERN]
    virgent assess [PATH] [--host] [--runtime] [--git-history] [--online] [--llm] [-o FILE]
    virgent report [--format markdown|json] [-o FILE]
    virgent audit verify | export
    virgent ask "question"               policy-gated LLM query (needs API key)
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .engine import SecurityAgent
from .models import Actor
from .policy import PolicyViolation, write_default_policy


def _agent(args, with_provider: bool = False) -> SecurityAgent:
    policy_path = Path(args.policy) if args.policy else Path(args.workdir) / "policy.yaml"
    policy = str(policy_path) if policy_path.exists() else None
    provider = None
    if with_provider:
        from .llm.provider import AnthropicProvider
        provider = AnthropicProvider()
    actor = Actor(id=f"cli:{getpass.getuser()}", type="human")
    return SecurityAgent(workdir=args.workdir, policy=policy, actor=actor, provider=provider)


def cmd_init(args) -> int:
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    policy_path = workdir / "policy.yaml"
    if not policy_path.exists():
        write_default_policy(policy_path)
        print(f"wrote default policy: {policy_path}")
    agent = _agent(args)
    print(f"initialized workdir: {agent.workdir} (audit head {agent.audit.head_hash[:16]}…)")
    return 0


def cmd_ingest(args) -> int:
    agent = _agent(args)
    evidence = agent.ingest(args.target, ingestor="file")
    print(f"ingested {len(evidence)} file items from {args.target}")
    if args.git_history:
        commits = agent.ingest(args.target, ingestor="git")
        print(f"ingested {len(commits)} commits from git history")
    return 0


def _print_findings(findings) -> None:
    for f in sorted(findings, key=lambda f: f.severity.rank):
        print(f"[{f.severity.value.upper():8}] {f.id}  {f.title}  ({f.location})")


def cmd_host(args) -> int:
    agent = _agent(args)
    evidence = agent.ingest("localhost", ingestor="host")
    print(f"collected {len(evidence)} host fact(s) from {agent.ingestors['host'].hostname}")
    if args.scan:
        findings = agent.scan(capabilities=["host"])
        _print_findings(findings)
        print(f"\n{len(findings)} host finding(s). Audit head: {agent.audit.head_hash[:16]}…")
    return 0


def cmd_runtime(args) -> int:
    agent = _agent(args)
    evidence = agent.ingest("localhost", ingestor="runtime")
    print(f"captured {len(evidence)} runtime snapshot(s) from {agent.ingestors['runtime'].hostname}")
    if args.scan:
        findings = agent.scan(capabilities=["runtime"])
        _print_findings(findings)
        print(f"\n{len(findings)} runtime finding(s). Audit head: {agent.audit.head_hash[:16]}…")
    return 0


def cmd_fim(args) -> int:
    agent = _agent(args)
    if args.fim_command == "baseline":
        summary = agent.integrity_baseline(args.paths)
        print(f"baselined {summary['recorded']} file(s); watching {summary['total']} total")
        if summary["missing"]:
            print(f"(unreadable/missing: {', '.join(summary['missing'])})")
        return 0
    if args.fim_command == "check":
        findings = agent.integrity_check()
        _print_findings(findings)
        print(f"\n{len(findings)} integrity change(s) across {len(agent.integrity.watched)} watched file(s).")
        return 0 if not findings else 1
    return 2


def cmd_watch(args) -> int:
    import time
    agent = _agent(args)
    seen: set[str] = set()
    rounds = 0
    print(f"watching {agent.ingestors['runtime'].hostname} every {args.interval}s "
          f"({'forever' if not args.rounds else str(args.rounds) + ' round(s)'}); Ctrl-C to stop")
    try:
        while True:
            rounds += 1
            findings = agent.monitor_tick(capabilities=args.capability or ["host", "runtime"])
            new = [f for f in findings if f.fingerprint not in seen]
            for f in new:
                seen.add(f.fingerprint)
            ts = findings[0].created_at if findings else ""
            if new:
                print(f"\n[tick {rounds}] {len(new)} new finding(s):")
                _print_findings(new)
            else:
                print(f"[tick {rounds}] no new findings (audit head {agent.audit.head_hash[:12]}…)")
            if args.rounds and rounds >= args.rounds:
                break
            if args.interval > 0:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


def cmd_scan(args) -> int:
    agent = _agent(args, with_provider=args.llm)
    for pattern in args.approve or []:
        agent.approve(pattern, Actor(id=f"cli:{getpass.getuser()}", type="human"))
    if args.online:
        agent.enable_online_dependency_checks()
    caps = args.capability or None
    findings = agent.scan(capabilities=caps)
    _print_findings(findings)
    print(f"\n{len(findings)} finding(s). Audit head: {agent.audit.head_hash[:16]}…")
    return 0


def cmd_assess(args) -> int:
    """Full pipeline: ingest a target + git history + host, scan everything, report."""
    import os
    agent = _agent(args, with_provider=args.llm)
    for pattern in args.approve or []:
        agent.approve(pattern, Actor(id=f"cli:{getpass.getuser()}", type="human"))
    if args.target:
        agent.ingest(args.target)
        if args.git_history:
            try:
                agent.ingest(args.target, ingestor="git")
            except Exception as e:  # noqa: BLE001 - non-repo targets are fine
                print(f"(skipping git history: {e})")
    if args.host:
        agent.ingest("localhost", ingestor="host")
    if args.runtime:
        agent.ingest("localhost", ingestor="runtime")
    if args.online:
        agent.enable_online_dependency_checks()
    findings = agent.scan()
    _print_findings(findings)
    print(f"\n{len(findings)} finding(s) across {len(agent.provenance.all_ids())} evidence items.")
    out = args.output or None
    rendered = agent.report(fmt=args.format)
    if out:
        from pathlib import Path
        Path(out).write_text(rendered, encoding="utf-8")
        print(f"wrote report: {out}")
    verify = agent.verify_audit()
    print(f"audit chain verified: {verify.ok} (head {agent.audit.head_hash[:16]}…)")
    return 0 if verify.ok else 1


def cmd_list(args) -> int:
    from .compliance.frameworks import CONTROLS, frameworks
    agent = _agent(args)
    print("Ingestors (sources the agent can consume):")
    for name, ing in sorted(agent.ingestors.items()):
        print(f"  - {name:8} {ing.__class__.__name__}")
    print("\nCapabilities (analyses that produce findings):")
    for name, cap in sorted(agent.capabilities.items()):
        print(f"  - {name:12} {cap.description}")
    if "host" not in agent.capabilities:
        pass
    print("\nCompliance frameworks covered:")
    for fw in frameworks():
        n = sum(1 for c in CONTROLS.values() if c["framework"] == fw)
        print(f"  - {fw:14} ({n} controls)")
    print("\nNote: the LLM review capability requires a reasoning provider "
          "(run scans with --llm and set ANTHROPIC_API_KEY).")
    return 0


def cmd_report(args) -> int:
    agent = _agent(args)
    rendered = agent.report(fmt=args.format)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"wrote report: {args.output}")
    else:
        print(rendered)
    return 0


def cmd_audit(args) -> int:
    agent = _agent(args)
    if args.audit_command == "verify":
        result = agent.verify_audit()
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.ok else 1
    if args.audit_command == "export":
        for rec in agent.audit.iter_records():
            print(json.dumps(rec, ensure_ascii=False))
        return 0
    return 2


def cmd_ask(args) -> int:
    agent = _agent(args, with_provider=True)
    result = agent.reason(
        prompt=args.question,
        system="You are a security analyst assistant inside an audited enterprise environment. "
               "Be precise; cite what you would need to verify claims.",
        purpose="cli.ask",
    )
    print(result.text)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="virgent", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workdir", default=".virgent", help="agent state directory (default: .virgent)")
    parser.add_argument("--policy", default=None, help="policy YAML (default: <workdir>/policy.yaml)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize workdir and default policy")
    sub.add_parser("list", help="list all ingestors, capabilities, and frameworks")

    p_ingest = sub.add_parser("ingest", help="ingest a file, directory, or repo")
    p_ingest.add_argument("target")
    p_ingest.add_argument("--git-history", action="store_true", help="also ingest git commit history")

    p_host = sub.add_parser("host", help="inspect the running host (read-only hardening review)")
    p_host.add_argument("--scan", action="store_true", help="also run the host capability immediately")

    p_runtime = sub.add_parser("runtime", help="capture live-system state (processes, connections, sessions, services)")
    p_runtime.add_argument("--scan", action="store_true", help="also run the runtime threat capability")

    p_fim = sub.add_parser("fim", help="file integrity monitoring")
    fim_sub = p_fim.add_subparsers(dest="fim_command", required=True)
    p_fim_base = fim_sub.add_parser("baseline", help="record known-good hashes for files")
    p_fim_base.add_argument("paths", nargs="+")
    fim_sub.add_parser("check", help="detect changes vs the baseline")

    p_watch = sub.add_parser("watch", help="continuously monitor the live system, alerting on new findings")
    p_watch.add_argument("--interval", type=int, default=60, help="seconds between ticks (default 60)")
    p_watch.add_argument("--rounds", type=int, default=0, help="stop after N ticks (default: run forever)")
    p_watch.add_argument("--capability", action="append", help="capabilities to run each tick")

    p_scan = sub.add_parser("scan", help="run security capabilities over ingested evidence")
    p_scan.add_argument("--capability", action="append", help="run only this capability (repeatable)")
    p_scan.add_argument("--online", action="store_true", help="enable OSV vulnerability lookups (network)")
    p_scan.add_argument("--llm", action="store_true", help="enable the LLM review capability")
    p_scan.add_argument("--approve", action="append",
                        help="grant approval for a restricted action pattern, e.g. 'collect.web'")

    p_assess = sub.add_parser("assess", help="full pipeline: ingest + host + scan + report")
    p_assess.add_argument("target", nargs="?", default=None, help="path/repo to assess (optional)")
    p_assess.add_argument("--host", action="store_true", help="also inspect the running host")
    p_assess.add_argument("--runtime", action="store_true", help="also capture live-system state")
    p_assess.add_argument("--git-history", action="store_true", help="also ingest git history of target")
    p_assess.add_argument("--online", action="store_true", help="enable OSV vulnerability lookups")
    p_assess.add_argument("--llm", action="store_true", help="enable the LLM review capability")
    p_assess.add_argument("--approve", action="append", help="grant approval for a restricted action")
    p_assess.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_assess.add_argument("-o", "--output", default=None, help="write the report to a file")

    p_report = sub.add_parser("report", help="generate an auditor-ready report")
    p_report.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_report.add_argument("-o", "--output", default=None)

    p_audit = sub.add_parser("audit", help="audit log operations")
    p_audit.add_argument("audit_command", choices=["verify", "export"])

    p_ask = sub.add_parser("ask", help="ask the reasoning model a question (audited)")
    p_ask.add_argument("question")

    args = parser.parse_args(argv)
    handlers = {
        "init": cmd_init,
        "list": cmd_list,
        "ingest": cmd_ingest,
        "host": cmd_host,
        "runtime": cmd_runtime,
        "fim": cmd_fim,
        "watch": cmd_watch,
        "scan": cmd_scan,
        "assess": cmd_assess,
        "report": cmd_report,
        "audit": cmd_audit,
        "ask": cmd_ask,
    }
    try:
        return handlers[args.command](args)
    except PolicyViolation as e:
        print(f"policy violation: {e}", file=sys.stderr)
        if e.decision.effect == "require_approval":
            print("hint: re-run with --approve '<action-pattern>' to record a human approval",
                  file=sys.stderr)
        return 3
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
