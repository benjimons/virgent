"""Virgent command-line interface.

    virgent init                         create workdir + default policy
    virgent ingest PATH [--git-history]  ingest a source tree (and git log)
    virgent scan [--capability NAME] [--online] [--approve PATTERN]
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


def cmd_scan(args) -> int:
    agent = _agent(args, with_provider=args.llm)
    for pattern in args.approve or []:
        agent.approve(pattern, Actor(id=f"cli:{getpass.getuser()}", type="human"))
    if args.online:
        agent.enable_online_dependency_checks()
    caps = args.capability or None
    findings = agent.scan(capabilities=caps)
    for f in sorted(findings, key=lambda f: f.severity.rank):
        print(f"[{f.severity.value.upper():8}] {f.id}  {f.title}  ({f.location})")
    print(f"\n{len(findings)} finding(s). Audit head: {agent.audit.head_hash[:16]}…")
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

    p_ingest = sub.add_parser("ingest", help="ingest a file, directory, or repo")
    p_ingest.add_argument("target")
    p_ingest.add_argument("--git-history", action="store_true", help="also ingest git commit history")

    p_scan = sub.add_parser("scan", help="run security capabilities over ingested evidence")
    p_scan.add_argument("--capability", action="append", help="run only this capability (repeatable)")
    p_scan.add_argument("--online", action="store_true", help="enable OSV vulnerability lookups (network)")
    p_scan.add_argument("--llm", action="store_true", help="enable the LLM review capability")
    p_scan.add_argument("--approve", action="append",
                        help="grant approval for a restricted action pattern, e.g. 'collect.web'")

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
        "ingest": cmd_ingest,
        "scan": cmd_scan,
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
