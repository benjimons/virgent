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


def cmd_discover(args) -> int:
    agent = _agent(args)
    human = Actor(id=f"cli:{getpass.getuser()}", type="human")
    if args.network:
        agent.approve("discover.network", human)
    if args.cloud:
        agent.approve("discover.cloud", human)
    if args.ingest or args.cloud:
        summary = agent.autodiscover(network=args.network, cloud=args.cloud)
        print(f"discovered {summary['targets']} local target(s); "
              f"ingested {summary['ingested']}, inventoried {summary['inventory']}, "
              f"cloud resources {summary['cloud_resources']}")
        return 0
    targets = agent.discover(network=args.network)
    for t in targets:
        print(f"  [{t.sensitivity:7}] {t.kind:8} {t.locator}"
              + ("  (git)" if t.metadata.get("git") else ""))
    print(f"\n{len(targets)} target(s) discovered.")
    return 0


def cmd_auto(args) -> int:
    """Fully autonomous: discover assets, ingest, scan everything, detect, report."""
    agent = _agent(args, with_provider=args.llm)
    for pattern in args.approve or []:
        agent.approve(pattern, Actor(id=f"cli:{getpass.getuser()}", type="human"))
    summary = agent.autodiscover(network=args.network, cloud=args.cloud)
    print(f"discovered {summary['targets']} local asset(s); "
          f"ingested {summary['ingested']}, inventoried {summary['inventory']}, "
          f"cloud resources {summary['cloud_resources']}")
    if args.online:
        agent.enable_online_dependency_checks()
    findings = agent.scan()
    _, incidents = agent.soc_detect()
    _print_findings(findings)
    print(f"\n{len(findings)} finding(s), {len(incidents)} incident(s) "
          f"across {len(agent.provenance.all_ids())} evidence items.")
    if args.output:
        Path(args.output).write_text(agent.report(fmt=args.format), encoding="utf-8")
        print(f"wrote report: {args.output}")
    verify = agent.verify_audit()
    print(f"audit chain verified: {verify.ok} (head {agent.audit.head_hash[:16]}…)")
    return 0 if verify.ok else 1


def cmd_watch(args) -> int:
    import time
    agent = _agent(args)
    seen_findings: set[str] = set()
    seen_incidents: set[str] = set()
    rounds = 0
    caps = args.capability or ["host", "runtime"]
    logs = args.log or []
    print(f"watching {agent.ingestors['runtime'].hostname} every {args.interval}s "
          f"(caps={','.join(caps)}"
          + (f", logs={len(logs)}" if logs else "")
          + (", auto-discover" if args.discover else "")
          + f"; {'forever' if not args.rounds else str(args.rounds) + ' round(s)'}); Ctrl-C to stop")
    try:
        while True:
            rounds += 1
            cycle = agent.monitor_cycle(capabilities=caps, log_sources=logs, discover=args.discover)
            new_f = [f for f in cycle["findings"] if f.fingerprint not in seen_findings]
            for f in new_f:
                seen_findings.add(f.fingerprint)
            new_i = [i for i in cycle["incidents"]
                     if i.id not in seen_incidents and i.status not in ("resolved",)]
            for i in new_i:
                seen_incidents.add(i.id)
            if new_f or new_i:
                print(f"\n[tick {rounds}] {len(new_f)} new finding(s), {len(new_i)} new incident(s):")
                _print_findings(new_f)
                for i in new_i:
                    print(f"  INCIDENT [{i.priority}] {i.severity.value.upper()} {i.id}  {i.title}")
                pend = agent.pending_decisions()
                if pend:
                    print(f"  {len(pend)} decision(s) awaiting a human: virgent decisions")
            else:
                print(f"[tick {rounds}] clear (audit head {agent.audit.head_hash[:12]}…)")
            if args.rounds and rounds >= args.rounds:
                break
            if args.interval > 0:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


def _parse_target(spec: str) -> dict:
    """host or host:port,port,..."""
    if ":" in spec:
        host, _, ports = spec.partition(":")
        return {"host": host, "ports": [int(p) for p in ports.split(",") if p.strip()]}
    return {"host": spec}


def cmd_pentest(args) -> int:
    agent = _agent(args)
    approver = Actor(id=f"cli:{getpass.getuser()}", type="human")
    if args.authorize:
        agent.approve("pentest.*", approver)
    targets = [_parse_target(t) for t in args.target]
    findings = agent.pentest(targets)
    _print_findings(findings)
    print(f"\n{len(findings)} verified finding(s) from active probing.")
    return 0


def cmd_vulns(args) -> int:
    agent = _agent(args)
    if args.vulns_command == "sync":
        summary = agent.sync_vulns()
        print(f"register: +{summary['added']} new, {summary['reobserved']} re-observed, "
              f"{summary['reopened']} reopened, {summary['total']} total")
        return 0
    if args.vulns_command == "summary":
        s = agent.vulns.summary()
        print(json.dumps(s, indent=2))
        return 0
    if args.vulns_command == "list":
        entries = agent.vulns.entries(status=args.status, open_only=args.open)
        for e in entries:
            print(f"[risk {e.risk:3}] {e.status:13} {e.fingerprint}  "
                  f"{e.finding['severity']:8} {e.finding['title']}")
        print(f"\n{len(entries)} entr(y/ies).")
        return 0
    if args.vulns_command == "status":
        entry = agent.set_vuln_status(args.fingerprint, args.state, note=args.note or "")
        print(f"{args.fingerprint} -> {entry['status']}")
        return 0
    return 2


def cmd_soc(args) -> int:
    from .access import EscalationRequired
    agent = _agent(args, with_provider=getattr(args, "llm", False))
    if args.soc_command == "detect":
        alerts, incidents = agent.soc_detect()
        print(f"{len(alerts)} alert(s), {len(incidents)} incident(s):")
        for inc in incidents:
            print(f"  [{inc.priority}] {inc.severity.value.upper():8} {inc.id}  "
                  f"{inc.title}  entities={inc.entities}")
        return 0
    if args.soc_command == "list":
        for inc in agent.soc.casebook.all_incidents():
            print(f"[{inc.priority}] {inc.status:10} {inc.severity.value.upper():8} "
                  f"{inc.id}  {inc.title}")
        return 0
    if args.soc_command == "show":
        inc = agent.soc.casebook.get_incident(args.incident)
        print(json.dumps(inc.to_dict(), indent=2, default=str))
        return 0
    if args.soc_command == "triage":
        inc = agent.soc_triage(args.incident)
        print(f"{inc.id} -> {inc.status} ({inc.priority})")
        print(inc.summary)
        return 0
    if args.soc_command == "plan":
        for step in agent.soc_plan(args.incident):
            print(f"  {step['action']:16} [{step['sensitivity']}]  {step['description']}  {step['params']}")
        return 0
    if args.soc_command == "respond":
        try:
            entry = agent.soc_respond(args.incident, args.action)
            print(f"{args.action}: {entry['result'].get('status')} — {entry['result'].get('detail', '')}")
            return 0
        except EscalationRequired as e:
            req = e.request
            print(f"human decision required: {req.id}")
            print(f"  action={req.action} sensitivity={req.sensitivity} "
                  f"needs role >= {req.required_role}")
            print(f"  resolve with: virgent decide {req.id} approve --role {req.required_role}")
            return 4
    return 2


def cmd_notify(args) -> int:
    agent = _agent(args)
    if args.notify_command == "test":
        results = agent.notify_test()
        if not results:
            print("no channels configured (see the 'notify' block in policy.yaml)")
        for r in results:
            print(f"  {r.get('channel', '?'):8} -> {r.get('status')}"
                  + (f"  ({r.get('detail')})" if r.get("detail") else ""))
        return 0
    return 2


def cmd_decisions(args) -> int:
    agent = _agent(args)
    pending = agent.pending_decisions()
    for r in pending:
        print(f"{r['id']}  {r['action']}  sensitivity={r['sensitivity']}  "
              f"needs>={r['required_role']}  ctx={r.get('context', {})}")
    print(f"\n{len(pending)} pending decision(s).")
    return 0


def cmd_decide(args) -> int:
    agent = _agent(args)
    resolver = f"cli:{getpass.getuser()}"
    result = agent.resolve_decision(args.decision_id, args.decision,
                                    resolver=resolver, role=args.role, note=args.note or "")
    print(f"{args.decision_id} -> {result['status']}"
          + (f" (escalated: role '{args.role}' below required '{result['required_role']}')"
             if result["status"] == "pending" else ""))
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


def cmd_org(args) -> int:
    from .org import FUNCTIONS, RACI, ROLES, RUNBOOKS, TEAMS, escalation_chain
    if args.org_command == "overview":
        print("Security organization (NIST CSF-aligned):\n")
        for code, fn in FUNCTIONS.items():
            print(f"  {code} {fn.name:10} owner={TEAMS[fn.owning_team].name}")
            print(f"       {fn.outcome}")
            print(f"       capabilities: {', '.join(fn.capabilities)}")
        return 0
    if args.org_command == "teams":
        for t in TEAMS.values():
            print(f"{t.name} ({', '.join(t.functions)}) — {t.mission}")
            print(f"  roles: {', '.join(t.roles)}")
        return 0
    if args.org_command == "roles":
        for r in ROLES.values():
            print(f"{r.title} [access={r.access_role}]"
                  + (f" -> {r.reports_to}" if r.reports_to else ""))
            for resp in r.responsibilities:
                print(f"  - {resp}")
        return 0
    if args.org_command == "raci":
        for fn, assign in RACI.items():
            print(f"{fn}: " + ", ".join(f"{role}={ra}" for role, ra in assign.items()))
        return 0
    if args.org_command == "escalation":
        print("escalation chain:", " -> ".join(escalation_chain("agent")))
        return 0
    if args.org_command == "runbook":
        if args.name and args.name in RUNBOOKS:
            rb = RUNBOOKS[args.name]
            print(f"# {rb['title']}  (owner: {rb['owner']})")
            print(f"triggers: {', '.join(rb['triggers'])}")
            print(f"controls: {', '.join(rb['controls'])}")
            for i, step in enumerate(rb["steps"], 1):
                print(f"  {i}. {step}")
        else:
            for name, rb in RUNBOOKS.items():
                print(f"  {name:24} {rb['title']}")
        return 0
    return 2


def cmd_posture(args) -> int:
    agent = _agent(args)
    posture = agent.program_posture()
    print(f"Security program maturity: {posture['maturity_score']}/100 "
          f"({posture['maturity_band']})")
    print(f"CSF functions covered: {posture['csf_functions_covered']}/6")
    for code, info in posture["org"].items():
        mark = "✓" if info["covered"] else "·"
        print(f"  {mark} {code} {info['function']:10} ({info['owning_team']})")
    ops = posture["operations"]
    print(f"\ncontrols with evidence: {posture['controls_with_evidence']} "
          f"across {len(posture['frameworks_touched'])} frameworks")
    print(f"open vulnerabilities: {ops['open_vulnerabilities']}")
    print(f"open incidents: {ops['open_incidents']} | "
          f"pending decisions: {ops['pending_decisions']} | "
          f"audit verified: {ops['audit_chain_verified']}")
    return 0


def cmd_frameworks(args) -> int:
    from .compliance.frameworks import CONTROLS, framework_size, frameworks
    print(f"{len(CONTROLS)} controls across {len(frameworks())} frameworks:\n")
    for fw in frameworks():
        print(f"  {fw:18} {framework_size(fw):4} controls")
    if args.framework:
        print(f"\nControls for {args.framework}:")
        for cid, meta in sorted(CONTROLS.items()):
            if meta["framework"] == args.framework:
                print(f"  {cid:24} {meta['title']}")
    return 0


def cmd_ccm(args) -> int:
    agent = _agent(args)
    result = agent.ccm_assess()
    s = result["summary"]
    if args.ccm_command == "summary":
        print(f"controls monitored: {s['controls_monitored']}  "
              f"compliance: {s['compliance_pct']}%")
        print(f"  by status: {s['by_status']}")
        if s["overdue"]:
            print(f"  OVERDUE ({len(s['overdue'])}): {', '.join(s['overdue'])}")
        return 0
    # default / list: show each control
    for r in sorted(result["results"], key=lambda r: (r["status"] != "fail", r["control_id"])):
        mark = {"fail": "✗", "pass": "✓", "not_assessed": "·"}.get(r["status"], "?")
        due = f"  due {r['due_at'][:10]}" if r["due_at"] else ""
        over = "  OVERDUE" if r.get("overdue") else ""
        print(f"  {mark} {r['control_id']:18} [{r['status']:12}] owner={r['owner']:22}"
              f" {r['title'][:40]}{due}{over}")
    print(f"\ncompliance: {s['compliance_pct']}%  ({s['by_status']})")
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
    p_fw = sub.add_parser("frameworks", help="show the compliance control catalog")
    p_fw.add_argument("--framework", help="list all controls for one framework")

    p_org = sub.add_parser("org", help="the security organization: functions, teams, roles, runbooks")
    org_sub = p_org.add_subparsers(dest="org_command", required=True)
    org_sub.add_parser("overview", help="CSF functions and owning teams")
    org_sub.add_parser("teams", help="teams and their missions")
    org_sub.add_parser("roles", help="roles and responsibilities")
    org_sub.add_parser("raci", help="RACI matrix by function")
    org_sub.add_parser("escalation", help="the escalation chain")
    p_rb = org_sub.add_parser("runbook", help="show a runbook (or list all)")
    p_rb.add_argument("name", nargs="?", default=None)

    sub.add_parser("posture", help="security-program posture (CSF coverage + live state)")

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

    p_discover = sub.add_parser("discover", help="autonomously find assets to secure (repos, logs, host; scoped network; cloud)")
    p_discover.add_argument("--network", action="store_true", help="also sweep the policy network_scope (approval-gated)")
    p_discover.add_argument("--cloud", action="store_true", help="enumerate cloud resources via read-only credentials (approval-gated)")
    p_discover.add_argument("--ingest", action="store_true", help="ingest each discovered target immediately")

    p_auto = sub.add_parser("auto", help="fully autonomous: discover + ingest + scan + detect + report")
    p_auto.add_argument("--network", action="store_true", help="include scoped network discovery")
    p_auto.add_argument("--cloud", action="store_true", help="include cloud posture (CSPM) discovery")
    p_auto.add_argument("--online", action="store_true", help="enable OSV vulnerability lookups")
    p_auto.add_argument("--llm", action="store_true", help="enable the LLM review capability")
    p_auto.add_argument("--approve", action="append", help="grant approval for a restricted action")
    p_auto.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_auto.add_argument("-o", "--output", default=None, help="write the report to a file")

    p_watch = sub.add_parser("watch", help="continuously monitor the live system, alerting on new findings")
    p_watch.add_argument("--interval", type=int, default=60, help="seconds between ticks (default 60)")
    p_watch.add_argument("--rounds", type=int, default=0, help="stop after N ticks (default: run forever)")
    p_watch.add_argument("--capability", action="append", help="capabilities to run each tick")
    p_watch.add_argument("--log", action="append", help="log file to tail + run SOC detection each tick (repeatable, offset-tracked)")
    p_watch.add_argument("--discover", action="store_true", help="auto-discover new assets each tick")

    p_notify = sub.add_parser("notify", help="notification channels (decisions, incidents)")
    notify_sub = p_notify.add_subparsers(dest="notify_command", required=True)
    notify_sub.add_parser("test", help="send a test notification through every configured channel")

    p_soc = sub.add_parser("soc", help="security operations: detect, triage, respond to incidents")
    soc_sub = p_soc.add_subparsers(dest="soc_command", required=True)
    p_sd = soc_sub.add_parser("detect", help="run detection + correlation over ingested logs")
    p_sd.add_argument("--llm", action="store_true", help="enable LLM-assisted triage later")
    soc_sub.add_parser("list", help="list incidents")
    p_ss = soc_sub.add_parser("show", help="show an incident")
    p_ss.add_argument("incident")
    p_st = soc_sub.add_parser("triage", help="triage an incident (LLM if --llm and key set)")
    p_st.add_argument("incident")
    p_st.add_argument("--llm", action="store_true")
    p_sp = soc_sub.add_parser("plan", help="show the recommended response plan for an incident")
    p_sp.add_argument("incident")
    p_sr = soc_sub.add_parser("respond", help="execute a response action (autonomy/approval gated)")
    p_sr.add_argument("incident")
    p_sr.add_argument("--action", required=True)

    p_dec = sub.add_parser("decisions", help="list pending human decisions")

    p_decide = sub.add_parser("decide", help="approve/deny a pending decision (human-in-the-loop)")
    p_decide.add_argument("decision_id")
    p_decide.add_argument("decision", choices=["approve", "deny"])
    p_decide.add_argument("--role", default="responder", help="your role in the access chain")
    p_decide.add_argument("--note", default="")

    p_pentest = sub.add_parser("pentest", help="authorized, non-destructive active probing (scope-gated)")
    p_pentest.add_argument("target", nargs="+", help="host or host:port,port (must be in policy pentest.scope)")
    p_pentest.add_argument("--authorize", action="store_true",
                          help="record your approval for pentest.* for this run")

    p_vulns = sub.add_parser("vulns", help="vulnerability management register")
    vsub = p_vulns.add_subparsers(dest="vulns_command", required=True)
    vsub.add_parser("sync", help="merge current findings into the register")
    vsub.add_parser("summary", help="register summary (counts, risk, overdue)")
    p_vl = vsub.add_parser("list", help="list register entries by risk")
    p_vl.add_argument("--status", help="filter by lifecycle status")
    p_vl.add_argument("--open", action="store_true", help="show only open/acknowledged")
    p_vs = vsub.add_parser("status", help="set the lifecycle status of an entry")
    p_vs.add_argument("fingerprint")
    p_vs.add_argument("state", choices=sorted(["open", "acknowledged", "resolved", "accepted", "false_positive"]))
    p_vs.add_argument("--note", default="")

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

    p_ccm = sub.add_parser("ccm", help="continuous control monitoring: per-control pass/fail + SLA")
    ccm_sub = p_ccm.add_subparsers(dest="ccm_command")
    ccm_sub.add_parser("list", help="show each monitored control's status (default)")
    ccm_sub.add_parser("summary", help="compliance summary + overdue controls")

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
        "frameworks": cmd_frameworks,
        "org": cmd_org,
        "posture": cmd_posture,
        "ingest": cmd_ingest,
        "discover": cmd_discover,
        "auto": cmd_auto,
        "host": cmd_host,
        "runtime": cmd_runtime,
        "fim": cmd_fim,
        "watch": cmd_watch,
        "notify": cmd_notify,
        "pentest": cmd_pentest,
        "vulns": cmd_vulns,
        "soc": cmd_soc,
        "decisions": cmd_decisions,
        "decide": cmd_decide,
        "scan": cmd_scan,
        "assess": cmd_assess,
        "ccm": cmd_ccm,
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
