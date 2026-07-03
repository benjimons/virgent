"""Host inspection: ingestor (injected fakes) + capability rules + e2e."""
import pytest

from virgent.capabilities.host import (
    HostInspectionCapability,
    check_file_perms,
    check_firewall,
    check_listening,
    check_sshd,
    check_sysctl,
    check_users,
)
from virgent.engine import SecurityAgent
from virgent.ingest.host import ALLOWED_COMMANDS, HostIngestor, _default_runner
from virgent.models import Actor, Evidence, Severity

ACTOR = Actor(id="test", type="system")

SSHD_BAD = """\
# managed sshd
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
X11Forwarding yes
Protocol 1
"""

PASSWD = "root:x:0:0::/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
SHADOW = "root:$6$abc:1::::::\nguest::1::::::\n"

SS_OUTPUT = """# ss -tulnH
tcp   LISTEN 0 128 0.0.0.0:6379 0.0.0.0:*
tcp   LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*
tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
tcp   LISTEN 0 128 0.0.0.0:23 0.0.0.0:*
"""


def fake_host_ingestor():
    files = {
        "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04"\n',
        "/etc/ssh/sshd_config": SSHD_BAD,
        "/etc/passwd": PASSWD,
        "/etc/shadow": SHADOW,
        "/proc/sys/kernel/randomize_va_space": "0\n",
        "/proc/sys/net/ipv4/ip_forward": "1\n",
        "/proc/sys/net/ipv4/tcp_syncookies": "1\n",
    }
    commands = {
        ("ss", "-tulnH"): SS_OUTPUT,
        ("ufw", "status"): "Status: inactive\n",
    }
    stats = {
        "/etc/shadow": {"mode": "644", "owner": "root", "uid": 0},   # too permissive
        "/etc/passwd": {"mode": "644", "owner": "root", "uid": 0},
    }
    return HostIngestor(
        reader=lambda p: files.get(p),
        runner=lambda argv: commands.get(tuple(argv)),
        stat_fn=lambda p: stats.get(p),
        hostname="test-host",
    )


# -- ingestor safety ----------------------------------------------------------

def test_default_runner_refuses_non_allowlisted_command():
    assert _default_runner(["rm", "-rf", "/"]) is None
    assert ("ss", "-tulnH") in ALLOWED_COMMANDS


def test_ingestor_collects_facts_with_provenance_metadata():
    items = list(fake_host_ingestor().collect())
    facts = {i.metadata["fact"] for i in items}
    assert {"os-release", "sshd_config", "users", "sysctl", "listening", "firewall", "file-perms"} <= facts
    for i in items:
        assert i.kind == "host-fact"
        assert i.source.startswith("host:test-host:")
        assert i.metadata["host"] == "test-host"


def test_ingestor_survives_missing_sources():
    ing = HostIngestor(reader=lambda p: None, runner=lambda a: None, stat_fn=lambda p: None)
    assert list(ing.collect()) == []


# -- rule units ---------------------------------------------------------------

def test_sshd_rules():
    rules = {i["rule"] for i in check_sshd(SSHD_BAD)}
    assert {"ssh-permit-root-login", "ssh-password-auth", "ssh-permit-empty-passwords",
            "ssh-protocol-1", "ssh-x11-forwarding"} <= rules
    empty = [i for i in check_sshd(SSHD_BAD) if i["rule"] == "ssh-permit-empty-passwords"]
    assert empty[0]["severity"] == Severity.CRITICAL


def test_user_rules_detect_uid0_and_empty_password():
    content = f"# /etc/passwd\n{PASSWD}# /etc/shadow\n{SHADOW}"
    issues = check_users(content)
    rules = {i["rule"] for i in issues}
    assert "account-uid0-nonroot" in rules   # 'backdoor' has UID 0
    assert "account-empty-password" in rules  # 'guest' has empty password
    assert all(i["severity"] == Severity.CRITICAL for i in issues)


def test_sysctl_rules_flag_deviations():
    content = "kernel.randomize_va_space = 0\nnet.ipv4.ip_forward = 1\nnet.ipv4.tcp_syncookies = 1"
    rules = {i["rule"] for i in check_sysctl(content)}
    assert "sysctl-kernel.randomize_va_space" in rules
    assert "sysctl-net.ipv4.ip_forward" in rules
    assert "sysctl-net.ipv4.tcp_syncookies" not in rules  # value is correct


def test_firewall_inactive():
    assert check_firewall("Status: inactive")
    assert check_firewall("Status: active") == []


def test_listening_flags_exposed_sensitive_services_only():
    issues = check_listening(SS_OUTPUT)
    rules = {i["rule"] for i in issues}
    assert "exposed-service-redis" in rules       # 0.0.0.0:6379
    assert "exposed-service-telnet" in rules      # 0.0.0.0:23
    assert "exposed-service-postgresql" not in rules  # bound to 127.0.0.1
    telnet = [i for i in issues if i["rule"] == "exposed-service-telnet"]
    assert telnet[0]["severity"] == Severity.CRITICAL


def test_file_perm_rules():
    content = "/etc/shadow mode=644 owner=root\n/etc/passwd mode=666 owner=root"
    rules = {i["rule"] for i in check_file_perms(content)}
    assert "perm-shadow-exposed" in rules   # shadow world-readable
    assert "perm-world-writable" in rules   # passwd world-writable


# -- capability + engine e2e --------------------------------------------------

def test_capability_maps_controls():
    ev = Evidence(id="ev-1", source="host:h:sshd_config", kind="host-fact",
                  content=SSHD_BAD, sha256="0" * 64,
                  collected_at="2026-01-01T00:00:00+00:00",
                  metadata={"fact": "sshd_config", "host": "h"})
    findings = HostInspectionCapability().analyze([ev])
    assert findings
    all_controls = {c for f in findings for c in f.controls}
    assert "CIS:5.2" in all_controls
    assert "NIST:AC-6" in all_controls


def test_engine_host_pipeline(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    agent.ingestors["host"] = fake_host_ingestor()   # inject fakes
    evidence = agent.ingest("localhost", ingestor="host")
    assert evidence and all(e.kind == "host-fact" for e in evidence)

    findings = agent.scan(capabilities=["host"])
    rules = {f.metadata["rule"] for f in findings}
    assert "ssh-permit-empty-passwords" in rules
    assert "account-uid0-nonroot" in rules
    assert "firewall-inactive" in rules
    assert "exposed-service-redis" in rules

    # the collection action was audited as collect.host and the chain verifies
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "collect.host" in actions
    assert "scan.host" in actions
    assert agent.verify_audit().ok

    report = agent.report(fmt="markdown")
    assert "CIS" in report
