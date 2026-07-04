"""Autonomous asset discovery: finders, scope gating, engine autodiscover."""
import pytest

from virgent.discovery import AssetDiscoverer, Target, _in_scope
from virgent.engine import SecurityAgent
from virgent.models import Actor
from virgent.policy import PolicyEngine, PolicyViolation

ACTOR = Actor(id="test", type="system")


def fake_discoverer(repos=(), logs=(), scope=(), sweep=None):
    return AssetDiscoverer(
        roots=["/x"], log_globs=["/y/*.log"], network_scope=list(scope),
        repo_finder=lambda roots: list(repos),
        log_finder=lambda globs: list(logs),
        sweeper=sweep or (lambda cidr, ports: []),
    )


def test_local_discovery_lists_host_repos_logs():
    d = fake_discoverer(repos=["/x/app"], logs=["/y/auth.log"])
    targets = d.discover_local()
    kinds = {(t.kind, t.ingestor) for t in targets}
    assert ("host", "host") in kinds
    assert ("runtime", "runtime") in kinds
    assert ("repo", "file") in kinds
    assert ("log", "tail") in kinds
    repo = next(t for t in targets if t.kind == "repo")
    assert repo.sensitivity == "observe"
    assert repo.metadata.get("git") is True


def test_network_discovery_is_scope_limited():
    swept = []
    def sweeper(cidr, ports):
        swept.append(cidr)
        return [("10.0.0.5", 6379), ("10.0.0.6", 5432)]
    d = fake_discoverer(scope=["10.0.0.0/24"], sweep=sweeper)
    targets = d.discover_network()
    assert swept == ["10.0.0.0/24"]
    assert {t.locator for t in targets} == {"10.0.0.5:6379", "10.0.0.6:5432"}
    assert all(t.sensitivity == "active" for t in targets)


def test_network_discovery_drops_out_of_scope_results():
    # a misbehaving sweeper returns a host outside the declared scope
    d = fake_discoverer(scope=["10.0.0.0/24"],
                        sweep=lambda cidr, ports: [("8.8.8.8", 53), ("10.0.0.9", 22)])
    targets = d.discover_network()
    assert {t.locator for t in targets} == {"10.0.0.9:22"}  # 8.8.8.8 rejected


def test_in_scope_matches_cidr_suffix_and_exact():
    assert _in_scope("10.0.0.5", ["10.0.0.0/24"])
    assert _in_scope("db.corp.internal", [".corp.internal"])
    assert _in_scope("host1", ["host1"])
    assert not _in_scope("9.9.9.9", ["10.0.0.0/24"])


def test_engine_discover_local_is_autonomous_and_audited(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    agent.discoverer = fake_discoverer(repos=[], logs=[])
    targets = agent.discover(network=False)
    assert any(t.kind == "host" for t in targets)
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "discover.local" in actions


def test_engine_network_discovery_requires_approval(tmp_path):
    policy = PolicyEngine()  # default: discover.network requires approval
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    agent.discoverer = fake_discoverer(scope=["10.0.0.0/24"],
                                       sweep=lambda c, p: [("10.0.0.5", 22)])
    with pytest.raises(PolicyViolation):
        agent.discover(network=True)
    # after approval it proceeds and records inventory
    agent.approve("discover.network", Actor(id="alice", type="human"))
    targets = agent.discover(network=True)
    assert any(t.kind == "service" for t in targets)


def test_autodiscover_ingests_repo_and_host(tmp_path):
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "settings.py").write_text('KEY = "AKIA' + 'IOSFODNN7EXAMPLE"\n')
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    # discoverer that "finds" our seeded repo (no .git, so git ingest is skipped)
    agent.discoverer = AssetDiscoverer(
        roots=[str(tmp_path)], log_globs=[],
        repo_finder=lambda roots: [str(repo)],
        log_finder=lambda globs: [])
    summary = agent.autodiscover(network=False)
    assert summary["ingested"] >= 1
    # the discovered repo's code was ingested and is scannable
    findings = agent.scan(capabilities=["secrets"])
    assert any(f.metadata.get("secret_kind") == "aws-access-key" for f in findings)
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "discover.ingest" in actions


def test_monitor_cycle_with_discovery_folds_in_logs(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(
        f"Jan 10 10:0{i} h sshd[1]: Failed password for root from 45.9.1.2 port 5{i} ssh2"
        for i in range(6)) + "\n")
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    agent.discoverer = AssetDiscoverer(
        roots=[], log_globs=[], include_host=False,
        repo_finder=lambda r: [], log_finder=lambda g: [str(log)])
    cycle = agent.monitor_cycle(capabilities=["runtime"], discover=True)
    # the discovered log drove SOC detection without being named explicitly
    assert cycle["incidents"]
    assert agent.verify_audit().ok
