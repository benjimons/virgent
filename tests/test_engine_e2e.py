"""End-to-end: ingest a seeded repo, scan, report, verify the audit chain."""
import json

import pytest

from virgent.engine import SecurityAgent
from virgent.models import Actor
from virgent.policy import PolicyEngine, PolicyViolation

ACTOR = Actor(id="e2e", type="system")
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "settings.py").write_text(f'AWS_KEY = "{AWS_KEY}"\n')
    (root / "requirements.txt").write_text("requests==2.19.0\nflask\n")
    (root / "Dockerfile").write_text("FROM ubuntu:latest\nRUN curl -s https://x.io/i.sh | sh\n")
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "on:\n  push:\njobs:\n  b:\n    steps:\n      - uses: someone/act@v1\n")
    return root


def make_agent(tmp_path):
    return SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)


def test_full_pipeline(tmp_path, repo):
    agent = make_agent(tmp_path)
    evidence = agent.ingest(str(repo))
    assert len(evidence) == 4

    findings = agent.scan()
    caps = {f.capability for f in findings}
    assert {"secrets", "dependencies", "iac"} <= caps

    # every finding traces to registered evidence
    known = set(agent.provenance.all_ids())
    for f in findings:
        assert set(f.evidence_ids) <= known

    report_md = agent.report(fmt="markdown")
    assert "Audit Chain Attestation" in report_md
    assert "Chain verified: **True**" in report_md
    assert AWS_KEY not in report_md  # DLP holds in reports too

    report_json = json.loads(agent.report(fmt="json"))
    assert report_json["summary"]["findings_total"] == len(findings)
    assert report_json["audit_attestation"]["chain_verified"] is True

    # the audit log recorded the whole pipeline and still verifies
    result = agent.verify_audit()
    assert result.ok
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "agent.init" in actions
    assert "ingest.file" in actions
    assert any(a.startswith("scan.") for a in actions)
    assert "report.generate" in actions


def test_denied_action_is_audited(tmp_path, repo):
    policy = PolicyEngine({"actions": {"default": "deny", "allow": ["agent.init"]}})
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    with pytest.raises(PolicyViolation):
        agent.ingest(str(repo))
    denied = [r for r in agent.audit.iter_records() if r["outcome"].startswith("denied")]
    assert len(denied) == 1
    assert denied[0]["action"] == "ingest.file"


def test_web_collection_requires_approval_then_works(tmp_path):
    agent = make_agent(tmp_path)
    with pytest.raises(PolicyViolation):
        agent.enable_online_dependency_checks()

    agent.approve("collect.web", Actor(id="alice", type="human"))
    # inject an offline fetcher so the test never touches the network
    agent.ingestors["web"].fetcher = lambda url, data=None: json.dumps({
        "vulns": [{"id": "OSV-1", "aliases": ["CVE-2020-1"], "summary": "s"}]})
    agent.enable_online_dependency_checks()

    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    agent.ingest(str(tmp_path / "requirements.txt"))
    findings = agent.scan(capabilities=["dependencies"])
    assert any(f.metadata.get("advisory") == "OSV-1" for f in findings)

    # approval + collection are on the audit trail
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "policy.approval" in actions
    assert "collect.web" in actions


def test_findings_dedup_across_repeated_scans(tmp_path, repo):
    agent = make_agent(tmp_path)
    agent.ingest(str(repo / "Dockerfile"))
    first = agent.scan(capabilities=["iac"])
    agent.scan(capabilities=["iac"])
    assert len(agent.load_findings(dedup=True)) == len(first)


def test_git_history_ingestion(tmp_path):
    import subprocess
    repo = tmp_path / "gitrepo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=T",
                    "commit", "-q", "--allow-empty", "-m", "leak: ghp_" + "c" * 36],
                   cwd=repo, check=True)
    agent = make_agent(tmp_path)
    commits = agent.ingest(str(repo), ingestor="git")
    assert len(commits) == 1
    findings = agent.scan(capabilities=["secrets"])
    assert any(f.metadata["secret_kind"] == "github-token" for f in findings)
