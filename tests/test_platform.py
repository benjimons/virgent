"""Persistence (SQLite index), HTTP API/console routing, and ticketing."""
import json

from virgent.api import Api
from virgent.engine import SecurityAgent
from virgent.integrations import FileTicketer, JiraTicketer, SlackTicketer, build_ticketer
from virgent.models import Actor
from virgent.policy import PolicyEngine
from virgent.store import Store

ACTOR = Actor(id="test", type="system")
AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def seeded_agent(tmp_path, policy=None):
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    (tmp_path / "cfg.py").write_text(f'KEY = "{AWS}"\n')
    agent.ingest(str(tmp_path / "cfg.py"))
    agent.scan(capabilities=["secrets"])
    return agent


# -- store --------------------------------------------------------------------

def test_store_rebuild_and_query(tmp_path):
    agent = seeded_agent(tmp_path)
    n = agent.reindex()
    assert n["findings"] >= 1
    crit = agent.store.query_findings(severity="critical")
    assert crit and crit[0]["severity"] == "critical"
    assert agent.store.query_findings(capability="secrets")
    counts = agent.store.counts()
    assert counts["findings_total"] >= 1


def test_store_standalone(tmp_path):
    from virgent.models import Finding, Severity
    s = Store(tmp_path / "i.db")
    f = Finding(id="fnd-1", capability="x", title="t", description="d",
                severity=Severity.HIGH, evidence_ids=["ev-1"], controls=["NIST:IA-5"])
    s.rebuild([f], [])
    assert s.query_findings()[0]["id"] == "fnd-1"
    # severity floor: "critical" shows only critical-or-worse, so a HIGH finding is excluded
    assert s.query_findings(severity="critical") == []
    assert s.query_findings(severity="high")[0]["id"] == "fnd-1"


# -- API ----------------------------------------------------------------------

def test_api_requires_token(tmp_path):
    agent = seeded_agent(tmp_path)
    api = Api(agent, token="secret")
    status, _, _ = api.handle("GET", "/api/findings", {})
    assert status == 401
    status, _, _ = api.handle("GET", "/api/findings", {"Authorization": "Bearer wrong"})
    assert status == 401
    status, _, body = api.handle("GET", "/api/findings", {"Authorization": "Bearer secret"})
    assert status == 200
    assert isinstance(json.loads(body), list)


def test_api_disabled_without_token(tmp_path):
    agent = seeded_agent(tmp_path)
    api = Api(agent, token=None)
    status, _, _ = api.handle("GET", "/api/findings", {"Authorization": "Bearer anything"})
    assert status == 401   # no token configured -> API closed


def test_api_healthz_and_console_open(tmp_path):
    agent = seeded_agent(tmp_path)
    api = Api(agent, token="t")
    assert api.handle("GET", "/healthz", {})[0] == 200
    status, ctype, body = api.handle("GET", "/", {})
    assert status == 200 and "text/html" in ctype and "Virgent Console" in body


def test_api_posture_findings_incidents(tmp_path):
    agent = seeded_agent(tmp_path)
    h = {"Authorization": "Bearer t"}
    api = Api(agent, token="t")
    assert api.handle("GET", "/api/posture", h)[0] == 200
    _, _, body = api.handle("GET", "/api/findings?severity=critical&limit=5", h)
    findings = json.loads(body)
    assert all(f["severity"] == "critical" for f in findings)
    assert api.handle("GET", "/api/incidents", h)[0] == 200
    assert api.handle("GET", "/api/decisions", h)[0] == 200


def test_api_resolve_decision(tmp_path):
    from virgent.access import EscalationRequired
    policy = PolicyEngine({"actions": {"default": "allow"},
                           "access": {"autonomy": {"respond": "escalate"}}})
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    # create a pending decision by attempting a gated response
    log = tmp_path / "auth.log"
    log.write_text("\n".join(
        f"Jan 10 10:0{i} h sshd[1]: Failed password for root from 45.9.1.2 port 5{i} ssh2"
        for i in range(6)) + "\n")
    agent.ingest(str(log))
    _, incidents = agent.soc_detect()
    try:
        agent.soc_respond(incidents[0].id, "block_ip")
    except EscalationRequired:
        pass
    did = agent.pending_decisions()[0]["id"]

    api = Api(agent, token="t")
    status, _, body = api.handle("POST", f"/api/decisions/{did}/resolve",
                                 {"Authorization": "Bearer t"},
                                 json.dumps({"decision": "approve", "resolver": "alice",
                                             "role": "admin"}))
    assert status == 200
    assert json.loads(body)["status"] == "approved"


# -- ticketing ----------------------------------------------------------------

def test_file_ticketer(tmp_path):
    t = FileTicketer(path=str(tmp_path / "tickets.jsonl"))
    r = t.create("finding", {"title": "public bucket", "severity": "critical"})
    assert r["status"] == "created" and r["ticket_id"].startswith("TCK-")
    assert "public bucket" in (tmp_path / "tickets.jsonl").read_text()


def test_jira_ticketer_domain_gated_and_creates():
    calls = []
    j = JiraTicketer(url="https://org.atlassian.net", project="SEC",
                     fetcher=lambda u, b, h: calls.append(u) or json.dumps({"key": "SEC-1"}),
                     domain_check=lambda host: host == "org.atlassian.net")
    r = j.create("incident", {"title": "brute force", "severity": "high"})
    assert r["ticket_id"] == "SEC-1"
    blocked = JiraTicketer(url="https://evil.example", project="SEC",
                           fetcher=lambda u, b, h: "x",
                           domain_check=lambda host: host == "org.atlassian.net")
    assert blocked.create("incident", {})["status"] == "blocked"


def test_build_ticketer_from_policy(tmp_path):
    assert build_ticketer({}) is None
    t = build_ticketer({"ticketing": {"enabled": True, "connector": "file",
                                       "path": "t.jsonl"}}, workdir=tmp_path)
    assert isinstance(t, FileTicketer)


def test_engine_open_ticket_audited(tmp_path):
    policy = PolicyEngine({"actions": {"default": "allow"},
                           "ticketing": {"enabled": True, "connector": "file", "path": "t.jsonl"}})
    agent = seeded_agent(tmp_path, policy=policy)
    fps = [f.fingerprint for f in agent.load_findings()]
    result = agent.open_ticket(finding_fingerprint=fps[0])
    assert result["status"] == "created"
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "ticket.create" in actions
    assert agent.verify_audit().ok
