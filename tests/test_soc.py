"""SOC pipeline: parsing, detection, correlation, triage, response, access."""
import pytest

from virgent.access import Autonomy, AutonomyPolicy, DecisionBroker, EscalationRequired, Sensitivity
from virgent.engine import SecurityAgent
from virgent.llm.provider import MockProvider
from virgent.models import Actor, Severity
from virgent.policy import PolicyEngine, PolicyViolation
from virgent.soc.correlation import correlate
from virgent.soc.detection import DetectionConfig, DetectionEngine
from virgent.soc.events import parse_line

ACTOR = Actor(id="test", type="system")

AUTH_LOG = "\n".join(
    [f"Jan 10 10:0{i} host sshd[123]: Failed password for root from 10.0.0.9 port 5{i} ssh2"
     for i in range(6)]
    + ["Jan 10 10:07 host sshd[123]: Accepted password for root from 10.0.0.9 port 60 ssh2"]
)

SPRAY_LOG = "\n".join(
    f"Jan 10 11:0{i} host sshd[1]: Failed password for user{i} from 10.0.0.50 port 5{i} ssh2"
    for i in range(6)
)

WEB_LOG = '10.0.0.7 - - [10/Jan/2026:10:00:00 +0000] "GET /p?id=1 UNION SELECT password FROM users HTTP/1.1" 200 12'


# -- parsing ------------------------------------------------------------------

def test_parse_auth_lines():
    fail = parse_line("Jan 10 10:00 h sshd[1]: Failed password for bob from 1.2.3.4 port 5 ssh2")
    assert fail.event_type == "ssh_login_failed" and fail.user == "bob" and fail.src_ip == "1.2.3.4"
    ok = parse_line("Jan 10 10:00 h sshd[1]: Accepted publickey for alice from 5.6.7.8 port 5 ssh2")
    assert ok.event_type == "ssh_login_success" and ok.user == "alice"


def test_parse_json_line():
    ev = parse_line('{"timestamp":"t","user":"carol","src_ip":"9.9.9.9","event_type":"login","host":"h1"}')
    assert ev.user == "carol" and ev.src_ip == "9.9.9.9" and ev.host == "h1"


# -- detection ----------------------------------------------------------------

def _events(text, source="auth.log"):
    return [e for e in (parse_line(l, source) for l in text.splitlines()) if e]


def test_brute_force_and_compromise_detection():
    alerts = DetectionEngine().run(_events(AUTH_LOG))
    rules = {a.rule for a in alerts}
    assert "ssh-brute-force" in rules
    assert "successful-login-after-bruteforce" in rules
    compromise = [a for a in alerts if a.rule == "successful-login-after-bruteforce"]
    assert compromise[0].severity == Severity.CRITICAL


def test_password_spray_detection():
    alerts = DetectionEngine().run(_events(SPRAY_LOG))
    assert any(a.rule == "password-spray" for a in alerts)


def test_web_attack_detection():
    alerts = DetectionEngine().run(_events(WEB_LOG, "access.log"))
    assert any(a.rule == "web-attack-sqli" for a in alerts)


def test_threshold_config():
    cfg = DetectionConfig(brute_force_threshold=100)
    assert not any(a.rule == "ssh-brute-force" for a in DetectionEngine(cfg).run(_events(AUTH_LOG)))


# -- correlation --------------------------------------------------------------

def test_correlation_groups_by_entity():
    alerts = DetectionEngine().run(_events(AUTH_LOG))
    incidents = correlate(alerts)
    # all AUTH_LOG alerts share ip 10.0.0.9 -> one incident
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.severity == Severity.CRITICAL
    assert inc.priority == "P1"
    assert "10.0.0.9" in inc.entities.get("ip", [])


def test_incident_ids_stable_across_runs():
    a1 = DetectionEngine().run(_events(AUTH_LOG))
    a2 = DetectionEngine().run(_events(AUTH_LOG))
    assert {i.id for i in correlate(a1)} == {i.id for i in correlate(a2)}


# -- access model -------------------------------------------------------------

def test_autonomy_defaults_and_risk_escalation():
    ap = AutonomyPolicy()
    assert ap.evaluate(Sensitivity.OBSERVE)[0] == Autonomy.AUTO
    assert ap.evaluate(Sensitivity.RESPOND)[0] == Autonomy.CONFIRM
    assert ap.evaluate(Sensitivity.DESTRUCTIVE)[0] == Autonomy.ESCALATE
    # high risk bumps the required role up the chain
    _, role_low = ap.evaluate(Sensitivity.RESPOND, {"risk": 10})
    _, role_high = ap.evaluate(Sensitivity.RESPOND, {"risk": 95})
    assert ap.role_rank(role_high) > ap.role_rank(role_low)


def test_broker_escalates_on_insufficient_role(tmp_path):
    ap = AutonomyPolicy()
    broker = DecisionBroker(tmp_path / "dec.json", ap)
    req = broker.open("respond.isolate_host", Sensitivity.DESTRUCTIVE, {}, "admin", Autonomy.ESCALATE)
    # analyst tries to approve an admin-level decision -> escalated, still pending
    broker.resolve(req.id, "approve", resolver="bob", role="analyst")
    assert broker.get(req.id).status == "pending"
    assert broker.get(req.id).escalations
    # admin approves -> resolved
    broker.resolve(req.id, "approve", resolver="carol", role="admin")
    assert broker.get(req.id).status == "approved"


# -- engine e2e ---------------------------------------------------------------

def test_engine_soc_pipeline_and_gated_response(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    logf = tmp_path / "auth.log"
    logf.write_text(AUTH_LOG + "\n")
    agent.ingest(str(logf))
    alerts, incidents = agent.soc_detect()
    assert incidents
    inc = incidents[0]

    # auto triage (no LLM) works
    agent.soc_triage(inc.id)
    assert agent.soc.casebook.get_incident(inc.id).status == "triaged"

    # a RESPOND action with no approval must escalate to a human
    with pytest.raises(EscalationRequired) as ei:
        agent.soc_respond(inc.id, "block_ip")
    decision_id = ei.value.request.id
    assert agent.pending_decisions()

    # a CRITICAL incident escalates block_ip to admin; analyst is too junior
    res = agent.resolve_decision(decision_id, "approve", resolver="bob", role="analyst")
    assert res["status"] == "pending"

    # admin approves -> now the action executes (dry-run by default)
    agent.resolve_decision(decision_id, "approve", resolver="carol", role="admin")
    entry = agent.soc_respond(inc.id, "block_ip")
    assert entry["result"]["status"] == "dry-run"
    assert "10.0.0.9" in str(entry["result"]["params"])

    # everything is on the audit trail and the chain verifies
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "soc.detect" in actions
    assert "decision.requested" in actions
    assert "decision.escalated" in actions
    assert "respond.block_ip" in actions
    assert agent.verify_audit().ok


def test_observe_tier_autoexecutes(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    logf = tmp_path / "auth.log"
    logf.write_text(AUTH_LOG + "\n")
    agent.ingest(str(logf))
    _, incidents = agent.soc_detect()
    # 'review' is OBSERVE tier -> AUTO, no human needed
    entry = agent.soc_respond(incidents[0].id, "review")
    assert entry["result"]["status"] == "dry-run"


def test_llm_triage(tmp_path):
    provider = MockProvider(responses=[
        '{"assessment":"brute force then success; likely compromise",'
        '"true_positive_likelihood":"high","priority":"P1",'
        '"recommended_next_action":"block 10.0.0.9 and reset root"}'])
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR, provider=provider)
    logf = tmp_path / "auth.log"
    logf.write_text(AUTH_LOG + "\n")
    agent.ingest(str(logf))
    _, incidents = agent.soc_detect()
    inc = agent.soc_triage(incidents[0].id)
    assert "compromise" in inc.summary.lower()
    assert inc.priority == "P1"
