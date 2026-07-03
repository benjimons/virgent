"""Security-org model, runbooks, and program posture."""
from virgent.engine import SecurityAgent
from virgent.models import Actor
from virgent.org import (
    FUNCTIONS,
    RACI,
    ROLES,
    RUNBOOKS,
    TEAMS,
    escalation_chain,
    program_posture,
    select_runbooks,
)

ACTOR = Actor(id="test", type="system")


def test_org_covers_all_csf_functions():
    assert set(FUNCTIONS) == {"GV", "ID", "PR", "DE", "RS", "RC"}
    # every function has an owning team that exists
    for fn in FUNCTIONS.values():
        assert fn.owning_team in TEAMS
    # every RACI function has exactly one Accountable role
    for fn, assign in RACI.items():
        assert list(assign.values()).count("A") == 1, fn


def test_roles_map_to_access_chain():
    access_roles = {r.access_role for r in ROLES.values()}
    assert access_roles <= {"agent", "analyst", "responder", "admin"}
    assert ROLES["ciso"].access_role == "admin"
    assert ROLES["agent"].access_role == "agent"


def test_escalation_chain():
    chain = escalation_chain("agent")
    assert chain[0] == "soc-analyst"
    assert chain[-1] == "ciso"
    assert "agent" not in chain


def test_runbook_selection_by_rule():
    rbs = select_runbooks(["ssh-brute-force"])
    assert any(r["id"] == "ir-ssh-brute-force" for r in rbs)
    rbs2 = select_runbooks(["successful-login-after-bruteforce"])
    assert any(r["id"] == "ir-account-compromise" for r in rbs2)


def test_every_runbook_wellformed():
    for name, rb in RUNBOOKS.items():
        assert rb["steps"] and rb["title"] and rb["owner"]
        assert rb["triggers"]
        assert rb["controls"]


def test_program_posture_scoring():
    posture = program_posture(
        active_capabilities=["secrets", "host", "runtime", "soc", "fim", "pentest"],
        findings=[],
        open_vulns_by_severity={"critical": 0, "high": 0},
        open_incidents=0,
        pending_decisions=0,
        audit_ok=True,
    )
    assert posture["csf_functions_covered"] >= 5
    assert 0 <= posture["maturity_score"] <= 100
    assert posture["maturity_band"] in ("initial", "developing", "managed", "leading")


def test_engine_program_posture_e2e(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    (tmp_path / "cfg.py").write_text('KEY = "AKIA' + 'IOSFODNN7EXAMPLE"\n')
    agent.ingest(str(tmp_path / "cfg.py"))
    agent.scan(capabilities=["secrets"])
    posture = agent.program_posture()
    assert posture["controls_with_evidence"] > 0
    assert posture["operations"]["audit_chain_verified"] is True
    # posture generation is itself audited
    assert any(r["action"] == "report.posture" for r in agent.audit.iter_records())


def test_soc_runbooks_attached_to_incident(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    log = "\n".join(
        f"Jan 10 10:0{i} h sshd[1]: Failed password for root from 10.0.0.9 port 5{i} ssh2"
        for i in range(6))
    logf = tmp_path / "auth.log"
    logf.write_text(log + "\n")
    agent.ingest(str(logf))
    _, incidents = agent.soc_detect()
    rbs = agent.soc_runbooks(incidents[0].id)
    assert any(r["id"] == "ir-ssh-brute-force" for r in rbs)
