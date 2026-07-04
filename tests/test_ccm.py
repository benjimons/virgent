"""Continuous Control Monitoring: pass/fail/not-assessed, SLA, persistence."""
from virgent.ccm import ControlMonitor, _owner_for
from virgent.engine import SecurityAgent
from virgent.models import Actor, Finding, Severity

ACTOR = Actor(id="test", type="system")


def f(fid, controls, severity=Severity.HIGH):
    return Finding(id=fid, capability="x", title="t", description="d",
                   severity=severity, evidence_ids=["ev-1"], controls=controls)


def test_control_fails_when_findings_map_to_it(tmp_path):
    m = ControlMonitor(tmp_path / "ccm.json")
    results = m.assess([f("fnd-1", ["NIST:IA-5"], Severity.CRITICAL)],
                       active_capabilities=["secrets", "iac", "host"])
    ia5 = next(r for r in results if r.control_id == "NIST:IA-5")
    assert ia5.status == "fail"
    assert ia5.finding_ids == ["fnd-1"]
    assert ia5.severity == "critical"
    assert ia5.due_at  # SLA due date set
    assert ia5.owner == "iam"


def test_control_passes_when_capability_ran_clean(tmp_path):
    m = ControlMonitor(tmp_path / "ccm.json")
    results = m.assess([], active_capabilities=["secrets"])
    ia5 = next(r for r in results if r.control_id == "NIST:IA-5")
    assert ia5.status == "pass"
    assert ia5.due_at == ""


def test_control_not_assessed_when_capability_absent(tmp_path):
    m = ControlMonitor(tmp_path / "ccm.json")
    results = m.assess([], active_capabilities=[])   # nothing ran
    assert all(r.status == "not_assessed" for r in results)


def test_first_failed_at_persists_and_clears(tmp_path):
    path = tmp_path / "ccm.json"
    m1 = ControlMonitor(path)
    r1 = m1.assess([f("fnd-1", ["NIST:IA-5"])], ["secrets"])
    ff = next(r for r in r1 if r.control_id == "NIST:IA-5").first_failed_at
    assert ff
    # second run, still failing -> first_failed_at unchanged (persisted)
    m2 = ControlMonitor(path)
    r2 = m2.assess([f("fnd-1", ["NIST:IA-5"])], ["secrets"])
    assert next(r for r in r2 if r.control_id == "NIST:IA-5").first_failed_at == ff
    # now clean -> cleared
    m3 = ControlMonitor(path)
    r3 = m3.assess([], ["secrets"])
    assert next(r for r in r3 if r.control_id == "NIST:IA-5").first_failed_at == ""


def test_summary_compliance_pct(tmp_path):
    m = ControlMonitor(tmp_path / "ccm.json")
    results = m.assess([f("fnd-1", ["NIST:IA-5"])], ["secrets"])
    s = m.summary(results)
    assert s["by_status"]["fail"] >= 1
    assert s["by_status"]["pass"] >= 1   # other secrets controls pass
    assert 0 <= s["compliance_pct"] <= 100


def test_owner_mapping():
    assert _owner_for("NIST:AC-2") == "iam"
    assert _owner_for("NIST:SI-4") == "soc"
    assert _owner_for("CIS:5.2") == "infrastructure"
    assert _owner_for("PCI:1") == "grc"


def test_engine_ccm_assess_audited(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    (tmp_path / "cfg.py").write_text('AWS_KEY = "AKIA' + 'IOSFODNN7EXAMPLE"\n')
    agent.ingest(str(tmp_path / "cfg.py"))
    agent.scan(capabilities=["secrets"])
    out = agent.ccm_assess()
    assert out["summary"]["controls_monitored"] > 0
    # the secret finding should fail its mapped controls
    assert out["summary"]["by_status"].get("fail", 0) >= 1
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "ccm.assess" in actions
    assert agent.verify_audit().ok
