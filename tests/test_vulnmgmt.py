from virgent.models import Finding, Severity
from virgent.vulnmgmt import VulnerabilityRegister, risk_score


def mk(title, sev=Severity.HIGH, loc="a.py:1", confidence="high", meta=None):
    return Finding(id="fnd-x", capability="secrets", title=title, description="d",
                   severity=sev, evidence_ids=["ev-1"], location=loc,
                   confidence=confidence, metadata=meta or {})


def test_risk_scoring_orders_by_severity_and_confidence():
    assert risk_score(mk("a", Severity.CRITICAL)) > risk_score(mk("a", Severity.HIGH))
    assert risk_score(mk("a", Severity.HIGH, confidence="high")) > \
           risk_score(mk("a", Severity.HIGH, confidence="low"))
    # a real advisory bumps score
    assert risk_score(mk("v", Severity.HIGH, meta={"advisory": "CVE-1"})) >= \
           risk_score(mk("v", Severity.HIGH))


def test_sync_adds_and_reobserves(tmp_path):
    reg = VulnerabilityRegister(tmp_path / "reg.json")
    s1 = reg.sync([mk("issue A"), mk("issue B", loc="b.py:2")])
    assert s1["added"] == 2 and s1["total"] == 2
    s2 = reg.sync([mk("issue A")])
    assert s2["added"] == 0 and s2["reobserved"] == 1
    entry = next(e for e in reg.entries() if e.finding["title"] == "issue A")
    assert entry.times_seen == 2


def test_resolved_reopens_on_reobservation(tmp_path):
    reg = VulnerabilityRegister(tmp_path / "reg.json")
    reg.sync([mk("issue A")])
    fp = reg.entries()[0].fingerprint
    reg.set_status(fp, "resolved", actor="alice")
    assert reg.entries(status="resolved")
    s = reg.sync([mk("issue A")])          # came back
    assert s["reopened"] == 1
    assert reg.entries()[0].status == "open"


def test_status_lifecycle_and_audit_log(tmp_path):
    reg = VulnerabilityRegister(tmp_path / "reg.json")
    reg.sync([mk("issue A")])
    fp = reg.entries()[0].fingerprint
    reg.set_status(fp, "accepted", actor="ciso", note="compensating control in place")
    e = reg.entries(status="accepted")[0]
    assert e.status == "accepted" and e.changed_by == "ciso"
    # transitions are logged
    log = (tmp_path / "reg.log.jsonl").read_text()
    assert "status_change" in log and "ciso" in log


def test_persistence_reload(tmp_path):
    reg1 = VulnerabilityRegister(tmp_path / "reg.json")
    reg1.sync([mk("issue A")])
    reg2 = VulnerabilityRegister(tmp_path / "reg.json")
    assert reg2.summary()["total"] == 1


def test_overdue_by_sla(tmp_path):
    reg = VulnerabilityRegister(tmp_path / "reg.json")
    reg.sync([mk("critical thing", Severity.CRITICAL)])
    e = reg.entries()[0]
    e.first_seen = "2020-01-01T00:00:00+00:00"   # ancient
    reg._save()
    reg2 = VulnerabilityRegister(tmp_path / "reg.json")
    assert len(reg2.overdue()) == 1
