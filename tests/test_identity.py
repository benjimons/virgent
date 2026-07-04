"""Identity security: posture rules, access reviews, engine gating, Okta provider."""
import json

import pytest

from virgent.capabilities.identity import IdentityPostureCapability, check_account
from virgent.engine import SecurityAgent
from virgent.identity import MockIdentityProvider, OktaProvider, generate_access_reviews
from virgent.identity.providers import IdentityAccount
from virgent.models import Actor, Evidence
from virgent.policy import PolicyEngine, PolicyViolation

ACTOR = Actor(id="test", type="system")


def acc(**kw):
    base = dict(provider="okta", id="u1", email="u1@corp", status="active",
                mfa_enabled=True, admin=False)
    base.update(kw)
    return IdentityAccount(**base)


def test_posture_rules():
    rules = {r[0] for r in check_account(acc(admin=True, mfa_enabled=False).to_dict())}
    assert "identity-no-mfa" in rules
    rules = {r[0] for r in check_account(acc(last_login_days=200).to_dict())}
    assert "identity-dormant" in rules
    rules = {r[0] for r in check_account(acc(status="suspended").to_dict())}
    assert "identity-disabled-present" in rules
    rules = {r[0] for r in check_account(acc(service_account=True, admin=True).to_dict())}
    assert "identity-privileged-svc-account" in rules


def test_clean_account_no_findings():
    assert check_account(acc(mfa_enabled=True, last_login_days=2,
                             credential_age_days=30).to_dict()) == []


def test_no_mfa_admin_is_high():
    issues = check_account(acc(admin=True, mfa_enabled=False).to_dict())
    sev = next(i[2] for i in issues if i[0] == "identity-no-mfa")
    assert sev.value == "high"


def test_capability_over_identity_evidence():
    a = acc(admin=True, mfa_enabled=False)
    ev = Evidence(id="ev-1", source="identity:okta:u1", kind="identity-account",
                  content=json.dumps(a.to_dict()), sha256="0" * 64,
                  collected_at="2026-01-01T00:00:00+00:00")
    findings = IdentityPostureCapability().analyze([ev])
    assert findings and any(f.metadata["rule"] == "identity-no-mfa" for f in findings)
    assert "NIST:IA-5" in findings[0].controls


def test_access_reviews():
    accounts = [
        acc(admin=True), acc(id="u2", last_login_days=200),
        acc(id="u3", status="deprovisioned"),
        acc(id="svc", service_account=True, admin=True),
    ]
    reviews = generate_access_reviews(accounts)
    recs = {r.item for r in reviews}
    assert any("admin" in i for i in recs)
    assert any("dormant" in i for i in recs)
    assert any("disabled account" in i for i in recs)
    assert all(r.id.startswith("rev-") for r in reviews)


def test_okta_provider_via_fake_fetcher():
    responses = {
        "/api/v1/users?limit=200": [
            {"id": "00u1", "status": "ACTIVE",
             "profile": {"email": "a@corp"}, "lastLogin": None, "passwordChanged": None}],
        "/api/v1/users/00u1/factors": [],
        "/api/v1/users/00u1/roles": [{"type": "SUPER_ADMIN"}],
    }
    p = OktaProvider(org_url="https://x.okta.com", token="t",
                     fetcher=lambda path: responses.get(path, []))
    accounts = p.enumerate()
    assert len(accounts) == 1
    assert accounts[0].admin is True
    assert accounts[0].mfa_enabled is False


def test_engine_identity_gated_and_scans(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    agent.identity_provider = MockIdentityProvider(accounts=[
        acc(admin=True, mfa_enabled=False), acc(id="u2", last_login_days=300)])
    with pytest.raises(PolicyViolation):
        agent.discover_identity()          # default: discover.identity gated
    agent.approve("discover.identity", Actor(id="alice", type="human"))
    accounts = agent.discover_identity()
    assert len(accounts) == 2
    findings = agent.scan(capabilities=["identity"])
    rules = {f.metadata["rule"] for f in findings}
    assert "identity-no-mfa" in rules
    assert "identity-dormant" in rules
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "discover.identity" in actions
    assert agent.verify_audit().ok


def test_engine_access_reviews_audited(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    agent.identity_provider = MockIdentityProvider(accounts=[acc(admin=True)])
    reviews = agent.access_reviews()
    assert reviews
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "identity.reviews" in actions
