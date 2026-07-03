import pytest

from virgent.models import Actor
from virgent.policy import PolicyEngine, PolicyViolation, write_default_policy


def test_default_policy_allows_scans_denies_unknown():
    engine = PolicyEngine()
    assert engine.evaluate("scan.secrets").allowed
    assert engine.evaluate("ingest.file").allowed
    assert engine.evaluate("delete.everything").effect == "deny"


def test_deny_takes_precedence():
    engine = PolicyEngine({
        "actions": {"default": "allow", "deny": ["scan.*"], "allow": ["scan.secrets"]}
    })
    decision = engine.evaluate("scan.secrets")
    assert decision.effect == "deny"
    assert decision.rule == "scan.*"


def test_require_approval_then_grant():
    engine = PolicyEngine()
    assert engine.evaluate("collect.web").effect == "require_approval"
    with pytest.raises(PolicyViolation):
        engine.enforce("collect.web")

    approver = Actor(id="alice", type="human")
    engine.grant_approval("collect.web", approver)
    decision = engine.evaluate("collect.web")
    assert decision.allowed
    assert decision.approved_by == "alice"


def test_glob_matching():
    engine = PolicyEngine({"actions": {"default": "deny", "allow": ["remediate.rotate-*"]}})
    assert engine.evaluate("remediate.rotate-keys").allowed
    assert engine.evaluate("remediate.delete-user").effect == "deny"


def test_domain_allowlist():
    engine = PolicyEngine({"network": {"allowed_domains": ["osv.dev"]}})
    assert engine.domain_allowed("osv.dev")
    assert engine.domain_allowed("api.osv.dev")
    assert not engine.domain_allowed("evil-osv.dev")
    assert not engine.domain_allowed("example.com")


def test_policy_roundtrip_via_file(tmp_path):
    path = write_default_policy(tmp_path / "policy.yaml")
    engine = PolicyEngine.from_file(path)
    assert engine.evaluate("scan.secrets").allowed
    assert engine.llm["redact_before_send"] is True
