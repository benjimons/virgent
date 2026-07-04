"""Multi-cloud providers, CIEM, and attack-path correlation."""
import json

from virgent.cloud import (
    AzureProvider,
    CompositeCloudProvider,
    GCPProvider,
    MockCloudProvider,
)
from virgent.cloud.providers import CloudResource as R, build_cloud_provider
from virgent.capabilities.cloud import CloudPostureCapability
from virgent.engine import SecurityAgent
from virgent.models import Actor, Evidence, Severity
from virgent.policy import PolicyEngine

ACTOR = Actor(id="test", type="system")


class _FakeGCP:
    def list_buckets(self): return [{"name": "gcs-public", "public": True, "encrypted": False}]
    def list_firewalls(self):
        return [{"name": "fw-ssh", "sourceRanges": ["0.0.0.0/0"],
                 "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]
    def list_service_accounts(self):
        return [{"email": "sa@proj.iam", "owner_or_editor": True}]


class _FakeAzure:
    def list_storage_accounts(self):
        return [{"name": "stor1", "allow_blob_public_access": True, "encryption": True}]
    def list_network_security_groups(self):
        return [{"name": "nsg1", "rules": [{"access": "Allow", "source": "Internet",
                                            "port": "3389", "protocol": "tcp"}]}]


def test_gcp_provider_normalizes_and_rules_apply():
    resources = GCPProvider(project="p", client=_FakeGCP()).enumerate()
    kinds = {(r.service, r.rtype) for r in resources}
    assert ("gcs", "bucket") in kinds and ("gcp", "firewall") in kinds
    # feed through the shared CSPM capability
    evs = [Evidence(id=f"ev-{i}", source="x", kind="cloud-asset",
                    content=json.dumps(r.to_dict()), sha256="0"*64,
                    collected_at="2026-01-01T00:00:00+00:00")
           for i, r in enumerate(resources)]
    findings = CloudPostureCapability().analyze(evs)
    rules = {f.metadata["rule"] for f in findings}
    assert "cloud-s3-public" in rules            # GCS bucket reuses bucket rule
    assert "cloud-sg-open-sensitive" in rules    # GCP firewall reuses SG rule


def test_azure_provider_normalizes():
    resources = AzureProvider(subscription="s", client=_FakeAzure()).enumerate()
    kinds = {(r.service, r.rtype) for r in resources}
    assert ("azure", "storage_account") in kinds and ("azure", "nsg") in kinds


def test_composite_enumerates_all_and_tolerates_failure():
    class Boom:
        name = "boom"
        def enumerate(self): raise RuntimeError("down")
    comp = CompositeCloudProvider([
        MockCloudProvider(resources=[R("aws", "s3", "bucket", "b", config={"public": True})]),
        Boom(),
        GCPProvider(client=_FakeGCP()),
    ])
    resources = comp.enumerate()
    providers = {r.provider for r in resources}
    assert "aws" in providers and "gcp" in providers   # boom skipped, not fatal


def test_build_multicloud_composite():
    class _Sess:
        region_name = "us-east-1"
    policy = {"cloud": {"enabled": True, "providers": [
        {"provider": "aws"}, {"provider": "gcp", "project": "p"}]}}
    prov = build_cloud_provider(policy, session=_Sess())
    assert isinstance(prov, CompositeCloudProvider)
    assert len(prov.providers) == 2


# -- CIEM ---------------------------------------------------------------------

def _idp_ev(i, admin, mfa, svc=False):
    a = {"provider": "okta", "id": f"u{i}", "admin": admin,
         "mfa_enabled": mfa, "service_account": svc}
    return Evidence(id=f"ev-{i}", source="x", kind="identity-account",
                    content=json.dumps(a), sha256="0"*64,
                    collected_at="2026-01-01T00:00:00+00:00")


def test_ciem_admin_concentration_and_toxic_combos():
    from virgent.ciem import analyze_entitlements
    # 3 of 5 are admin (60%) -> concentration; one admin w/o MFA -> toxic
    evs = [_idp_ev(0, True, False), _idp_ev(1, True, True), _idp_ev(2, True, True),
           _idp_ev(3, False, True), _idp_ev(4, False, True)]
    findings = analyze_entitlements(evs)
    rules = {f.metadata["rule"] for f in findings}
    assert "ciem-admin-concentration" in rules
    assert "ciem-admin-no-mfa" in rules


def test_engine_ciem_analyze_audited(tmp_path):
    policy = PolicyEngine({"actions": {"default": "allow"}})
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    from virgent.identity import MockIdentityProvider
    from virgent.identity.providers import IdentityAccount
    agent.identity_provider = MockIdentityProvider(accounts=[
        IdentityAccount(provider="okta", id=f"u{i}", admin=(i < 3), mfa_enabled=False)
        for i in range(5)])
    agent.discover_identity()
    findings = agent.ciem_analyze()
    assert findings
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "ciem.analyze" in actions


# -- attack paths -------------------------------------------------------------

def make_finding(rule, evidence_ids, severity=Severity.HIGH):
    from virgent.models import Finding
    return Finding(id=f"fnd-{rule}", capability="x", title=rule, description="d",
                   severity=severity, evidence_ids=evidence_ids, controls=[],
                   metadata={"rule": rule})


def test_attack_path_exposure_plus_privilege():
    from virgent.attackpath import correlate_attack_paths
    findings = [make_finding("cloud-s3-public", ["ev-1"]),
                make_finding("cloud-iam-admin", ["ev-2"])]
    paths = correlate_attack_paths(findings)
    assert paths
    assert paths[0].severity == Severity.CRITICAL
    assert set(paths[0].evidence_ids) == {"ev-1", "ev-2"}


def test_attack_path_none_without_both_halves():
    from virgent.attackpath import correlate_attack_paths
    assert correlate_attack_paths([make_finding("cloud-s3-public", ["ev-1"])]) == []


def test_engine_attack_paths_audited(tmp_path):
    policy = PolicyEngine({"actions": {"default": "allow"}})
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    agent._persist_findings([make_finding("cloud-sg-open-sensitive", ["ev-1"]),
                             make_finding("identity-no-mfa", ["ev-2"])])
    paths = agent.attack_paths()
    assert paths
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "attackpath.correlate" in actions
