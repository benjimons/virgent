"""Cloud posture (CSPM): provider enumeration, rules, engine wiring, gating.

All offline — the real AWSProvider is exercised through an injected fake boto3
session so no credentials or network are needed.
"""
import json

import pytest

from virgent.capabilities.cloud import (
    CloudPostureCapability,
    check_bucket,
    check_iam_user,
    check_rds,
    check_security_group,
)
from virgent.cloud import AWSProvider, MockCloudProvider
from virgent.cloud.providers import CloudResource, build_cloud_provider
from virgent.engine import SecurityAgent
from virgent.models import Actor, Evidence, Severity
from virgent.policy import PolicyEngine, PolicyViolation

ACTOR = Actor(id="test", type="system")


def res(service, rtype, rid, config, region="us-east-1"):
    return CloudResource(provider="aws", service=service, rtype=rtype, id=rid,
                         region=region, config=config)


# -- rule units ---------------------------------------------------------------

def test_bucket_rules():
    rules = {r[0] for r in check_bucket(res("s3", "bucket", "b1",
             {"public": True, "encrypted": False, "public_access_block": False}).to_dict())}
    assert "cloud-s3-public" in rules
    assert "cloud-s3-unencrypted" in rules
    pub = [r for r in check_bucket(res("s3", "bucket", "b1", {"public": True}).to_dict())
           if r[0] == "cloud-s3-public"]
    assert pub[0][2] == Severity.CRITICAL


def test_security_group_open_sensitive_port():
    r = res("ec2", "security_group", "sg-1",
            {"open_ingress": [{"from": 22, "to": 22, "proto": "tcp"}]}).to_dict()
    issues = check_security_group(r)
    assert issues and issues[0][0] == "cloud-sg-open-sensitive"
    assert "SSH" in issues[0][1]


def test_security_group_all_ports():
    r = res("ec2", "security_group", "sg-2",
            {"open_ingress": [{"from": None, "to": None, "proto": "-1"}]}).to_dict()
    assert check_security_group(r)[0][0] == "cloud-sg-open-all"


def test_rds_rules():
    rules = {r[0] for r in check_rds(res("rds", "db_instance", "db1",
             {"publicly_accessible": True, "encrypted": False}).to_dict())}
    assert rules == {"cloud-rds-public", "cloud-rds-unencrypted"}


def test_iam_rules():
    rules = {r[0] for r in check_iam_user(res("iam", "user", "bob",
             {"console_access": True, "mfa_enabled": False,
              "max_access_key_age_days": 200, "admin_policy": True}).to_dict())}
    assert rules == {"cloud-iam-no-mfa", "cloud-iam-stale-key", "cloud-iam-admin"}


def test_iam_clean_user_no_findings():
    assert check_iam_user(res("iam", "user", "ok",
        {"console_access": True, "mfa_enabled": True,
         "max_access_key_age_days": 10, "admin_policy": False}).to_dict()) == []


# -- capability ---------------------------------------------------------------

def test_capability_over_cloud_asset_evidence():
    r = res("s3", "bucket", "public-bucket", {"public": True, "encrypted": True})
    ev = Evidence(id="ev-1", source="cloud:aws:us-east-1:public-bucket", kind="cloud-asset",
                  content=json.dumps(r.to_dict()), sha256="0" * 64,
                  collected_at="2026-01-01T00:00:00+00:00")
    findings = CloudPostureCapability().analyze([ev])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "NIST:AC-3" in findings[0].controls
    assert findings[0].metadata["service"] == "s3"


# -- AWSProvider via a fake boto3 session -------------------------------------

class _FakeClient:
    def __init__(self, service, data):
        self.service = service
        self.data = data
    def __getattr__(self, name):
        def call(**kwargs):
            return self.data.get(name, {})
        return call


class _FakeSession:
    region_name = "us-east-1"
    def __init__(self, data):
        self.data = data
    def client(self, service, region_name=None):
        return _FakeClient(service, self.data.get(service, {}))


def test_aws_provider_normalizes_resources():
    session = _FakeSession({
        "s3": {
            "list_buckets": {"Buckets": [{"Name": "logs"}]},
            "get_public_access_block": {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
            "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
            # get_bucket_encryption raising would mean unencrypted; here return {} = "configured"
            "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {}},
        },
        "iam": {"list_users": {"Users": [{"UserName": "svc"}]},
                "list_access_keys": {"AccessKeyMetadata": []},
                "list_mfa_devices": {"MFADevices": []},
                "list_attached_user_policies": {"AttachedPolicies": []}},
        "ec2": {"describe_security_groups": {"SecurityGroups": [
            {"GroupId": "sg-1", "GroupName": "web",
             "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}},
        "rds": {"describe_db_instances": {"DBInstances": []}},
    })
    provider = AWSProvider(regions=["us-east-1"], session=session)
    resources = provider.enumerate()
    kinds = {(r.service, r.rtype) for r in resources}
    assert ("s3", "bucket") in kinds
    assert ("ec2", "security_group") in kinds
    assert ("iam", "user") in kinds
    sg = next(r for r in resources if r.rtype == "security_group")
    assert sg.config["open_ingress"][0]["from"] == 22


def test_aws_provider_tolerates_missing_permissions():
    # a session whose calls all return empty must not crash enumeration
    provider = AWSProvider(regions=["us-east-1"], session=_FakeSession({}))
    assert provider.enumerate() == []


# -- engine wiring + gating ---------------------------------------------------

def test_build_cloud_provider_disabled_by_default():
    assert build_cloud_provider({}) is None
    assert build_cloud_provider({"cloud": {"enabled": False}}) is None


def test_engine_discover_cloud_requires_approval_and_ingests(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    agent.cloud_provider = MockCloudProvider(resources=[
        res("s3", "bucket", "public-bucket", {"public": True, "encrypted": False}),
        res("iam", "user", "bob", {"console_access": True, "mfa_enabled": False,
                                    "max_access_key_age_days": 5, "admin_policy": False}),
    ])
    # default policy: discover.cloud requires approval
    with pytest.raises(PolicyViolation):
        agent.discover_cloud()
    agent.approve("discover.cloud", Actor(id="alice", type="human"))
    resources = agent.discover_cloud()
    assert len(resources) == 2

    findings = agent.scan(capabilities=["cloud"])
    rules = {f.metadata["rule"] for f in findings}
    assert "cloud-s3-public" in rules
    assert "cloud-iam-no-mfa" in rules

    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "discover.cloud" in actions
    assert agent.verify_audit().ok


def test_autodiscover_with_cloud(tmp_path):
    policy = PolicyEngine({"actions": {"default": "allow"}})
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    agent.cloud_provider = MockCloudProvider(resources=[
        res("rds", "db_instance", "prod", {"publicly_accessible": True, "encrypted": True})])
    agent.discoverer.repo_finder = lambda roots: []
    agent.discoverer.log_finder = lambda globs: []
    summary = agent.autodiscover(cloud=True)
    assert summary["cloud_resources"] == 1
    findings = agent.scan(capabilities=["cloud"])
    assert any(f.metadata["rule"] == "cloud-rds-public" for f in findings)
