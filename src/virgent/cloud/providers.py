"""Cloud providers: normalized, read-only resource enumeration.

A provider turns a cloud account into a flat list of :class:`CloudResource`.
The AWS provider uses boto3 and issues **only read-only** Describe/List/Get
calls; every call is wrapped so that partial IAM permissions degrade
gracefully (a resource type the role can't read is skipped, never fatal).
The normalization (the ``config`` dict) is what the posture rules read, so the
rules never depend on boto3 response shapes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class CloudResource:
    provider: str          # aws | gcp | azure
    service: str           # s3 | ec2 | iam | rds | ...
    rtype: str             # bucket | security_group | user | db_instance | instance
    id: str                # resource id / ARN
    region: str = "global"
    config: dict = field(default_factory=dict)   # normalized attributes rules read
    tags: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "service": self.service, "rtype": self.rtype,
            "id": self.id, "region": self.region, "config": self.config, "tags": self.tags,
        }


class CloudProvider(Protocol):
    name: str
    def enumerate(self) -> list[CloudResource]: ...


@dataclass
class MockCloudProvider:
    """Deterministic provider for tests and offline/air-gapped audits."""

    resources: list = field(default_factory=list)
    name: str = "mock"

    def enumerate(self) -> list[CloudResource]:
        return list(self.resources)


def _iso_age_days(ts) -> int | None:
    """Whole days between an aware datetime and now, without importing at top."""
    if ts is None:
        return None
    try:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        return (now - ts).days
    except Exception:  # noqa: BLE001
        return None


class AWSProvider:
    """Read-only AWS enumeration via boto3.

    Credentials resolve through the standard boto3 chain (instance role,
    ``AWS_*`` env vars, or a named profile), so it sees exactly what that IAM
    identity is allowed to see. Only Describe/List/Get calls are made.
    """

    name = "aws"

    def __init__(self, regions: list | None = None, session=None):
        if session is None:
            try:
                import boto3
            except ImportError as e:  # pragma: no cover - exercised only with the extra
                raise RuntimeError(
                    "The 'boto3' package is required for AWSProvider. "
                    "Install it with: pip install 'virgent[aws]'") from e
            session = boto3.session.Session()
        self.session = session
        self.regions = regions or [session.region_name or "us-east-1"]

    # each collector is best-effort; missing permissions must not abort the run
    @staticmethod
    def _safe(fn, default=None):
        try:
            return fn()
        except Exception:  # noqa: BLE001 - provider partial-permission tolerance
            return default

    def enumerate(self) -> list[CloudResource]:
        out: list[CloudResource] = []
        out += self._safe(self._s3, []) or []
        out += self._safe(self._iam, []) or []
        for region in self.regions:
            out += self._safe(lambda r=region: self._security_groups(r), []) or []
            out += self._safe(lambda r=region: self._rds(r), []) or []
        return out

    def _s3(self) -> list[CloudResource]:
        s3 = self.session.client("s3")
        res: list[CloudResource] = []
        for b in self._safe(lambda: s3.list_buckets().get("Buckets", []), []) or []:
            name = b["Name"]
            pab = self._safe(lambda: s3.get_public_access_block(Bucket=name)
                             .get("PublicAccessBlockConfiguration", {}), {}) or {}
            policy_status = self._safe(
                lambda: s3.get_bucket_policy_status(Bucket=name)
                .get("PolicyStatus", {}), {}) or {}
            enc = self._safe(lambda: s3.get_bucket_encryption(Bucket=name), None)
            all_blocked = all(pab.get(k) for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
            res.append(CloudResource(
                provider="aws", service="s3", rtype="bucket", id=name,
                config={
                    "public": bool(policy_status.get("IsPublic")) or not all_blocked,
                    "public_access_block": all_blocked,
                    "encrypted": enc is not None,
                }))
        return res

    def _security_groups(self, region: str) -> list[CloudResource]:
        ec2 = self.session.client("ec2", region_name=region)
        res: list[CloudResource] = []
        groups = self._safe(lambda: ec2.describe_security_groups().get("SecurityGroups", []), []) or []
        for g in groups:
            open_ports = []
            for perm in g.get("IpPermissions", []):
                cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
                cidrs += [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
                if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
                    frm, to = perm.get("FromPort"), perm.get("ToPort")
                    open_ports.append({"from": frm, "to": to, "proto": perm.get("IpProtocol")})
            res.append(CloudResource(
                provider="aws", service="ec2", rtype="security_group",
                id=g["GroupId"], region=region,
                config={"open_ingress": open_ports, "name": g.get("GroupName")}))
        return res

    def _iam(self) -> list[CloudResource]:
        iam = self.session.client("iam")
        res: list[CloudResource] = []
        for u in self._safe(lambda: iam.list_users().get("Users", []), []) or []:
            name = u["UserName"]
            keys = self._safe(lambda: iam.list_access_keys(UserName=name)
                              .get("AccessKeyMetadata", []), []) or []
            key_ages = [d for d in (_iso_age_days(k.get("CreateDate")) for k in keys) if d is not None]
            mfa = self._safe(lambda: iam.list_mfa_devices(UserName=name).get("MFADevices", []), []) or []
            has_console = self._safe(lambda: bool(iam.get_login_profile(UserName=name)), False)
            attached = self._safe(lambda: iam.list_attached_user_policies(UserName=name)
                                  .get("AttachedPolicies", []), []) or []
            admin = any(p.get("PolicyName") == "AdministratorAccess"
                        or p.get("PolicyArn", "").endswith("AdministratorAccess") for p in attached)
            res.append(CloudResource(
                provider="aws", service="iam", rtype="user", id=name,
                config={
                    "max_access_key_age_days": max(key_ages) if key_ages else None,
                    "console_access": bool(has_console),
                    "mfa_enabled": len(mfa) > 0,
                    "admin_policy": admin,
                }))
        return res

    def _rds(self, region: str) -> list[CloudResource]:
        rds = self.session.client("rds", region_name=region)
        res: list[CloudResource] = []
        dbs = self._safe(lambda: rds.describe_db_instances().get("DBInstances", []), []) or []
        for db in dbs:
            res.append(CloudResource(
                provider="aws", service="rds", rtype="db_instance",
                id=db.get("DBInstanceIdentifier", "?"), region=region,
                config={
                    "publicly_accessible": bool(db.get("PubliclyAccessible")),
                    "encrypted": bool(db.get("StorageEncrypted")),
                    "engine": db.get("Engine"),
                }))
        return res


def build_cloud_provider(policy: dict, session=None) -> "CloudProvider | None":
    """Construct a cloud provider from the ``cloud`` policy block.

    Returns None unless a provider is explicitly enabled — reaching into a
    cloud account is never on by accident.
    """
    cfg = (policy or {}).get("cloud") or {}
    if not cfg.get("enabled"):
        return None
    provider = cfg.get("provider", "aws")
    if provider == "aws":
        return AWSProvider(regions=cfg.get("regions"), session=session)
    return None
