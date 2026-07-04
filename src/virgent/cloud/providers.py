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


class GCPProvider:
    """Read-only Google Cloud enumeration.

    Normalizes to the same config keys as AWS so one CSPM rule set covers all
    clouds. The ``client`` is injectable (a fake in tests); the default path
    would use the google-cloud SDK.
    """

    name = "gcp"

    def __init__(self, project: str = "", client=None):
        self.project = project
        self.client = client   # injected; default SDK wiring omitted for offline safety

    def enumerate(self) -> list[CloudResource]:
        if self.client is None:  # pragma: no cover - needs the SDK + creds
            raise RuntimeError("GCPProvider needs an injected client (google-cloud SDK wiring)")
        out: list[CloudResource] = []
        for b in self.client.list_buckets() or []:
            out.append(CloudResource(
                provider="gcp", service="gcs", rtype="bucket", id=b["name"],
                config={"public": bool(b.get("public")),
                        "encrypted": bool(b.get("encrypted", True)),
                        "public_access_block": not b.get("public")}))
        for fw in self.client.list_firewalls() or []:
            open_ingress = []
            if "0.0.0.0/0" in (fw.get("sourceRanges") or []):
                for allowed in fw.get("allowed", []):
                    for p in allowed.get("ports", [None]):
                        frm = int(p) if p and str(p).isdigit() else None
                        open_ingress.append({"from": frm, "to": frm, "proto": allowed.get("IPProtocol")})
            out.append(CloudResource(
                provider="gcp", service="gcp", rtype="firewall", id=fw["name"],
                config={"open_ingress": open_ingress}))
        for sa in self.client.list_service_accounts() or []:
            out.append(CloudResource(
                provider="gcp", service="gcp", rtype="service_account", id=sa["email"],
                config={"admin_policy": bool(sa.get("owner_or_editor")),
                        "mfa_enabled": True, "console_access": False,
                        "max_access_key_age_days": sa.get("key_age_days")}))
        return out


class AzureProvider:
    """Read-only Azure enumeration, normalized to shared config keys."""

    name = "azure"

    def __init__(self, subscription: str = "", client=None):
        self.subscription = subscription
        self.client = client

    def enumerate(self) -> list[CloudResource]:
        if self.client is None:  # pragma: no cover - needs the SDK + creds
            raise RuntimeError("AzureProvider needs an injected client (azure-mgmt SDK wiring)")
        out: list[CloudResource] = []
        for s in self.client.list_storage_accounts() or []:
            out.append(CloudResource(
                provider="azure", service="azure", rtype="storage_account", id=s["name"],
                config={"public": bool(s.get("allow_blob_public_access")),
                        "encrypted": bool(s.get("encryption", True)),
                        "public_access_block": not s.get("allow_blob_public_access")}))
        for nsg in self.client.list_network_security_groups() or []:
            open_ingress = []
            for rule in nsg.get("rules", []):
                if rule.get("access") == "Allow" and rule.get("source") in ("*", "0.0.0.0/0", "Internet"):
                    port = rule.get("port")
                    frm = int(port) if port and str(port).isdigit() else None
                    open_ingress.append({"from": frm, "to": frm, "proto": rule.get("protocol")})
            out.append(CloudResource(
                provider="azure", service="azure", rtype="nsg", id=nsg["name"],
                config={"open_ingress": open_ingress}))
        return out


class CompositeCloudProvider:
    """Enumerates several providers as one (multi-cloud)."""

    name = "multi-cloud"

    def __init__(self, providers: list):
        self.providers = providers

    def enumerate(self) -> list[CloudResource]:
        out: list[CloudResource] = []
        for p in self.providers:
            try:
                out += p.enumerate()
            except Exception:  # noqa: BLE001 - one cloud's failure shouldn't blind the others
                continue
        return out


def _build_one(spec: dict, session=None):
    provider = spec.get("provider", "aws")
    if provider == "aws":
        return AWSProvider(regions=spec.get("regions"), session=session)
    if provider == "gcp":
        return GCPProvider(project=spec.get("project", ""))
    if provider == "azure":
        return AzureProvider(subscription=spec.get("subscription", ""))
    return None


def build_cloud_provider(policy: dict, session=None) -> "CloudProvider | None":
    """Construct a cloud provider (or a multi-cloud composite) from policy.

    Returns None unless explicitly enabled — reaching into a cloud account is
    never on by accident. ``cloud.providers`` (a list) builds a composite;
    otherwise the single ``cloud.provider`` is used.
    """
    cfg = (policy or {}).get("cloud") or {}
    if not cfg.get("enabled"):
        return None
    specs = cfg.get("providers")
    if specs:
        built = [p for p in (_build_one(s, session) for s in specs) if p]
        return CompositeCloudProvider(built) if built else None
    return _build_one(cfg, session)
