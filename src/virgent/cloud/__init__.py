"""Cloud asset discovery and posture (CSPM).

Reaches into a cloud account with its own read-only credentials, enumerates
the resources only a credentialed insider can see (S3 buckets, security
groups, IAM users, RDS instances…), and normalizes them into
:class:`CloudResource` objects. The engine stamps each as provenance evidence,
and :class:`CloudPostureCapability` evaluates them against misconfiguration
rules mapped to compliance controls.

Providers are injectable (real ``AWSProvider`` via boto3, or
``MockCloudProvider`` for tests / air-gapped runs), so nothing here needs the
network or credentials to be importable or testable.
"""
from .providers import (
    AWSProvider,
    CloudProvider,
    CloudResource,
    MockCloudProvider,
    build_cloud_provider,
)

__all__ = [
    "CloudResource",
    "CloudProvider",
    "AWSProvider",
    "MockCloudProvider",
    "build_cloud_provider",
]
