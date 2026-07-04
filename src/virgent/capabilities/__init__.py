"""Security capabilities.

A capability analyzes evidence and produces findings. Each finding carries
its evidence IDs (provenance) and compliance-control mappings, so every
claim in a report is traceable to a hash-verified source.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..models import Evidence, Finding


class Capability(ABC):
    name: str = "abstract"
    description: str = ""

    @abstractmethod
    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        """Return findings for the given evidence."""


from .secrets import SecretScanCapability          # noqa: E402
from .dependencies import DependencyAuditCapability  # noqa: E402
from .iac import IaCCapability                      # noqa: E402
from .host import HostInspectionCapability          # noqa: E402
from .runtime import RuntimeInspectionCapability     # noqa: E402
from .cloud import CloudPostureCapability            # noqa: E402
from .identity import IdentityPostureCapability       # noqa: E402
from .llm_review import LLMReviewCapability         # noqa: E402

__all__ = [
    "Capability",
    "SecretScanCapability",
    "DependencyAuditCapability",
    "IaCCapability",
    "HostInspectionCapability",
    "RuntimeInspectionCapability",
    "CloudPostureCapability",
    "IdentityPostureCapability",
    "LLMReviewCapability",
]
