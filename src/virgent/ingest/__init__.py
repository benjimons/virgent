"""Ingestion layer.

Ingestors turn external information sources (files, git history, web feeds,
logs, structured data) into :class:`RawItem` objects. The engine registers
each item with the provenance store — ingestors never bypass provenance.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class RawItem:
    source: str
    kind: str
    content: str
    metadata: dict = field(default_factory=dict)


class Ingestor(ABC):
    """Base class: a named source-type reader producing RawItems."""

    name: str = "abstract"

    @abstractmethod
    def collect(self, target: str) -> Iterable[RawItem]:
        """Yield items from ``target`` (a path, URL, or other locator)."""


from .files import FileIngestor          # noqa: E402
from .git_history import GitHistoryIngestor  # noqa: E402
from .host import HostIngestor              # noqa: E402
from .tail import TailIngestor              # noqa: E402
from .web import WebCollector, query_osv     # noqa: E402

__all__ = [
    "RawItem",
    "Ingestor",
    "FileIngestor",
    "GitHistoryIngestor",
    "HostIngestor",
    "TailIngestor",
    "WebCollector",
    "query_osv",
]
