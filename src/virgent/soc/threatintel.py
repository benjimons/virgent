"""Threat-intelligence enrichment.

Matches alert entities (IPs, domains, file hashes) against known-bad
indicators and enriches the alert — raising severity and tagging the source —
so a brute-force from a known C2 node stands out from background noise. The
feed is injectable (a dict, a file, or a lookup callable), so enrichment is
testable offline and can be wired to any real intel source (MISP, OTX,
commercial) without touching detection.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Severity

# severity bump when an alert matches a malicious indicator
_BUMP = {
    Severity.INFO: Severity.LOW, Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH, Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}


@dataclass
class ThreatIntel:
    """indicator (ip/domain/hash) -> {malicious, source, tags, ...}."""

    indicators: dict = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path) -> "ThreatIntel":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        # accept {indicators: {...}} or a bare mapping
        return cls(indicators=data.get("indicators", data) if isinstance(data, dict) else {})

    def lookup(self, indicator: str) -> dict | None:
        return self.indicators.get(indicator)

    def enrich_alerts(self, alerts: list) -> int:
        """Enrich matching alerts in place. Returns the number enriched."""
        enriched = 0
        for a in alerts:
            hits = []
            for value in a.entities.values():
                if isinstance(value, str):
                    intel = self.lookup(value)
                    if intel and intel.get("malicious", True):
                        hits.append((value, intel))
            if not hits:
                continue
            enriched += 1
            a.severity = _BUMP.get(a.severity, a.severity)
            tags = sorted({t for _, i in hits for t in i.get("tags", [])})
            sources = sorted({i.get("source", "intel") for _, i in hits})
            a.description += (f" [threat-intel: matched {', '.join(v for v, _ in hits)} "
                              f"— {', '.join(sources)}" + (f"; tags: {', '.join(tags)}" if tags else "") + "]")
        return enriched
