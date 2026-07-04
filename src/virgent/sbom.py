"""Software Bill of Materials (CycloneDX) generation.

Builds a CycloneDX 1.5 SBOM from the dependency inventory Virgent already
parses (requirements.txt / package.json). The serial number is derived
deterministically from the component set, so the same inputs produce the same
SBOM (reproducible, diffable, signable).
"""
from __future__ import annotations

import json

from .capabilities.dependencies import parse_package_json, parse_requirements
from .models import Evidence, sha256_hex, utcnow

_ECOSYSTEM_PURL = {"PyPI": "pypi", "npm": "npm"}


def _component(dep: dict) -> dict:
    eco = _ECOSYSTEM_PURL.get(dep["ecosystem"], dep["ecosystem"].lower())
    version = dep.get("version", "")
    purl = f"pkg:{eco}/{dep['name']}" + (f"@{version}" if version else "")
    return {
        "type": "library",
        "name": dep["name"],
        "version": version,
        "purl": purl,
        "bom-ref": purl,
        "properties": [
            {"name": "virgent:pinned", "value": str(bool(dep.get("pinned")))},
            {"name": "virgent:ecosystem", "value": dep["ecosystem"]},
        ],
    }


def components_from_evidence(evidence: list[Evidence]) -> list[dict]:
    comps: dict[str, dict] = {}
    for ev in evidence:
        filename = ev.metadata.get("filename", ev.source).lower()
        deps = []
        if filename.endswith("requirements.txt"):
            deps = parse_requirements(ev.content)
        elif filename.endswith("package.json"):
            deps = parse_package_json(ev.content)
        for dep in deps:
            c = _component(dep)
            comps[c["bom-ref"]] = c
    return [comps[k] for k in sorted(comps)]


def generate_sbom(evidence: list[Evidence], name: str = "virgent-target",
                  version: str = "0.0.0", timestamp: str | None = None) -> dict:
    components = components_from_evidence(evidence)
    serial = "urn:uuid:" + sha256_hex(json.dumps(
        [c["bom-ref"] for c in components], sort_keys=True))[:32]
    # format as a UUID-ish string
    s = serial.split(":")[-1]
    serial = f"urn:uuid:{s[:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp or utcnow(),
            "tools": [{"vendor": "Virgent", "name": "virgent", "version": "0.1.0"}],
            "component": {"type": "application", "name": name, "version": version},
        },
        "components": components,
    }
