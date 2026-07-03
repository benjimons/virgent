from virgent.compliance.frameworks import CONTROLS, controls_for, coverage, frameworks
from virgent.compliance.report import generate_report
from virgent.models import Finding, Severity


def make_finding(i, controls):
    return Finding(
        id=f"fnd-test-{i:05d}", capability="test", title=f"finding {i}",
        description="d", severity=Severity.HIGH, evidence_ids=[f"ev-{i}"],
        controls=controls,
    )


def test_catalog_has_expected_frameworks():
    assert {"SOC2", "ISO27001", "NIST-800-53", "OWASP-Top10"} <= set(frameworks())


def test_coverage_matrix():
    findings = [
        make_finding(1, ["SOC2:CC6.1", "NIST:IA-5"]),
        make_finding(2, ["SOC2:CC6.1"]),
    ]
    matrix = coverage(findings)
    assert matrix["SOC2"]["SOC2:CC6.1"] == ["fnd-test-00001", "fnd-test-00002"]
    assert matrix["NIST-800-53"]["NIST:IA-5"] == ["fnd-test-00001"]


def test_controls_for_unknown_id():
    out = controls_for(["MADEUP:1"])
    assert out[0]["framework"] == "unknown"


def test_report_contains_all_sections():
    findings = [make_finding(1, ["SOC2:CC6.1"])]
    prov = [{
        "evidence_id": "ev-1", "source": "a.py", "kind": "code",
        "sha256": "ab" * 32, "collected_at": "2026-01-01T00:00:00+00:00",
        "method": "ingest.file",
    }]
    attestation = {
        "records": 3, "head_hash": "cd" * 32, "chain_verified": True,
        "signed": False, "verified_at": "2026-01-01T00:00:00+00:00",
    }
    md = generate_report(findings, prov, attestation, {"actor": "test"})
    for section in ("Executive Summary", "Findings", "Compliance Control Coverage",
                    "Evidence & Provenance", "Audit Chain Attestation"):
        assert section in md
    assert "SOC2:CC6.1" in md
    assert CONTROLS["SOC2:CC6.1"]["title"] in md
    assert attestation["head_hash"] in md
