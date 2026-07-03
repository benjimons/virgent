import json

from virgent.capabilities.dependencies import (
    DependencyAuditCapability,
    parse_package_json,
    parse_requirements,
)
from virgent.capabilities.iac import IaCCapability
from virgent.capabilities.secrets import SecretScanCapability
from virgent.models import Evidence, Severity


def ev(source, kind, content, filename=None):
    return Evidence(
        id=f"ev-test-{abs(hash(source)) % 10 ** 6}",
        source=source, kind=kind, content=content,
        sha256="0" * 64, collected_at="2026-01-01T00:00:00+00:00",
        metadata={"filename": filename or source.rsplit("/", 1)[-1]},
    )


# -- secrets -----------------------------------------------------------------

def test_secret_scan_finds_and_maps_controls():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    evidence = [ev("src/config.py", "code", f"KEY = '{aws}'\n")]
    findings = SecretScanCapability().analyze(evidence)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.location.endswith(":1")
    assert f.evidence_ids == [evidence[0].id]
    assert "NIST:IA-5" in f.controls
    assert aws not in f.description  # never leaks the secret


def test_secret_scan_skips_irrelevant_kinds():
    evidence = [ev("photo.bin", "binary", "AKIA" + "IOSFODNN7EXAMPLE")]
    assert SecretScanCapability().analyze(evidence) == []


# -- dependencies --------------------------------------------------------------

def test_parse_requirements():
    deps = parse_requirements("requests==2.31.0\nflask>=2.0\n# comment\n\n-r other.txt\n")
    assert {d["name"]: d["pinned"] for d in deps} == {"requests": True, "flask": False}


def test_parse_package_json():
    content = json.dumps({"dependencies": {"lodash": "^4.17.21", "left-pad": "1.3.0"}})
    deps = parse_package_json(content)
    by_name = {d["name"]: d for d in deps}
    assert not by_name["lodash"]["pinned"]
    assert by_name["left-pad"]["pinned"]


def test_dependency_vulns_via_injected_osv():
    def fake_osv(package, ecosystem, version):
        if package == "requests":
            return [{"id": "GHSA-xxxx", "aliases": ["CVE-2024-0001"],
                     "summary": "test vuln", "severity": [{"type": "CVSS_V3", "score": "HIGH"}]}]
        return []

    cap = DependencyAuditCapability(osv_query=fake_osv)
    evidence = [ev("requirements.txt", "config", "requests==2.19.0\n")]
    findings = cap.analyze(evidence)
    vuln = [f for f in findings if "GHSA-xxxx" in f.title]
    assert len(vuln) == 1
    assert vuln[0].severity == Severity.HIGH
    assert "OWASP:A06" in vuln[0].controls
    assert vuln[0].metadata["aliases"] == ["CVE-2024-0001"]


def test_unpinned_dependency_flagged_offline():
    cap = DependencyAuditCapability()
    findings = cap.analyze([ev("requirements.txt", "config", "flask\n")])
    assert len(findings) == 1
    assert "Unpinned" in findings[0].title


# -- IaC ------------------------------------------------------------------------

DOCKERFILE_BAD = """\
FROM ubuntu:latest
RUN curl -sSL https://example.com/install.sh | sh
ENV API_KEY=abc123def456
"""


def test_dockerfile_rules():
    findings = IaCCapability().analyze([ev("app/Dockerfile", "config", DOCKERFILE_BAD, "Dockerfile")])
    rules = {f.metadata["rule"] for f in findings}
    assert "docker-runs-as-root" in rules
    assert "docker-curl-pipe-sh" in rules
    assert "docker-secret-in-env" in rules


GHA_BAD = """\
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: someone/cool-action@main
      - run: echo "${{ secrets.DEPLOY_KEY }}"
"""


def test_github_actions_rules():
    evidence = [ev("repo/.github/workflows/ci.yml", "config", GHA_BAD, "ci.yml")]
    findings = IaCCapability().analyze(evidence)
    rules = {f.metadata["rule"] for f in findings}
    assert "gha-pull-request-target-checkout" in rules
    assert "gha-unpinned-action" in rules
    assert "gha-secret-echoed" in rules
    crit = [f for f in findings if f.metadata["rule"] == "gha-pull-request-target-checkout"]
    assert crit[0].severity == Severity.CRITICAL


K8S_BAD = """\
kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          securityContext:
            privileged: true
"""


def test_kubernetes_rules():
    findings = IaCCapability().analyze([ev("deploy/app.yaml", "config", K8S_BAD, "app.yaml")])
    rules = {f.metadata["rule"] for f in findings}
    assert "k8s-privileged" in rules
    assert "k8s-host-network" in rules
