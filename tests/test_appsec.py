"""SAST, container image scanning, SBOM generation, and artifact signing."""
import json

from virgent.capabilities.image import ImageScanCapability, check_image
from virgent.capabilities.sast import SASTCapability
from virgent.engine import SecurityAgent
from virgent.models import Actor, Evidence, Severity
from virgent.sbom import generate_sbom
from virgent.signing import sign_bytes, verify_bytes

ACTOR = Actor(id="test", type="system")


def code_ev(source, content, filename=None):
    return Evidence(id=f"ev-{abs(hash(source)) % 10**6}", source=source, kind="code",
                    content=content, sha256="0"*64,
                    collected_at="2026-01-01T00:00:00+00:00",
                    metadata={"filename": filename or source.rsplit("/", 1)[-1]})


# -- SAST ---------------------------------------------------------------------

def test_sast_python_rules():
    content = (
        "import os, pickle, subprocess, hashlib\n"
        "def h(req):\n"
        "    os.system('ping ' + req.args['host'])\n"
        "    subprocess.run(cmd, shell=True)\n"
        "    cur.execute('SELECT * FROM u WHERE n=' + req.args['n'])\n"
        "    pickle.loads(req.data)\n"
        "    hashlib.md5(pw).hexdigest()\n"
        "    requests.get(url, verify=False)\n"
    )
    findings = SASTCapability().analyze([code_ev("app.py", content)])
    rules = {f.metadata["rule"] for f in findings}
    assert "py-command-injection" in rules
    assert "py-subprocess-shell" in rules
    assert "py-sql-injection" in rules
    assert "py-insecure-deserialization" in rules
    assert "py-weak-hash" in rules
    assert "py-tls-verification-disabled" in rules
    # each finding carries a CWE
    assert all(f.metadata.get("cwe") for f in findings)


def test_sast_js_rules():
    content = "el.innerHTML = req.query.name;\nchild_process.exec('ls ' + req.query.dir);\n"
    findings = SASTCapability().analyze([code_ev("app.js", content)])
    rules = {f.metadata["rule"] for f in findings}
    assert "js-xss-innerhtml" in rules
    assert "js-command-injection" in rules


def test_sast_ignores_safe_code():
    content = "import json\ndata = json.loads(payload)\nyaml.safe_load(x)\n"
    findings = SASTCapability().analyze([code_ev("ok.py", content)])
    assert findings == []


# -- image --------------------------------------------------------------------

def test_image_rules():
    content = (
        "FROM ubuntu:22.04\n"
        "RUN apt-get install -y curl wget\n"
        "RUN pip install flask requests\n"
        "ADD https://example.com/x.sh /x.sh\n"
        "RUN pip install foo --trusted-host pypi.org\n"
    )
    rules = {i[0] for i in check_image(content)}
    assert "image-unpinned-os-package" in rules
    assert "image-unpinned-pip" in rules
    assert "image-remote-add" in rules
    assert "image-integrity-check-disabled" in rules


def test_image_capability_only_dockerfiles():
    ev = Evidence(id="ev-1", source="x/Dockerfile", kind="config",
                  content="FROM ubuntu:22.04\nRUN apt-get install -y curl\n",
                  sha256="0"*64, collected_at="2026-01-01T00:00:00+00:00",
                  metadata={"filename": "Dockerfile"})
    findings = ImageScanCapability().analyze([ev])
    assert findings and findings[0].metadata["rule"] == "image-unpinned-os-package"


# -- SBOM ---------------------------------------------------------------------

def req_ev():
    return Evidence(id="ev-req", source="requirements.txt", kind="config",
                    content="flask==2.3.0\nrequests>=2.0\n", sha256="0"*64,
                    collected_at="2026-01-01T00:00:00+00:00",
                    metadata={"filename": "requirements.txt"})


def test_sbom_cyclonedx_shape_and_determinism():
    bom1 = generate_sbom([req_ev()], name="app", timestamp="2026-01-01T00:00:00+00:00")
    assert bom1["bomFormat"] == "CycloneDX"
    assert bom1["specVersion"] == "1.5"
    names = {c["name"] for c in bom1["components"]}
    assert {"flask", "requests"} <= names
    flask = next(c for c in bom1["components"] if c["name"] == "flask")
    assert flask["purl"] == "pkg:pypi/flask@2.3.0"
    # deterministic serial for the same components
    bom2 = generate_sbom([req_ev()], name="app", timestamp="2026-01-01T00:00:00+00:00")
    assert bom1["serialNumber"] == bom2["serialNumber"]


def test_engine_sbom_generate_audited(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
    agent.ingest(str(tmp_path / "requirements.txt"))
    bom = agent.generate_sbom(output=str(tmp_path / "sbom.json"))
    assert (tmp_path / "sbom.json").exists()
    assert any(c["name"] == "flask" for c in bom["components"])
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "sbom.generate" in actions


# -- signing ------------------------------------------------------------------

def test_sign_and_verify_roundtrip():
    data = b"attested report bytes"
    sig = sign_bytes(data, key=b"k")
    assert sig and sig["alg"] == "HMAC-SHA256"
    assert verify_bytes(data, sig, key=b"k")
    assert not verify_bytes(b"tampered", sig, key=b"k")
    assert not verify_bytes(data, sig, key=b"wrong-key")


def test_sign_returns_none_without_key():
    assert sign_bytes(b"x", key=None) is None


def test_engine_sign_artifact(tmp_path, monkeypatch):
    monkeypatch.setenv("VIRGENT_SIGNING_KEY", "sign-key")
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    report = tmp_path / "report.md"
    report.write_text("# report\n")
    r = agent.sign_artifact(str(report))
    assert r["signed"]
    from virgent.signing import verify_file
    assert verify_file(str(report))
