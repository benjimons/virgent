import json

from virgent.cli import main

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def seed_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "cfg.py").write_text(f'KEY = "{AWS_KEY}"\n')
    (repo / "requirements.txt").write_text("flask\n")
    return repo


def test_cli_init_ingest_scan_report_verify(tmp_path, capsys):
    wd = str(tmp_path / "wd")
    repo = seed_repo(tmp_path)

    assert main(["--workdir", wd, "init"]) == 0
    assert (tmp_path / "wd" / "policy.yaml").exists()

    assert main(["--workdir", wd, "ingest", str(repo)]) == 0
    assert main(["--workdir", wd, "scan"]) == 0
    out = capsys.readouterr().out
    assert "CRITICAL" in out

    assert main(["--workdir", wd, "report", "--format", "json",
                 "-o", str(tmp_path / "report.json")]) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["audit_attestation"]["chain_verified"] is True
    assert AWS_KEY not in (tmp_path / "report.json").read_text()
    capsys.readouterr()  # drain output from previous commands

    assert main(["--workdir", wd, "audit", "verify"]) == 0
    verify_out = json.loads(capsys.readouterr().out)
    assert verify_out["ok"] is True
    assert verify_out["records"] > 3


def test_cli_online_scan_requires_approval(tmp_path, capsys):
    wd = str(tmp_path / "wd")
    repo = seed_repo(tmp_path)
    main(["--workdir", wd, "init"])
    main(["--workdir", wd, "ingest", str(repo)])
    # without approval, --online is a policy violation (exit 3)
    assert main(["--workdir", wd, "scan", "--online"]) == 3
    assert "policy violation" in capsys.readouterr().err
