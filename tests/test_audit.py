import json

import pytest

from virgent.audit import AuditLog, GENESIS_HASH
from virgent.models import Actor

ACTOR = Actor(id="test", type="system")


@pytest.fixture
def log(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl", actor=ACTOR, hmac_key=b"test-key")


def test_chain_verifies_clean(log):
    for i in range(5):
        log.record(f"action.{i}", params={"i": i})
    result = log.verify()
    assert result.ok
    assert result.records == 5
    assert result.head_hash == log.head_hash


def test_genesis_prev_hash(log):
    rec = log.record("first")
    assert rec["prev_hash"] == GENESIS_HASH


def test_tampered_record_detected(log, tmp_path):
    for i in range(4):
        log.record(f"action.{i}", params={"i": i})
    path = tmp_path / "audit.jsonl"
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["params"]["i"] = 999  # rewrite history
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    result = AuditLog(path, actor=ACTOR, hmac_key=b"test-key").verify()
    assert not result.ok
    assert any("seq 2" in e and "hash mismatch" in e for e in result.errors)


def test_deleted_record_breaks_chain(log, tmp_path):
    for i in range(4):
        log.record(f"action.{i}")
    path = tmp_path / "audit.jsonl"
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    result = AuditLog(path, actor=ACTOR, hmac_key=b"test-key").verify()
    assert not result.ok
    assert any("sequence gap" in e or "chain break" in e for e in result.errors)


def test_forged_chain_without_key_fails_hmac(tmp_path):
    # Attacker rewrites a record AND recomputes the whole hash chain,
    # but cannot forge HMAC signatures without the key.
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, actor=ACTOR, hmac_key=b"secret")
    log.record("a", params={"x": 1})
    log.record("b", params={"x": 2})

    lines = [json.loads(l) for l in path.read_text().splitlines()]
    lines[0]["params"]["x"] = 42
    prev = GENESIS_HASH
    for rec in lines:
        rec["prev_hash"] = prev
        rec["hash"] = AuditLog._record_hash(rec)
        prev = rec["hash"]
        # attacker leaves old sig or strips it; either way verification fails
    path.write_text("\n".join(json.dumps(r) for r in lines) + "\n")

    result = AuditLog(path, actor=ACTOR, hmac_key=b"secret").verify()
    assert not result.ok
    assert any("HMAC" in e or "signature" in e for e in result.errors)


def test_resume_chain_across_instances(tmp_path):
    path = tmp_path / "audit.jsonl"
    log1 = AuditLog(path, actor=ACTOR, hmac_key=b"k")
    log1.record("one")
    log2 = AuditLog(path, actor=ACTOR, hmac_key=b"k")
    log2.record("two")
    result = log2.verify()
    assert result.ok
    assert result.records == 2


def test_attestation_shape(log):
    log.record("x")
    att = log.attestation()
    assert att["chain_verified"] is True
    assert att["records"] == 1
    assert att["signed"] is True
    assert len(att["head_hash"]) == 64
