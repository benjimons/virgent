"""Tamper-evident audit log.

Every action the agent takes is appended to a JSONL file where each record
is linked to its predecessor by a SHA-256 hash chain (blockchain-style).
Optionally each record also carries an HMAC-SHA256 signature computed with a
key held outside the log (``VIRGENT_AUDIT_KEY``), so an attacker who can
rewrite the file but does not hold the key cannot forge a valid chain.

Guarantees provided (given the log file and, for signatures, the key):
  * append-only ordering (monotonic ``seq``)
  * integrity of every record (recomputable ``hash``)
  * continuity (each ``prev_hash`` must equal the prior record's ``hash``)
  * authenticity when HMAC is enabled

The log never stores raw secrets: callers are expected to pass parameters
through :mod:`virgent.redaction` first (the engine does this centrally).
"""
from __future__ import annotations

import hmac
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .models import Actor, canonical_json, sha256_hex, utcnow

GENESIS_HASH = "0" * 64
AUDIT_KEY_ENV = "VIRGENT_AUDIT_KEY"


@dataclass
class VerificationResult:
    ok: bool
    records: int
    errors: list[str] = field(default_factory=list)
    head_hash: str = GENESIS_HASH

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "records": self.records,
            "errors": self.errors,
            "head_hash": self.head_hash,
        }


class AuditLog:
    """Append-only, hash-chained audit log stored as JSONL."""

    def __init__(self, path: str | Path, actor: Actor, hmac_key: bytes | None = None):
        self.path = Path(path)
        self.actor = actor
        if hmac_key is None:
            env_key = os.environ.get(AUDIT_KEY_ENV)
            hmac_key = env_key.encode("utf-8") if env_key else None
        self._hmac_key = hmac_key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = self._load_tail()

    # -- internal -----------------------------------------------------------

    def _load_tail(self) -> tuple[int, str]:
        """Resume the chain from an existing log file."""
        if not self.path.exists():
            return 0, GENESIS_HASH
        seq, head = 0, GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                seq = rec["seq"]
                head = rec["hash"]
        return seq, head

    @staticmethod
    def _record_hash(record: dict) -> str:
        body = {k: v for k, v in record.items() if k not in ("hash", "sig")}
        return sha256_hex(canonical_json(body))

    def _sign(self, record_hash: str) -> str | None:
        if not self._hmac_key:
            return None
        return hmac.new(self._hmac_key, record_hash.encode("ascii"), hashlib.sha256).hexdigest()

    # -- public API ---------------------------------------------------------

    @property
    def head_hash(self) -> str:
        return self._head

    @property
    def count(self) -> int:
        return self._seq

    def record(
        self,
        action: str,
        params: dict | None = None,
        outcome: str = "success",
        detail: str = "",
        actor: Actor | None = None,
    ) -> dict:
        """Append an audit record and return it."""
        self._seq += 1
        rec: dict[str, Any] = {
            "seq": self._seq,
            "ts": utcnow(),
            "actor": (actor or self.actor).to_dict(),
            "action": action,
            "params": params or {},
            "outcome": outcome,
            "detail": detail,
            "prev_hash": self._head,
        }
        rec["hash"] = self._record_hash(rec)
        sig = self._sign(rec["hash"])
        if sig:
            rec["sig"] = sig
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._head = rec["hash"]
        return rec

    def iter_records(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def export(self) -> list[dict]:
        return list(self.iter_records())

    def verify(self, require_signatures: bool | None = None) -> VerificationResult:
        """Walk the chain and validate hashes, continuity, and signatures.

        ``require_signatures`` defaults to True when an HMAC key is available.
        """
        if require_signatures is None:
            require_signatures = self._hmac_key is not None
        errors: list[str] = []
        prev = GENESIS_HASH
        expected_seq = 0
        head = GENESIS_HASH
        n = 0
        for rec in self.iter_records():
            n += 1
            expected_seq += 1
            seq = rec.get("seq")
            if seq != expected_seq:
                errors.append(f"record {n}: sequence gap (expected {expected_seq}, got {seq})")
                expected_seq = seq if isinstance(seq, int) else expected_seq
            if rec.get("prev_hash") != prev:
                errors.append(f"seq {seq}: chain break (prev_hash mismatch)")
            recomputed = self._record_hash(rec)
            if rec.get("hash") != recomputed:
                errors.append(f"seq {seq}: record hash mismatch (content altered)")
            if self._hmac_key is not None:
                sig = rec.get("sig")
                expected_sig = self._sign(rec.get("hash", ""))
                if require_signatures and not sig:
                    errors.append(f"seq {seq}: missing signature")
                elif sig and not hmac.compare_digest(sig, expected_sig or ""):
                    errors.append(f"seq {seq}: HMAC signature invalid")
            prev = rec.get("hash", prev)
            head = prev
        return VerificationResult(ok=not errors, records=n, errors=errors, head_hash=head)

    def attestation(self) -> dict:
        """Compact statement of the log's current state, for reports."""
        result = self.verify()
        return {
            "records": result.records,
            "head_hash": result.head_hash,
            "chain_verified": result.ok,
            "signed": self._hmac_key is not None,
            "verified_at": utcnow(),
        }
