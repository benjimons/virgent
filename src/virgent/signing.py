"""Detached signatures for portable attestation.

Signs artifacts (reports, SBOMs) with HMAC-SHA256 so their integrity and
origin can be verified anywhere, by anyone holding the key — the report's
audit attestation proves the *run*, this proves the *artifact*. The signing
key comes from ``VIRGENT_SIGNING_KEY`` (falling back to ``VIRGENT_AUDIT_KEY``);
signing is skipped, not faked, when no key is available.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from .models import sha256_hex, utcnow

SIGNING_KEY_ENV = "VIRGENT_SIGNING_KEY"
AUDIT_KEY_ENV = "VIRGENT_AUDIT_KEY"


def _key() -> bytes | None:
    k = os.environ.get(SIGNING_KEY_ENV) or os.environ.get(AUDIT_KEY_ENV)
    return k.encode("utf-8") if k else None


def sign_bytes(data: bytes, key: bytes | None = None) -> dict | None:
    key = key if key is not None else _key()
    if not key:
        return None
    digest = sha256_hex(data)
    sig = hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()
    return {"alg": "HMAC-SHA256", "sha256": digest, "sig": sig, "signed_at": utcnow()}


def verify_bytes(data: bytes, signature: dict, key: bytes | None = None) -> bool:
    key = key if key is not None else _key()
    if not key or not signature:
        return False
    if sha256_hex(data) != signature.get("sha256"):
        return False
    expected = hmac.new(key, signature["sha256"].encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature.get("sig", ""))


def sign_file(path: str | Path, key: bytes | None = None) -> Path | None:
    """Write ``<path>.sig`` (a detached JSON signature). Returns the sig path or None."""
    path = Path(path)
    sig = sign_bytes(path.read_bytes(), key)
    if sig is None:
        return None
    sig_path = path.with_suffix(path.suffix + ".sig")
    sig_path.write_text(json.dumps(sig, indent=2), encoding="utf-8")
    return sig_path


def verify_file(path: str | Path, key: bytes | None = None) -> bool:
    path = Path(path)
    sig_path = path.with_suffix(path.suffix + ".sig")
    if not sig_path.exists():
        return False
    return verify_bytes(path.read_bytes(), json.loads(sig_path.read_text()), key)
