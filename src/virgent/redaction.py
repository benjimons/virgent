"""Secret redaction (data-loss prevention).

Applied to anything that leaves the trust boundary — LLM prompts, audit-log
parameters, reports — so raw credentials are never persisted or transmitted.
The same pattern catalog powers the secret-scanning capability, which needs
line numbers rather than redaction.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

# (kind, compiled pattern). Order matters: more specific first.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(r"(?i)\baws(?:.{0,20})?(?:secret|private).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("gcp-service-account", re.compile(r'"private_key_id"\s*:\s*"[0-9a-f]{40}"')),
    ("azure-client-secret", re.compile(r"(?i)\b[A-Za-z0-9~_\-.]{3}\dQ~[A-Za-z0-9~_\-.]{31,34}\b")),
    ("azure-storage-key", re.compile(r"(?i)AccountKey=[A-Za-z0-9+/]{86}==")),
    ("twilio-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS[A-Za-z0-9_\-]{50,}\b")),
    ("datadog-key", re.compile(r"(?i)\bdd[a-z]{0,3}_[A-Za-z0-9]{32,40}\b")),
    ("digitalocean-token", re.compile(r"\bdop_v1_[0-9a-f]{64}\b")),
    ("hashicorp-vault-token", re.compile(r"\bhv[sb]\.[A-Za-z0-9_\-]{24,}\b")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("discord-webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("square-token", re.compile(r"\b(?:sq0atp|sq0csp|EAAA)[A-Za-z0-9_\-]{20,}\b")),
    ("mailgun-key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-.=+/]{20,}")),
    ("basic-auth-url", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@")),
    ("generic-assignment", re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)\b"
        r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
    )),
]

_PLACEHOLDER_VALUES = re.compile(
    r"(?i)^(\$\{.*\}|\$[A-Z_]+|<[^>]+>|\{\{.*\}\}|x+|\*+|change_?me.*|your[-_].*|placeholder|example.*|dummy.*|test)$"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_VALUES.match(value.strip()))


@dataclass
class SecretMatch:
    kind: str
    line: int          # 1-based line number of the match start
    excerpt: str       # redacted excerpt safe to store


def find_secrets(text: str) -> list[SecretMatch]:
    """Locate secrets in ``text`` without exposing their values."""
    matches: list[SecretMatch] = []
    claimed: list[tuple[int, int]] = []
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            span = m.span()
            if any(s < span[1] and span[0] < e for s, e in claimed):
                continue
            if kind == "generic-assignment":
                value = m.group(2)
                if looks_like_placeholder(value) or shannon_entropy(value) < 2.5:
                    continue
            claimed.append(span)
            line = text.count("\n", 0, m.start()) + 1
            line_text = text.splitlines()[line - 1] if text.splitlines() else ""
            excerpt, _ = redact(line_text)
            matches.append(SecretMatch(kind=kind, line=line, excerpt=excerpt.strip()[:200]))
    matches.sort(key=lambda s: s.line)
    return matches


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Replace secret material with ``[REDACTED:<kind>]`` placeholders.

    Returns the redacted text and a count of redactions per kind.
    """
    counts: dict[str, int] = {}
    out = text
    for kind, pattern in SECRET_PATTERNS:
        def _sub(m: re.Match, kind=kind) -> str:
            if kind == "generic-assignment":
                value = m.group(2)
                if looks_like_placeholder(value) or shannon_entropy(value) < 2.5:
                    return m.group(0)
                counts[kind] = counts.get(kind, 0) + 1
                return m.group(0).replace(value, f"[REDACTED:{kind}]")
            counts[kind] = counts.get(kind, 0) + 1
            return f"[REDACTED:{kind}]"
        out = pattern.sub(_sub, out)
    return out, counts


def redact_mapping(obj):
    """Recursively redact every string value in a JSON-like structure."""
    if isinstance(obj, str):
        return redact(obj)[0]
    if isinstance(obj, dict):
        return {k: redact_mapping(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_mapping(v) for v in obj]
    return obj
