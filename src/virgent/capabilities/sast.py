"""Static application security testing (taint-style heuristics).

Flags dangerous sinks reached with dynamic/untrusted input — command and code
injection, SQL string-building, insecure deserialization, disabled TLS
verification, and weak cryptography. This is heuristic (line-level), not full
interprocedural dataflow, so findings carry a CWE and are marked for review;
they map to secure-coding and injection controls.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..models import Evidence, Finding, Severity, new_finding_id
from . import Capability

CODING_CONTROLS = ["ISO27001:A.8.28", "OWASP:A03"]
DESERIAL_CONTROLS = ["ISO27001:A.8.28", "OWASP:A08"]
CRYPTO_CONTROLS = ["ISO27001:A.8.24", "OWASP:A02"]

# indicators that a call argument is dynamic/untrusted (not a pure literal)
_TAINT = r"(?:request|input\(|sys\.argv|os\.environ|params|payload|body|\.get\(|" \
         r"f['\"]|%\s|\.format\(|\+\s*\w|\{.*\})"


def _line(content: str, idx: int) -> int:
    return content.count("\n", 0, idx) + 1


# (rule, regex, severity, controls, cwe, title, remediation)
PY_RULES = [
    ("py-code-injection", re.compile(rf"\b(?:eval|exec)\([^)\n]*{_TAINT}", re.I),
     Severity.HIGH, CODING_CONTROLS, "CWE-95",
     "Dynamic code execution (eval/exec) on untrusted input",
     "Never eval/exec untrusted input; use safe parsers or explicit dispatch."),
    ("py-command-injection", re.compile(rf"\bos\.system\([^)\n]*{_TAINT}", re.I),
     Severity.HIGH, CODING_CONTROLS, "CWE-78",
     "OS command built from untrusted input",
     "Use subprocess with an argument list and shell=False; never interpolate input."),
    ("py-subprocess-shell", re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\([^\n]*shell\s*=\s*True"),
     Severity.HIGH, CODING_CONTROLS, "CWE-78",
     "subprocess called with shell=True",
     "Pass an argument list and shell=False; shell=True enables command injection."),
    ("py-sql-injection", re.compile(rf"\b(?:execute|executemany)\([^)\n]*(?:select|insert|update|delete)[^)\n]*(?:{_TAINT})", re.I),
     Severity.HIGH, CODING_CONTROLS, "CWE-89",
     "SQL query built by string concatenation/formatting",
     "Use parameterized queries / bound parameters, never string building."),
    ("py-insecure-deserialization", re.compile(r"\b(?:pickle|cPickle|_pickle|dill|shelve)\.loads?\(|\byaml\.load\((?![^)\n]*Safe)"),
     Severity.HIGH, DESERIAL_CONTROLS, "CWE-502",
     "Insecure deserialization of untrusted data",
     "Use safe formats (JSON) or yaml.safe_load; never unpickle untrusted data."),
    ("py-tls-verification-disabled", re.compile(r"verify\s*=\s*False|ssl\._create_unverified_context|CERT_NONE"),
     Severity.MEDIUM, ["OWASP:A02", "NIST:SC-8"], "CWE-295",
     "TLS certificate verification disabled",
     "Enable certificate verification; pin or trust a proper CA bundle."),
    ("py-weak-hash", re.compile(r"\bhashlib\.(?:md5|sha1)\(|\bMD5\b|\bSHA1\b"),
     Severity.MEDIUM, CRYPTO_CONTROLS, "CWE-327",
     "Weak hashing algorithm (MD5/SHA1)",
     "Use SHA-256+; for passwords use a KDF (bcrypt/scrypt/argon2)."),
    ("py-insecure-temp", re.compile(r"\btempfile\.mktemp\("),
     Severity.LOW, CODING_CONTROLS, "CWE-377",
     "Insecure temporary file (mktemp)",
     "Use tempfile.mkstemp or NamedTemporaryFile."),
]

JS_RULES = [
    ("js-code-injection", re.compile(rf"\beval\([^)\n]*{_TAINT}|new Function\(", re.I),
     Severity.HIGH, CODING_CONTROLS, "CWE-95",
     "Dynamic code execution (eval/Function) on untrusted input",
     "Avoid eval/new Function on input; use safe parsing."),
    ("js-command-injection", re.compile(rf"child_process\.(?:exec|execSync)\([^)\n]*{_TAINT}", re.I),
     Severity.HIGH, CODING_CONTROLS, "CWE-78",
     "Shell command built from untrusted input",
     "Use execFile/spawn with an argument array; never interpolate input into a shell."),
    ("js-xss-innerhtml", re.compile(r"\.innerHTML\s*=\s*(?![\"'`\s])", re.I),
     Severity.MEDIUM, ["OWASP:A03", "ISO27001:A.8.28"], "CWE-79",
     "DOM XSS via innerHTML assigned a non-literal value",
     "Use textContent or a sanitizer; never assign untrusted HTML."),
]


def _scan(content: str, rules) -> list[dict]:
    issues = []
    for rule, pattern, severity, controls, cwe, title, remediation in rules:
        for m in pattern.finditer(content):
            issues.append({"rule": rule, "line": _line(content, m.start()),
                           "severity": severity, "controls": controls, "cwe": cwe,
                           "title": title, "remediation": remediation})
    return issues


class SASTCapability(Capability):
    name = "sast"
    description = "Static analysis for injection, insecure deserialization, weak crypto, and disabled TLS"

    def analyze(self, evidence: Iterable[Evidence]) -> list[Finding]:
        findings: list[Finding] = []
        seq = 0
        for ev in evidence:
            if ev.kind != "code":
                continue
            name = ev.metadata.get("filename", ev.source).lower()
            if name.endswith(".py"):
                issues = _scan(ev.content, PY_RULES)
            elif name.endswith((".js", ".ts", ".jsx", ".tsx")):
                issues = _scan(ev.content, JS_RULES)
            else:
                continue
            for issue in issues:
                seq += 1
                findings.append(Finding(
                    id=new_finding_id(self.name, seq), capability=self.name,
                    title=f"{issue['title']} ({ev.source}:{issue['line']})",
                    description=f"SAST rule '{issue['rule']}' ({issue['cwe']}) matched at "
                                f"{ev.source}:{issue['line']}.",
                    severity=issue["severity"], evidence_ids=[ev.id],
                    location=f"{ev.source}:{issue['line']}",
                    controls=list(issue["controls"]), confidence="medium",
                    remediation=issue["remediation"],
                    metadata={"rule": issue["rule"], "cwe": issue["cwe"]}))
        return findings
