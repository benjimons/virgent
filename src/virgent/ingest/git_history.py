"""Git history ingestion: commits become evidence with full provenance.

Useful for supply-chain review (who changed what, when) and for scanning
history for secrets that were committed and later removed.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterator

from . import Ingestor, RawItem

FIELD_SEP = "\x1f"
RECORD_SEP = "\x1e"


class GitHistoryIngestor(Ingestor):
    name = "git"

    def __init__(self, max_commits: int = 200, include_patch: bool = False):
        self.max_commits = max_commits
        self.include_patch = include_patch

    def _run_git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git {' '.join(args[:2])} failed: {result.stderr.strip()}")
        return result.stdout

    def collect(self, target: str) -> Iterator[RawItem]:
        repo = Path(target)
        fmt = FIELD_SEP.join(["%H", "%an", "%ae", "%aI", "%s", "%b"]) + RECORD_SEP
        out = self._run_git(
            repo, "log", f"--max-count={self.max_commits}", f"--pretty=format:{fmt}", "--numstat",
        )
        for chunk in out.split(RECORD_SEP):
            chunk = chunk.strip("\n")
            if not chunk.strip():
                continue
            head, _, stats = chunk.partition("\n")
            parts = head.split(FIELD_SEP)
            if len(parts) < 5:
                continue
            commit, author, email, date, subject = parts[0], parts[1], parts[2], parts[3], parts[4]
            body = parts[5] if len(parts) > 5 else ""
            content_lines = [
                f"commit {commit}",
                f"author {author} <{email}>",
                f"date {date}",
                f"subject {subject}",
            ]
            if body.strip():
                content_lines.append(f"body {body.strip()}")
            if stats.strip():
                content_lines.append("changes:")
                content_lines.append(stats.strip())
            if self.include_patch:
                try:
                    patch = self._run_git(repo, "show", "--format=", commit)
                    content_lines.append("patch:")
                    content_lines.append(patch[:100_000])
                except RuntimeError:
                    pass
            yield RawItem(
                source=f"git:{repo}#{commit}",
                kind="commit",
                content="\n".join(content_lines),
                metadata={
                    "commit": commit,
                    "author": author,
                    "email": email,
                    "date": date,
                    "subject": subject,
                },
            )
