"""Filesystem ingestion: source trees, configs, logs, structured data."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator

from . import Ingestor, RawItem

DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".virgent",
}

KIND_BY_SUFFIX = {
    ".py": "code", ".js": "code", ".ts": "code", ".tsx": "code", ".jsx": "code",
    ".go": "code", ".rb": "code", ".java": "code", ".cs": "code", ".php": "code",
    ".c": "code", ".cpp": "code", ".h": "code", ".rs": "code", ".sh": "code",
    ".yaml": "config", ".yml": "config", ".toml": "config", ".ini": "config",
    ".cfg": "config", ".conf": "config", ".env": "config", ".tf": "config",
    ".json": "data", ".csv": "data", ".xml": "data", ".ndjson": "data",
    ".log": "log",
    ".md": "text", ".txt": "text", ".rst": "text",
}

SPECIAL_FILENAMES = {
    "dockerfile": "config",
    "makefile": "config",
    "requirements.txt": "config",
    "package.json": "config",
    "pipfile": "config",
    ".gitlab-ci.yml": "config",
}


def classify(path: Path) -> str:
    name = path.name.lower()
    if name in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[name]
    return KIND_BY_SUFFIX.get(path.suffix.lower(), "text")


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


class FileIngestor(Ingestor):
    name = "file"

    def __init__(
        self,
        max_bytes: int = 1_000_000,
        excludes: Iterable[str] | None = None,
    ):
        self.max_bytes = max_bytes
        self.excludes = set(excludes) if excludes is not None else set(DEFAULT_EXCLUDES)

    def _iter_paths(self, root: Path) -> Iterator[Path]:
        if root.is_file():
            yield root
            return
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(root).parts
            if any(part in self.excludes for part in rel_parts):
                continue
            yield path

    def collect(self, target: str) -> Iterator[RawItem]:
        root = Path(target)
        if not root.exists():
            raise FileNotFoundError(target)
        for path in self._iter_paths(root):
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if len(raw) > self.max_bytes or _is_binary(raw[:8192]):
                continue
            yield RawItem(
                source=str(path),
                kind=classify(path),
                content=raw.decode("utf-8", errors="replace"),
                metadata={"size_bytes": len(raw), "filename": path.name},
            )
