"""Offset-tracked log tailing.

Unlike :class:`FileIngestor`, which reads a whole file each time, the tail
ingestor remembers how far it has read into each log (byte offset + inode +
size) in a persistent state file, and on each call returns only the bytes
appended since last time. That is what lets ``virgent watch`` follow growing
logs (auth.log, syslog) forever without re-ingesting — and re-hashing — the
entire file every cycle.

Rotation and truncation are handled: if a file's inode changes (logrotate
moved it aside and created a fresh one) or its size shrank below the recorded
offset (it was truncated in place), tailing restarts from the beginning of the
new file so no lines are missed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterator

from . import Ingestor, RawItem


class TailIngestor(Ingestor):
    name = "tail"

    def __init__(self, state_path: str | Path, max_chunk_bytes: int = 5_000_000):
        self.state_path = Path(state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_chunk_bytes = max_chunk_bytes
        self._state: dict[str, dict] = {}
        if self.state_path.exists():
            try:
                self._state = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._state = {}

    def _save(self) -> None:
        self.state_path.write_text(
            json.dumps(self._state, indent=2, sort_keys=True), encoding="utf-8")

    def collect(self, target: str) -> Iterator[RawItem]:
        path = Path(target)
        try:
            st = path.stat()
        except OSError:
            return  # file gone/unreadable this cycle; try again next time
        key = str(path.resolve())
        prev = self._state.get(key, {})
        offset = int(prev.get("offset", 0))
        inode = getattr(st, "st_ino", 0)
        # rotation (new inode) or truncation (shrunk) → start over from 0
        if prev.get("inode") not in (None, inode) or st.st_size < offset:
            offset = 0
        if st.st_size <= offset:
            # nothing new; still refresh inode/size so rotation is detected next time
            self._state[key] = {"offset": offset, "inode": inode, "size": st.st_size}
            self._save()
            return
        try:
            with path.open("rb") as f:
                f.seek(offset)
                raw = f.read(self.max_chunk_bytes)
        except OSError:
            return
        new_offset = offset + len(raw)
        self._state[key] = {"offset": new_offset, "inode": inode, "size": st.st_size}
        self._save()
        text = raw.decode("utf-8", errors="replace")
        if not text.strip():
            return
        line_count = text.count("\n")
        yield RawItem(
            source=f"{path}#tail:{offset}-{new_offset}",
            kind="log",
            content=text,
            metadata={
                "filename": path.name,
                "tail_from": offset,
                "tail_to": new_offset,
                "lines": line_count,
            },
        )

    def watched(self) -> list[str]:
        return sorted(self._state)
