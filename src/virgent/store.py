"""Queryable index (SQLite).

The workdir's JSONL/JSON artifacts are the source of truth (append-only,
hash-chained, provable). This builds a fast, queryable SQLite index *over*
them so the API/console and reports can filter and count without rescanning
files — the read model to the audit log's write model. It is always
rebuildable from the artifacts, so it is a cache, never authoritative.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY, id TEXT, capability TEXT, severity TEXT,
    severity_rank INTEGER, title TEXT, location TEXT, controls TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, severity TEXT, status TEXT, priority TEXT,
    title TEXT, rules TEXT, created_at TEXT);
CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity_rank);
CREATE INDEX IF NOT EXISTS idx_find_cap ON findings(capability);
"""

_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def rebuild(self, findings: list, incidents: list) -> dict:
        """Rebuild the index from current findings + incidents."""
        cur = self.conn.cursor()
        cur.execute("DELETE FROM findings")
        cur.execute("DELETE FROM incidents")
        for f in findings:
            cur.execute(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                (f.fingerprint, f.id, f.capability, f.severity.value,
                 f.severity.rank, f.title, f.location, ",".join(f.controls), f.created_at))
        for i in incidents:
            cur.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?)",
                (i.id, i.severity.value, i.status, i.priority, i.title,
                 ",".join(i.rules), i.created_at))
        self.conn.commit()
        return {"findings": len(findings), "incidents": len(incidents)}

    def query_findings(self, severity: str | None = None, capability: str | None = None,
                       limit: int = 100) -> list[dict]:
        q = "SELECT * FROM findings"
        clauses, args = [], []
        if severity:
            clauses.append("severity_rank <= ?")
            args.append(_RANK.get(severity, 4))
        if capability:
            clauses.append("capability = ?")
            args.append(capability)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY severity_rank ASC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    def query_incidents(self, status: str | None = None, limit: int = 100) -> list[dict]:
        q = "SELECT * FROM incidents"
        args = []
        if status:
            q += " WHERE status = ?"
            args.append(status)
        q += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    def counts(self) -> dict:
        by_sev = {r["severity"]: r["n"] for r in self.conn.execute(
            "SELECT severity, COUNT(*) n FROM findings GROUP BY severity")}
        total = self.conn.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
        incidents = self.conn.execute("SELECT COUNT(*) n FROM incidents").fetchone()["n"]
        return {"findings_total": total, "findings_by_severity": by_sev,
                "incidents_total": incidents}

    def close(self) -> None:
        self.conn.close()
