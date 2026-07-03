"""Case management: persistence for alerts, incidents, and responses.

Alerts and incidents have stable IDs, so re-running detection updates the
same records rather than duplicating them — and human state on an incident
(status, triage summary, notes) survives across runs.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Alert, Incident


class Casebook:
    def __init__(self, directory: str | Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.alerts_path = self.dir / "alerts.json"
        self.incidents_path = self.dir / "incidents.json"
        self.responses_path = self.dir / "responses.jsonl"
        self._alerts: dict[str, Alert] = {}
        self._incidents: dict[str, Incident] = {}
        self._load()

    def _load(self) -> None:
        if self.alerts_path.exists():
            for aid, d in json.loads(self.alerts_path.read_text(encoding="utf-8")).items():
                self._alerts[aid] = Alert.from_dict(d)
        if self.incidents_path.exists():
            for iid, d in json.loads(self.incidents_path.read_text(encoding="utf-8")).items():
                self._incidents[iid] = Incident.from_dict(d)

    def _save_alerts(self) -> None:
        self.alerts_path.write_text(json.dumps(
            {k: v.to_dict() for k, v in self._alerts.items()},
            indent=2, sort_keys=True, default=str), encoding="utf-8")

    def _save_incidents(self) -> None:
        self.incidents_path.write_text(json.dumps(
            {k: v.to_dict() for k, v in self._incidents.items()},
            indent=2, sort_keys=True, default=str), encoding="utf-8")

    # -- alerts -------------------------------------------------------------

    def upsert_alerts(self, alerts: list[Alert]) -> None:
        for a in alerts:
            self._alerts[a.id] = a
        self._save_alerts()

    def all_alerts(self) -> list[Alert]:
        return list(self._alerts.values())

    # -- incidents ----------------------------------------------------------

    def merge_incidents(self, incidents: list[Incident]) -> list[Incident]:
        """Merge freshly-correlated incidents, preserving human state."""
        for inc in incidents:
            existing = self._incidents.get(inc.id)
            if existing:
                # keep human-owned fields; refresh machine-owned fields
                inc.status = existing.status
                inc.summary = existing.summary or inc.summary
                inc.notes = existing.notes
                inc.created_at = existing.created_at
            self._incidents[inc.id] = inc
        self._save_incidents()
        return self.all_incidents()

    def all_incidents(self) -> list[Incident]:
        return sorted(self._incidents.values(), key=lambda i: (i.severity.rank, i.id))

    def get_incident(self, iid: str) -> Incident:
        return self._incidents[iid]

    def update_incident(self, incident: Incident) -> None:
        self._incidents[incident.id] = incident
        self._save_incidents()

    # -- responses ----------------------------------------------------------

    def record_response(self, entry: dict) -> None:
        with self.responses_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
