"""Alert correlation into incidents.

Alerts that share an entity (an IP, a user, or a host) are grouped into a
single incident via union-find over entity values. Incident IDs are derived
from the entity set, so the same campaign maps to the same incident across
re-runs — letting human triage state persist.
"""
from __future__ import annotations

from .models import Alert, Incident, PRIORITY_BY_SEVERITY, incident_id
from ..models import Severity


class _UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _entity_nodes(entities: dict) -> list[str]:
    nodes = []
    for k, v in entities.items():
        values = v if isinstance(v, (list, tuple, set)) else [v]
        for item in values:
            nodes.append(f"{k}={item}")
    return nodes


def correlate(alerts: list[Alert]) -> list[Incident]:
    uf = _UnionFind()
    # link all entity-nodes within each alert; also link the alert to its nodes
    for alert in alerts:
        nodes = _entity_nodes(alert.entities) or [f"alert={alert.id}"]
        first = nodes[0]
        for n in nodes[1:]:
            uf.union(first, n)
        uf.union(f"alert:{alert.id}", first)

    groups: dict[str, list[Alert]] = {}
    for alert in alerts:
        root = uf.find(f"alert:{alert.id}")
        groups.setdefault(root, []).append(alert)

    incidents: list[Incident] = []
    for group in groups.values():
        entities: dict[str, set] = {}
        for alert in group:
            for k, v in alert.entities.items():
                values = v if isinstance(v, (list, tuple, set)) else [v]
                entities.setdefault(k, set()).update(values)
        entities_out = {k: sorted(v) for k, v in entities.items()}
        top = min(group, key=lambda a: a.severity.rank)
        severity = top.severity
        iid = incident_id(entities_out)
        incidents.append(Incident(
            id=iid,
            title=f"Incident: {top.title}",
            severity=severity,
            entities=entities_out,
            alert_ids=sorted(a.id for a in group),
            rules=sorted({a.rule for a in group}),
            priority=PRIORITY_BY_SEVERITY[severity],
        ))
    incidents.sort(key=lambda i: i.severity.rank)
    return incidents
