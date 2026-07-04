"""Detection evaluation harness.

Runs the detection engine over labeled log fixtures and computes precision,
recall, and F1 — per rule and overall — so detection quality is measurable and
regressions are caught. This is what lets you trust (and tune) autonomous
detection: a change to a rule can be scored against known-good/known-bad cases
before it ships.

A case is ``{"events": [raw log lines...], "expected": [rule names...]}``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .detection import DetectionEngine
from .events import parse_line


@dataclass
class EvalMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    per_rule: dict = field(default_factory=dict)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "per_rule": self.per_rule,
        }


def evaluate(cases: list[dict], engine: DetectionEngine | None = None) -> EvalMetrics:
    engine = engine or DetectionEngine()
    m = EvalMetrics()
    for case in cases:
        events = [e for e in (parse_line(ln) for ln in case.get("events", [])) if e]
        alerts = engine.run(events)
        produced = {a.rule for a in alerts}
        expected = set(case.get("expected", []))
        for rule in produced | expected:
            stats = m.per_rule.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0})
            if rule in produced and rule in expected:
                m.tp += 1; stats["tp"] += 1
            elif rule in produced and rule not in expected:
                m.fp += 1; stats["fp"] += 1
            elif rule not in produced and rule in expected:
                m.fn += 1; stats["fn"] += 1
    return m
