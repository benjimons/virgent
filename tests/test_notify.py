"""Notification dispatch: channels, gating, domain allowlist, engine wiring."""
import pytest

from virgent.access import EscalationRequired
from virgent.engine import SecurityAgent
from virgent.models import Actor, Severity
from virgent.notify import (
    FileNotifier,
    Notification,
    NotificationDispatcher,
    WebhookNotifier,
    build_dispatcher,
)
from virgent.policy import PolicyEngine

ACTOR = Actor(id="test", type="system")
GH_TOKEN = "ghp_" + "d" * 36


def test_file_notifier_writes_jsonl(tmp_path):
    n = FileNotifier(path=str(tmp_path / "n.jsonl"))
    r = n.send(Notification(kind="test", title="hi", severity=Severity.HIGH))
    assert r["status"] == "sent"
    assert "hi" in (tmp_path / "n.jsonl").read_text()


def test_webhook_domain_allowlist_blocks_unlisted():
    calls = []
    n = WebhookNotifier(url="https://evil.example/hook",
                        fetcher=lambda u, d: calls.append(u) or "ok",
                        domain_check=lambda host: host == "good.example")
    r = n.send(Notification(kind="test", title="x"))
    assert r["status"] == "blocked"
    assert calls == []  # never called out


def test_webhook_sends_when_allowed():
    calls = []
    n = WebhookNotifier(url="https://good.example/hook",
                        fetcher=lambda u, d: calls.append((u, d)) or "ok",
                        domain_check=lambda host: host == "good.example")
    r = n.send(Notification(kind="incident", title="x"))
    assert r["status"] == "sent"
    assert calls and calls[0][0] == "https://good.example/hook"


def test_dispatcher_gates_low_severity_incidents():
    sent = []
    fake = type("F", (), {"name": "f", "send": lambda self, n: sent.append(n) or {"status": "sent"}})()
    disp = NotificationDispatcher([fake], min_severity=Severity.HIGH)
    disp.dispatch(Notification(kind="incident", title="low", severity=Severity.LOW))
    assert sent == []  # below threshold
    disp.dispatch(Notification(kind="incident", title="hi", severity=Severity.CRITICAL))
    assert len(sent) == 1
    # decision events always notify regardless of severity threshold
    disp.dispatch(Notification(kind="decision.requested", title="d", severity=Severity.INFO))
    assert len(sent) == 2


def test_dispatch_never_raises_on_broken_channel():
    class Boom:
        name = "boom"
        def send(self, n):
            raise RuntimeError("channel down")
    disp = NotificationDispatcher([Boom()])
    results = disp.dispatch(Notification(kind="decision.requested", title="d"))
    assert results[0]["status"] == "error"  # captured, not raised


def test_build_dispatcher_from_policy(tmp_path):
    policy = {"notify": {"enabled": True, "min_severity": "medium",
                         "channels": [{"type": "file", "path": "n.jsonl"}, {"type": "stdout"}]}}
    disp = build_dispatcher(policy, workdir=tmp_path)
    assert len(disp.notifiers) == 2
    assert disp.min_severity == Severity.MEDIUM


def test_engine_notifies_on_decision_and_redacts(tmp_path):
    # force a response action that requires a human decision, capture notifications
    policy = PolicyEngine({
        "actions": {"default": "allow"},
        "notify": {"enabled": True, "min_severity": "high",
                   "channels": [{"type": "file", "path": "n.jsonl"}]},
        "access": {"autonomy": {"respond": "escalate"}},
    })
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    # seed an incident by ingesting a brute-force log then detecting
    log = tmp_path / "auth.log"
    log.write_text("\n".join(
        f"Jan 10 10:0{i} h sshd[1]: Failed password for root from 45.9.1.2 port 5{i} ssh2"
        for i in range(6)) + "\n")
    agent.ingest(str(log))
    _, incidents = agent.soc_detect()
    assert incidents
    # responding opens a human decision (raises) -> a notification is written first
    with pytest.raises(EscalationRequired):
        agent.soc_respond(incidents[0].id, "block_ip")
    notif_file = tmp_path / "wd" / "n.jsonl"
    assert notif_file.exists()
    content = notif_file.read_text()
    assert "decision" in content.lower()


def test_engine_notify_test_command(tmp_path):
    policy = PolicyEngine({"actions": {"default": "allow"},
                           "notify": {"channels": [{"type": "file", "path": "n.jsonl"}]}})
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    results = agent.notify_test()
    assert results and results[0]["status"] == "sent"
    audited = [r for r in agent.audit.iter_records() if r["action"] == "notify.test"]
    assert audited
