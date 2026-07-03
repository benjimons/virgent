import json

import pytest

from virgent.capabilities.llm_review import LLMReviewCapability, _extract_json_array
from virgent.engine import SecurityAgent
from virgent.llm.provider import MockProvider
from virgent.models import Actor, Severity
from virgent.policy import PolicyEngine

ACTOR = Actor(id="test", type="system")
GH_TOKEN = "ghp_" + "b" * 36


def make_agent(tmp_path, responses=None, policy=None):
    provider = MockProvider(responses=responses or ["[]"])
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy,
                          actor=ACTOR, provider=provider)
    return agent, provider


def test_reason_redacts_prompt_before_provider(tmp_path):
    agent, provider = make_agent(tmp_path)
    agent.reason(prompt=f"analyze this token: {GH_TOKEN}", purpose="test")
    sent = provider.calls[0]["prompt"]
    assert GH_TOKEN not in sent
    assert "[REDACTED:github-token]" in sent


def test_reason_audits_hashes_not_content(tmp_path):
    agent, _ = make_agent(tmp_path)
    result = agent.reason(prompt="hello world", purpose="test")
    records = [r for r in agent.audit.iter_records() if r["action"] == "llm.complete"]
    assert len(records) == 1
    params = records[0]["params"]
    assert params["prompt_sha256"] == result.prompt_sha256
    assert params["response_sha256"] == result.response_sha256
    assert "hello world" not in json.dumps(records[0])


def test_reason_respects_llm_disabled_policy(tmp_path):
    policy = PolicyEngine({"actions": {"default": "allow"}, "llm": {"enabled": False}})
    agent, _ = make_agent(tmp_path, policy=policy)
    with pytest.raises(Exception):
        agent.reason(prompt="hi", purpose="test")


def test_reason_enforces_max_input_chars(tmp_path):
    policy = PolicyEngine({
        "actions": {"default": "allow"},
        "llm": {"enabled": True, "max_input_chars": 10},
    })
    agent, _ = make_agent(tmp_path, policy=policy)
    with pytest.raises(ValueError):
        agent.reason(prompt="x" * 100, purpose="test")


def test_extract_json_array_tolerates_fences_and_prose():
    assert _extract_json_array('```json\n[{"title": "x"}]\n```') == [{"title": "x"}]
    assert _extract_json_array('Here you go: [{"title": "y"}] hope that helps') == [{"title": "y"}]
    assert _extract_json_array("no array here") == []
    assert _extract_json_array("[not valid json") == []


def test_llm_review_capability_end_to_end(tmp_path):
    response = json.dumps([{
        "title": "SQL injection in query builder",
        "description": "User input concatenated into SQL.",
        "severity": "high",
        "line": 3,
        "remediation": "Use parameterized queries.",
    }])
    agent, provider = make_agent(tmp_path, responses=[response])
    (tmp_path / "app.py").write_text(
        'import sqlite3\n\ndef q(c, name): return c.execute("SELECT * FROM u WHERE n=" + name)\n')
    agent.ingest(str(tmp_path / "app.py"))
    findings = agent.scan(capabilities=["llm-review"])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.location.endswith("app.py:3")
    assert f.confidence == "medium"          # model output is untrusted
    assert f.metadata["prompt_sha256"]
    # evidence is fenced against prompt injection
    assert "BEGIN EVIDENCE" in provider.calls[0]["prompt"]


def test_llm_review_ignores_malformed_model_output(tmp_path):
    agent, _ = make_agent(tmp_path, responses=["I think everything looks fine!"])
    (tmp_path / "app.py").write_text("print('ok')\n")
    agent.ingest(str(tmp_path / "app.py"))
    assert agent.scan(capabilities=["llm-review"]) == []
