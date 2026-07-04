"""Real response executors: validation, command/webhook, gating, factory."""
from virgent.engine import SecurityAgent
from virgent.models import Actor
from virgent.policy import PolicyEngine
from virgent.soc.executors import CommandExecutor, WebhookExecutor, build_executor

ACTOR = Actor(id="test", type="system")


def test_command_executor_runs_template_with_validated_ip():
    calls = []
    ex = CommandExecutor(
        templates={"block_ip": ["blocker", "--add", "{ip}"]},
        runner=lambda argv: calls.append(argv) or (0, "blocked"))
    r = ex.execute("block_ip", {"ip": "45.9.1.2"})
    assert r["status"] == "executed"
    assert calls == [["blocker", "--add", "45.9.1.2"]]


def test_command_executor_rejects_bad_ip_without_running():
    calls = []
    ex = CommandExecutor(
        templates={"block_ip": ["blocker", "{ip}"]},
        runner=lambda argv: calls.append(argv) or (0, ""))
    r = ex.execute("block_ip", {"ip": "1.2.3.4; rm -rf /"})
    assert r["status"] == "rejected"
    assert calls == []  # never executed a command with an injected param


def test_command_executor_rejects_bad_username():
    ex = CommandExecutor(templates={"disable_user": ["disable", "{user}"]},
                         runner=lambda argv: (0, ""))
    assert ex.execute("disable_user", {"user": "alice; drop"})["status"] == "rejected"
    assert ex.execute("disable_user", {"user": "alice"})["status"] == "executed"


def test_command_executor_falls_back_to_dryrun_for_unmapped_action():
    ex = CommandExecutor(templates={"block_ip": ["x", "{ip}"]}, runner=lambda a: (0, ""))
    r = ex.execute("isolate_host", {"host": "h1"})
    assert r["status"] == "dry-run"


def test_command_failure_reported():
    ex = CommandExecutor(templates={"block_ip": ["x", "{ip}"]},
                         runner=lambda argv: (2, "boom"))
    r = ex.execute("block_ip", {"ip": "10.0.0.1"})
    assert r["status"] == "failed" and r["return_code"] == 2


def test_webhook_executor_domain_gated():
    calls = []
    ex = WebhookExecutor(url="https://soar.example/execute",
                         fetcher=lambda u, d: calls.append(u) or "ok",
                         domain_check=lambda host: host == "soar.example")
    assert ex.execute("block_ip", {"ip": "8.8.8.8"})["status"] == "executed"
    ex2 = WebhookExecutor(url="https://bad.example/execute",
                          fetcher=lambda u, d: calls.append(u) or "ok",
                          domain_check=lambda host: host == "soar.example")
    assert ex2.execute("block_ip", {"ip": "8.8.8.8"})["status"] == "blocked"


def test_build_executor_from_policy():
    assert build_executor({}) is None                       # default -> dry-run
    assert build_executor({"response": {"executor": {"type": "dryrun"}}}) is None
    cmd = build_executor({"response": {"executor": {
        "type": "command", "templates": {"block_ip": ["x", "{ip}"]}}}})
    assert isinstance(cmd, CommandExecutor)
    wh = build_executor({"response": {"executor": {
        "type": "webhook", "url": "https://soar.example/x"}}})
    assert isinstance(wh, WebhookExecutor)


def test_engine_uses_configured_executor_only_after_gate(tmp_path):
    # auto autonomy for 'respond' + a command executor: the action actually runs
    ran = []
    policy = PolicyEngine({
        "actions": {"default": "allow"},
        "access": {"autonomy": {"respond": "auto", "destructive": "auto"}},
        "response": {"executor": {"type": "command",
                                  "templates": {"block_ip": ["blocker", "{ip}"]}}},
    })
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    # inject the runner so nothing real happens
    agent.response_executor.runner = lambda argv: ran.append(argv) or (0, "ok")
    log = tmp_path / "auth.log"
    log.write_text("\n".join(
        f"Jan 10 10:0{i} h sshd[1]: Failed password for root from 45.9.1.2 port 5{i} ssh2"
        for i in range(6)) + "\n")
    agent.ingest(str(log))
    _, incidents = agent.soc_detect()
    result = agent.soc_respond(incidents[0].id, "block_ip")
    assert result["result"]["status"] == "executed"
    assert ran == [["blocker", "45.9.1.2"]]
