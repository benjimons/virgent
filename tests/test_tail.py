"""Offset-tracked log tailing."""
from virgent.engine import SecurityAgent
from virgent.ingest.tail import TailIngestor
from virgent.models import Actor

ACTOR = Actor(id="test", type="system")


def test_tail_reads_only_new_bytes(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("line1\nline2\n")
    tail = TailIngestor(tmp_path / "state.json")

    first = list(tail.collect(str(log)))
    assert len(first) == 1
    assert "line1" in first[0].content and "line2" in first[0].content

    # nothing new -> no items
    assert list(tail.collect(str(log))) == []

    # append -> only the new line comes back
    with log.open("a") as f:
        f.write("line3\n")
    second = list(tail.collect(str(log)))
    assert len(second) == 1
    assert second[0].content.strip() == "line3"
    assert "line1" not in second[0].content


def test_tail_persists_offset_across_instances(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("a\nb\n")
    TailIngestor(tmp_path / "state.json").collect(str(log))
    list(TailIngestor(tmp_path / "state.json").collect(str(log)))  # consume
    # a fresh instance re-reads state and sees nothing new
    fresh = list(TailIngestor(tmp_path / "state.json").collect(str(log)))
    assert fresh == []


def test_tail_handles_truncation(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("old-and-long-content\n")
    tail = TailIngestor(tmp_path / "state.json")
    list(tail.collect(str(log)))
    # truncate + write fresh (shorter) content -> restart from 0
    log.write_text("new\n")
    out = list(tail.collect(str(log)))
    assert len(out) == 1
    assert out[0].content.strip() == "new"


def test_tail_missing_file_is_safe(tmp_path):
    tail = TailIngestor(tmp_path / "state.json")
    assert list(tail.collect(str(tmp_path / "nope.log"))) == []


def test_engine_monitor_cycle_tails_incrementally(tmp_path):
    agent = SecurityAgent(workdir=tmp_path / "wd", actor=ACTOR)
    log = tmp_path / "auth.log"
    log.write_text("\n".join(
        f"Jan 10 10:0{i} h sshd[1]: Failed password for root from 10.0.0.9 port 5{i} ssh2"
        for i in range(6)) + "\n")

    # use a capability that ingests nothing, so only log tailing adds evidence
    agent.monitor_cycle(capabilities=["secrets"], log_sources=[str(log)])
    ev_after_first = len(agent.provenance.all_ids())
    assert ev_after_first >= 1

    # second cycle with no new log lines adds no new evidence (offset-tracked)
    agent.monitor_cycle(capabilities=["secrets"], log_sources=[str(log)])
    assert len(agent.provenance.all_ids()) == ev_after_first
    assert agent.verify_audit().ok
