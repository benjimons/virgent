import pytest

from virgent.models import Actor
from virgent.provenance import ProvenanceStore

ACTOR = Actor(id="test", type="system")


@pytest.fixture
def store(tmp_path):
    return ProvenanceStore(tmp_path / "prov.jsonl")


def test_register_and_verify(store):
    ev = store.register(source="a.py", method="ingest.file", kind="code",
                        content="print('hi')", collector=ACTOR)
    assert ev.id.startswith("ev-")
    assert store.verify_content(ev.id)
    rec = store.get(ev.id)
    assert rec.source == "a.py"
    assert rec.sha256 == ev.sha256


def test_lineage_chain(store):
    root = store.register(source="raw.log", method="ingest.file", kind="log",
                          content="raw", collector=ACTOR)
    mid = store.register(source="derived:summary", method="derive.llm", kind="text",
                         content="summary", collector=ACTOR, derived_from=[root.id])
    leaf = store.register(source="derived:finding", method="derive.llm", kind="text",
                          content="finding", collector=ACTOR, derived_from=[mid.id])
    ancestry = [r.evidence_id for r in store.lineage(leaf.id)]
    assert ancestry == [mid.id, root.id]


def test_unknown_parent_rejected(store):
    with pytest.raises(KeyError):
        store.register(source="x", method="derive", kind="text",
                       content="x", collector=ACTOR, derived_from=["ev-does-not-exist"])


def test_persistence_across_instances(tmp_path):
    store1 = ProvenanceStore(tmp_path / "prov.jsonl")
    ev = store1.register(source="a", method="ingest.file", kind="text",
                         content="hello", collector=ACTOR)
    store2 = ProvenanceStore(tmp_path / "prov.jsonl")
    loaded = store2.load_evidence(ev.id)
    assert loaded.content == "hello"
    assert loaded.sha256 == ev.sha256
    assert store2.verify_content(ev.id)


def test_tampered_content_detected(tmp_path):
    store = ProvenanceStore(tmp_path / "prov.jsonl")
    ev = store.register(source="a", method="ingest.file", kind="text",
                        content="original", collector=ACTOR)
    (store.content_dir / ev.id).write_text("tampered", encoding="utf-8")
    assert not store.verify_content(ev.id)
