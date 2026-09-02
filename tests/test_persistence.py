"""Hash-chain log, SQLite store, and the composed audit sink."""

import json

import pytest

from chainmail import (
    AuditSink, Decision, HashChainLog, Proposal, ReceiptIntegrityError, RiskSignal,
    SQLiteStore, make_permission,
)
from chainmail.persistence import sanitize

OBJ = "Build a secure multi-agent governance prototype"


def _prop(pid):
    return Proposal(pid, "agent_research", "gather", make_permission("research"), OBJ, 0.85)


# -- hash chain ----------------------------------------------------

def test_verify_is_non_destructive():
    log = HashChainLog()
    log.append("t", {"msg": "first"})
    log.append("t", {"msg": "second"})
    assert log.verify().valid
    assert log.verify().valid          # a second call must not corrupt anything
    assert log.verify().valid
    assert log.verify().failed_record is None


def test_tamper_detected_with_zero_based_index():
    log = HashChainLog()
    log.append("t", {"msg": "first"})
    log.append("t", {"msg": "second"})
    log.entries[1]["data"]["msg"] = "tampered"
    result = log.verify()
    assert not result.valid
    assert result.failed_record == 1


def test_append_refuses_corrupt_chain():
    log = HashChainLog()
    log.entries.append({"not_a_record": True, "hash": "x", "prev_hash": "0" * 64})
    with pytest.raises(ReceiptIntegrityError):
        log.append("t", {"msg": "x"})


def test_chain_reload_and_verify(tmp_path):
    path = str(tmp_path / "chain.jsonl")
    log = HashChainLog(path)
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    reopened = HashChainLog(path)          # loads + verifies on construction
    assert len(reopened.entries) == 2
    assert reopened.verify().valid
    reopened.append("t", {"n": 3})         # chain continues, no second genesis
    assert HashChainLog(path).verify().valid


def test_two_independent_instances_sharing_a_file_produce_a_valid_chain(tmp_path):
    # Simulates two separate processes (each with its own HashChainLog
    # instance and in-memory state, unaware of the other's appends) sharing
    # one hash-chain file -- e.g. two governor processes pointed at the same
    # --hash-chain path. Each append must chain onto whatever the *file's*
    # last entry actually is, not this instance's possibly-stale in-memory
    # view, or the interleaved file fails verification once reloaded.
    path = str(tmp_path / "chain.jsonl")
    proc_a = HashChainLog(path)
    proc_b = HashChainLog(path)

    proc_a.append("t", {"who": "a", "n": 1})
    proc_b.append("t", {"who": "b", "n": 1})   # proc_b doesn't know about a's append
    proc_a.append("t", {"who": "a", "n": 2})
    proc_b.append("t", {"who": "b", "n": 2})

    reopened = HashChainLog(path)              # a fresh reader sees the whole file
    assert len(reopened.entries) == 4
    result = reopened.verify()
    assert result.valid, result.reason
    assert [e["data"]["who"] for e in reopened.entries] == ["a", "b", "a", "b"]


def test_chain_reload_detects_file_tamper(tmp_path):
    path = tmp_path / "chain.jsonl"
    log = HashChainLog(str(path))
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0]); rec["data"]["n"] = 999
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ReceiptIntegrityError):
        HashChainLog(str(path))


# -- sqlite -----------------------------------------------------

def test_sqlite_staged_rows(governor_with_sqlite):
    g, store = governor_with_sqlite
    g.evaluate(_prop("sq1"))
    history = store.get_proposal_history()
    assert [h["phase"] for h in history] == ["started", "completed"]
    assert history[0]["record_version"] == 1


def test_sqlite_prune(governor_with_sqlite):
    g, store = governor_with_sqlite
    for i in range(6):
        g.evaluate(_prop(f"p{i}"))
    removed = store.prune(keep_last=4)
    assert removed > 0
    assert len(store.get_proposal_history()) == 4


def test_suggest_envelope(governor_with_sqlite):
    g, _ = governor_with_sqlite
    for i in range(10):
        g.evaluate(_prop(f"h{i}"))
    s = g.suggest_envelope()
    assert "most_common_actions" in s and "decision_distribution" in s


# -- audit sink fail-closed ----------------------------------------

def test_audit_failure_is_fail_closed(make_governor):
    class BoomChain(HashChainLog):
        def append(self, *a, **k):
            raise RuntimeError("disk full")
    g = make_governor(audit=AuditSink(hash_chain=BoomChain()))
    r = g.evaluate(_prop("boom-1"))
    assert r.decision == Decision.HUMAN and RiskSignal.SANITIZATION_FAILURE in r.signals


# -- sanitize -----------------------------------------------------

def test_sanitize_bounds():
    assert len(sanitize("x" * 10000)) == 4096
    deep = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": 1}}}}}}}}}
    assert "<max-depth>" in str(sanitize(deep))
    cyc = []
    cyc.append(cyc)
    assert sanitize(cyc) == ["<cycle>"]
    assert len(sanitize(list(range(200)))) == 100


@pytest.fixture
def governor_with_sqlite(make_governor):
    store = SQLiteStore(":memory:")
    g = make_governor(audit=AuditSink(sqlite_store=store))
    return g, store
