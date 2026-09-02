"""Durable nonce / proposal-ID replay protection.

Covers: survival across a governor restart, atomicity across concurrent
governor instances sharing one store, that an unauthenticated proposal can
never poison an identifier, fail-closed behaviour on a persistence error,
schema migration of a pre-existing (and pre-hardening) database, that
in-memory cache eviction never weakens the durable guarantee, unconditional
consumption regardless of the final decision, and the documented scope
(per-agent nonces, fleet-wide proposal IDs, both independent of the envelope
fingerprint and of key_id -- so a claim survives a key rotation AND a
policy/envelope change; only the (namespace, agent_id, nonce) /
(namespace, proposal_id) columns are the uniqueness boundary).
"""

import sqlite3
import threading

import pytest

from chainmail import (
    ALGO_HMAC, AuditSink, ChainmailGovernor, CompositeVerifier, Decision, GovernorConfig,
    KeyRegistry, Proposal, RiskSignal, SQLiteStore, build_demo_envelope, make_permission,
    sign_proposal,
)

from conftest import JaccardEmbeddingEngine

OBJ = "Build a secure multi-agent governance prototype"


def _prop(pid, agent="agent_research", action="gather", nonce=None, confidence=0.85, **kw):
    return Proposal(pid, agent, action, make_permission("research"), OBJ, confidence,
                    nonce=nonce, **kw)


def _gov(sqlite_store, **kwargs):
    return ChainmailGovernor(
        build_demo_envelope(),
        config=kwargs.pop("config", GovernorConfig()),
        embedding=JaccardEmbeddingEngine(),
        auto_embedding=False,
        audit=AuditSink(sqlite_store=sqlite_store),
        **kwargs,
    )


# -- durability across restart ------------------------------------------

def test_nonce_rejected_after_restart(tmp_path):
    db = str(tmp_path / "chainmail.db")

    store_a = SQLiteStore(db)
    g_a = _gov(store_a)
    r1 = g_a.evaluate(_prop("p1", nonce="reused-nonce"))
    assert r1.decision == Decision.CONTINUE
    store_a.close()

    # simulate a process restart: a fresh store + fresh governor over the same file
    store_b = SQLiteStore(db)
    g_b = _gov(store_b)
    r2 = g_b.evaluate(_prop("p2", nonce="reused-nonce"))
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.REPLAY_DETECTED in r2.signals


def test_proposal_id_rejected_after_restart(tmp_path):
    db = str(tmp_path / "chainmail.db")

    store_a = SQLiteStore(db)
    g_a = _gov(store_a)
    r1 = g_a.evaluate(_prop("dup-id"))
    assert r1.decision == Decision.CONTINUE
    store_a.close()

    store_b = SQLiteStore(db)
    g_b = _gov(store_b)
    r2 = g_b.evaluate(_prop("dup-id"))
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.PROPOSAL_DUPLICATE in r2.signals


# -- atomicity across concurrent governors -------------------------------

def test_concurrent_governors_race_on_nonce(tmp_path):
    """Two governor instances sharing one durable store both attempt to claim
    the same nonce concurrently. Exactly one must win -- the UNIQUE
    constraint, not a Python-level lock, is what makes this safe, since the
    two governors are separate objects with separate locks."""
    db = str(tmp_path / "chainmail.db")
    store_a = SQLiteStore(db)
    store_b = SQLiteStore(db)
    g_a = _gov(store_a)
    g_b = _gov(store_b)

    results = []
    barrier = threading.Barrier(2)

    def run(gov, pid):
        barrier.wait()
        results.append(gov.evaluate(_prop(pid, nonce="race-nonce")).decision)

    t1 = threading.Thread(target=run, args=(g_a, "race-1"))
    t2 = threading.Thread(target=run, args=(g_b, "race-2"))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert sorted(results) == [Decision.CONTINUE, Decision.HUMAN]


# -- authenticate before claiming -----------------------------------------

def test_invalid_signature_cannot_poison_nonce(tmp_path):
    """An attacker who submits a forged signature must not be able to burn a
    nonce a legitimate, correctly-signed proposal will need."""
    db = str(tmp_path / "chainmail.db")
    reg = KeyRegistry()
    secret = b"shared-secret-value"
    reg.add_key("k-hmac", "agent_research", ALGO_HMAC, secret)
    store = SQLiteStore(db)
    g = _gov(store, config=GovernorConfig(require_signature=True),
            verifier=CompositeVerifier(reg))

    forged = _prop("forged", nonce="contested-nonce", signature="k-hmac:not-a-real-signature")
    r1 = g.evaluate(forged)
    assert r1.decision == Decision.HUMAN
    assert RiskSignal.SIGNATURE_INVALID in r1.signals

    legit = sign_proposal(_prop("legit", nonce="contested-nonce"), "k-hmac",
                          algorithm=ALGO_HMAC, hmac_secret=secret, nonce="contested-nonce")
    r2 = g.evaluate(legit)
    assert r2.decision == Decision.CONTINUE


# -- fail closed on persistence errors ------------------------------------

def test_failed_nonce_commit_cannot_continue(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    def _boom(**kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    store.claim_nonce = _boom
    r = g.evaluate(_prop("p1", nonce="n1"))
    assert r.decision == Decision.HUMAN
    assert RiskSignal.REPLAY_STORE_UNAVAILABLE in r.signals


def test_failed_proposal_id_commit_cannot_continue(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    def _boom(**kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    store.claim_proposal_id = _boom
    r = g.evaluate(_prop("p1"))
    assert r.decision == Decision.HUMAN
    assert RiskSignal.REPLAY_STORE_UNAVAILABLE in r.signals


# -- schema migration ------------------------------------------------------

def test_existing_v1_database_migrates_safely(tmp_path):
    db = str(tmp_path / "old.db")
    # Hand-build a v1-shaped database: schema_version=1, only the original
    # two tables, no replay tables.
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO schema_version (version) VALUES (1)")
    conn.execute("""
        CREATE TABLE proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT, record_version INTEGER NOT NULL,
            proposal_id TEXT NOT NULL, agent_id TEXT NOT NULL, action TEXT NOT NULL,
            decision TEXT NOT NULL, signals TEXT, overlap REAL, drift REAL,
            timestamp REAL NOT NULL, execution_id TEXT, phase TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE delegations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, record_version INTEGER NOT NULL,
            from_agent TEXT NOT NULL, to_agent TEXT NOT NULL, reason TEXT,
            authority TEXT, timestamp REAL NOT NULL
        )
    """)
    conn.execute("INSERT INTO proposals (record_version, proposal_id, agent_id, action, "
                 "decision, signals, overlap, drift, timestamp, execution_id, phase) "
                 "VALUES (1, 'old-1', 'agent_research', 'gather', 'CONTINUE', '[]', "
                 "0.9, 0.1, 1000.0, NULL, 'completed')")
    conn.commit()
    conn.close()

    store = SQLiteStore(db)  # opens the existing v1 file
    version = store._conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert version == SQLiteStore.SCHEMA_VERSION
    # pre-existing data survived the migration
    assert store.get_proposal_history() and store.get_proposal_history()[0]["proposal_id"] == "old-1"
    # new tables exist and are usable
    assert store.claim_nonce(namespace="default", envelope_fingerprint="fp", agent_id="a",
                             nonce="n1") is True
    assert store.claim_nonce(namespace="default", envelope_fingerprint="fp", agent_id="a",
                             nonce="n1") is False


def test_existing_v2_scope_based_database_migrates_safely(tmp_path):
    """A database built by the first (v2, ``scope``-column) shape of the
    replay tables must open cleanly and end up with the v3 (explicit-column)
    shape -- and every existing claim must survive the migration. A nonce
    consumed under the old schema must still read as consumed afterward:
    silently losing claim history across a migration would let a
    previously-used signed proposal or nonce become replayable again."""
    db = str(tmp_path / "v2.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO schema_version (version) VALUES (2)")
    conn.execute("""
        CREATE TABLE proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT, record_version INTEGER NOT NULL,
            proposal_id TEXT NOT NULL, agent_id TEXT NOT NULL, action TEXT NOT NULL,
            decision TEXT NOT NULL, signals TEXT, overlap REAL, drift REAL,
            timestamp REAL NOT NULL, execution_id TEXT, phase TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE delegations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, record_version INTEGER NOT NULL,
            from_agent TEXT NOT NULL, to_agent TEXT NOT NULL, reason TEXT,
            authority TEXT, timestamp REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE replay_nonces (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, nonce TEXT NOT NULL,
            agent_id TEXT NOT NULL, key_id TEXT, envelope_fingerprint TEXT NOT NULL,
            claimed_at REAL NOT NULL, UNIQUE (scope, nonce)
        )
    """)
    conn.execute("""
        CREATE TABLE replay_proposal_ids (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, proposal_id TEXT NOT NULL,
            agent_id TEXT NOT NULL, envelope_fingerprint TEXT NOT NULL,
            claimed_at REAL NOT NULL, UNIQUE (scope, proposal_id)
        )
    """)
    conn.execute("INSERT INTO replay_nonces (scope, nonce, agent_id, key_id, "
                 "envelope_fingerprint, claimed_at) VALUES ('default:fp:a', 'old-scoped-nonce', "
                 "'a', NULL, 'fp', 1000.0)")
    conn.commit()
    conn.close()

    store = SQLiteStore(db)  # opens the existing v2 (scope-column) file
    version = store._conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert version == SQLiteStore.SCHEMA_VERSION
    cols = {row[1] for row in store._conn.execute("PRAGMA table_info(replay_nonces)").fetchall()}
    assert "scope" not in cols
    assert {"deployment_namespace", "agent_id", "nonce"} <= cols
    # the old claim survived the migration -- re-attempting it must still
    # read as a replay, not a fresh nonce.
    assert store.claim_nonce(namespace="default", agent_id="a", nonce="old-scoped-nonce") is False
    # the new-shaped table is otherwise perfectly usable for new claims
    assert store.claim_nonce(namespace="default", agent_id="a", nonce="new-shape-nonce") is True
    assert store.claim_nonce(namespace="default", agent_id="a", nonce="new-shape-nonce") is False
    # the pre-v3 staging table left no trace
    assert not store._table_exists(store._conn, "replay_nonces_pre_v3")


def test_v2_rows_collapsing_under_v3_scope_do_not_crash_migration(tmp_path):
    """v3 narrowed nonce uniqueness to (namespace, agent_id, nonce), dropping
    envelope_fingerprint. Two v2 rows for the same nonce/agent claimed under
    different envelope fingerprints therefore collapse onto one v3 row;
    migration must tolerate that (INSERT OR IGNORE) rather than crash on the
    resulting UNIQUE conflict, and the nonce must still read as consumed
    afterward."""
    db = str(tmp_path / "collapse.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO schema_version (version) VALUES (2)")
    conn.execute("""
        CREATE TABLE replay_nonces (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, nonce TEXT NOT NULL,
            agent_id TEXT NOT NULL, key_id TEXT, envelope_fingerprint TEXT NOT NULL,
            claimed_at REAL NOT NULL, UNIQUE (scope, nonce)
        )
    """)
    # same (namespace, agent, nonce), two different envelope fingerprints --
    # legitimately distinct v2 rows, since fingerprint was part of scope
    conn.execute("INSERT INTO replay_nonces (scope, nonce, agent_id, key_id, "
                 "envelope_fingerprint, claimed_at) VALUES ('default:fp-one:a', "
                 "'shared-nonce', 'a', NULL, 'fp-one', 1000.0)")
    conn.execute("INSERT INTO replay_nonces (scope, nonce, agent_id, key_id, "
                 "envelope_fingerprint, claimed_at) VALUES ('default:fp-two:a', "
                 "'shared-nonce', 'a', NULL, 'fp-two', 2000.0)")
    conn.commit()
    conn.close()

    store = SQLiteStore(db)  # must not raise despite the now-colliding rows
    assert store.claim_nonce(namespace="default", agent_id="a", nonce="shared-nonce") is False
    rows = store._conn.execute(
        "SELECT COUNT(*) FROM replay_nonces WHERE deployment_namespace='default' "
        "AND agent_id='a' AND nonce='shared-nonce'"
    ).fetchone()
    assert rows[0] == 1


# -- cache eviction never weakens the durable guarantee --------------------

def test_cache_eviction_does_not_remove_durable_protection(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store, config=GovernorConfig(max_seen_nonces=1))

    r1 = g.evaluate(_prop("p1", nonce="first-nonce"))
    assert r1.decision == Decision.CONTINUE
    # this claim evicts "first-nonce" from the tiny in-memory cache
    r2 = g.evaluate(_prop("p2", nonce="second-nonce"))
    assert r2.decision == Decision.CONTINUE
    assert g._nonce_cache_key("agent_research", "first-nonce") not in g._seen_nonces

    # resubmitting the evicted nonce must still be caught -- by SQLite, not the cache
    r3 = g.evaluate(_prop("p3", nonce="first-nonce"))
    assert r3.decision == Decision.HUMAN
    assert RiskSignal.REPLAY_DETECTED in r3.signals


# -- documented scope -------------------------------------------------------

def test_nonce_scope_is_per_agent_not_global(tmp_path):
    """Nonce uniqueness is scoped per agent (see SQLiteStore.claim_nonce
    docstring): two different agents may legitimately reuse the same nonce
    string without it being treated as a replay of each other's request."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    r1 = g.evaluate(_prop("p1", agent="agent_research", nonce="shared-nonce"))
    assert r1.decision == Decision.CONTINUE
    r2 = g.evaluate(_prop("p2", agent="agent_deploy", action="deploy", nonce="shared-nonce"))
    assert RiskSignal.REPLAY_DETECTED not in r2.signals


def test_proposal_id_scope_is_fleet_wide(tmp_path):
    """Proposal-ID uniqueness is fleet-wide (see SQLiteStore.claim_proposal_id
    docstring): the same proposal_id from a *different* agent is still a
    duplicate, matching the pre-durability in-memory behaviour."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    r1 = g.evaluate(_prop("shared-id", agent="agent_research"))
    assert r1.decision == Decision.CONTINUE
    r2 = g.evaluate(_prop("shared-id", agent="agent_deploy", action="deploy"))
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.PROPOSAL_DUPLICATE in r2.signals


def test_nonce_stays_blocked_across_key_rotation(tmp_path):
    """Scope binds (namespace, agent_id, nonce) -- not key_id -- so a nonce
    claimed under one key for an agent is still blocked after that agent
    rotates to a new key. Nonces identify the request, not the signing key."""
    db = str(tmp_path / "chainmail.db")
    reg = KeyRegistry()
    secret1 = b"key-one-secret-value"
    reg.add_key("k1", "agent_research", ALGO_HMAC, secret1)
    store = SQLiteStore(db)
    g = _gov(store, config=GovernorConfig(require_signature=True),
            verifier=CompositeVerifier(reg))

    p1 = sign_proposal(_prop("p1", nonce="rotated-nonce"), "k1",
                       algorithm=ALGO_HMAC, hmac_secret=secret1, nonce="rotated-nonce")
    assert g.evaluate(p1).decision == Decision.CONTINUE

    secret2 = b"key-two-secret-value"
    reg.rotate("k1", "k2", secret2, algorithm=ALGO_HMAC)
    p2 = sign_proposal(_prop("p2", nonce="rotated-nonce"), "k2",
                       algorithm=ALGO_HMAC, hmac_secret=secret2, nonce="rotated-nonce")
    r2 = g.evaluate(p2)
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.REPLAY_DETECTED in r2.signals


def test_replay_detected_across_envelope_change(tmp_path):
    """The uniqueness boundary is independent of the envelope/policy
    fingerprint (see SQLiteStore module docs): replay protection identifies
    whether a *signed request* has already been submitted, and a policy
    update must not make an old signed proposal replayable again. An
    attacker holding an earlier signed proposal must not be able to retry it
    just by waiting for (or triggering) a policy change."""
    import dataclasses

    db = str(tmp_path / "chainmail.db")
    reg = KeyRegistry()
    secret = b"policy-change-secret-value"
    reg.add_key("k1", "agent_research", ALGO_HMAC, secret)
    store = SQLiteStore(db)

    env_a = build_demo_envelope()
    g_a = ChainmailGovernor(env_a, config=GovernorConfig(require_signature=True),
                            embedding=JaccardEmbeddingEngine(), auto_embedding=False,
                            audit=AuditSink(sqlite_store=store), verifier=CompositeVerifier(reg))
    original = sign_proposal(_prop("p1", nonce="pre-policy-change-nonce"), "k1",
                             algorithm=ALGO_HMAC, hmac_secret=secret,
                             nonce="pre-policy-change-nonce")
    assert g_a.evaluate(original).decision == Decision.CONTINUE

    # policy/envelope changes; a fresh governor is constructed over it
    env_b = dataclasses.replace(build_demo_envelope(), max_fleet_steps=999)
    assert env_b.fingerprint() != env_a.fingerprint()
    g_b = ChainmailGovernor(env_b, config=GovernorConfig(require_signature=True),
                            embedding=JaccardEmbeddingEngine(), auto_embedding=False,
                            audit=AuditSink(sqlite_store=store), verifier=CompositeVerifier(reg))

    # resubmitting the exact same signed proposal must still be a replay
    r = g_b.evaluate(original)
    assert r.decision == Decision.HUMAN
    assert RiskSignal.REPLAY_DETECTED in r.signals


# -- consumption semantics ---------------------------------------------------

def test_nonce_consumed_even_when_final_decision_is_not_continue(tmp_path):
    """An authenticated proposal consumes its nonce and proposal_id the
    moment they are claimed -- unconditionally, even if the contextual-risk
    checks further down evaluate() land on RESTRICT/RECHECK/HUMAN rather
    than CONTINUE. Retrying requires a new proposal with a new nonce."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    # confidence at/below low_confidence_max (default 0.35) -> LOW_CONFIDENCE -> RESTRICT
    risky = _prop("risky", nonce="consumed-even-on-restrict", confidence=0.1)
    r1 = g.evaluate(risky)
    assert r1.decision == Decision.RESTRICT
    assert RiskSignal.LOW_CONFIDENCE in r1.signals

    # the nonce was consumed regardless -- a retry with the same nonce is a replay
    retry = _prop("retry", nonce="consumed-even-on-restrict")
    r2 = g.evaluate(retry)
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.REPLAY_DETECTED in r2.signals
