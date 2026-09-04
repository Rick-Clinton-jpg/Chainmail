"""Durable restriction state.

Covers: survival across a governor restart, survival across an envelope
change and a key rotation, a second governor observing a restriction imposed
by the first (no in-memory cache to go stale -- every evaluate() reads the
store fresh), a forced persistence failure never producing CONTINUE (or a
falsely-reported RESTRICT), explicit clearing (idempotent, bound to a
specific restriction_id so a stale release can't touch a newer restriction),
schema migration (v1/v2/v3 -> v4), development mode being unaffected, and
production mode requiring durable restriction storage. History (the
append-only restriction_events log) is checked to survive clearing.
"""

import sqlite3

import pytest

from chainmail import (
    ALGO_HMAC, AuditSink, ChainmailGovernor, CompositeVerifier, Decision, DenyAllExecutionBoundary,
    GovernorConfig, KeyRegistry, Proposal, RiskSignal, SQLiteStore, build_demo_envelope,
    make_permission, sign_proposal,
)

from conftest import JaccardEmbeddingEngine

OBJ = "Build a secure multi-agent governance prototype"


def _prop(pid, agent="agent_research", action="gather", confidence=0.85, nonce=None, **kw):
    return Proposal(pid, agent, action, make_permission("research"), OBJ, confidence,
                    nonce=nonce, **kw)


def _restrict_prop(pid, **kw):
    """confidence below GovernorConfig.low_confidence_max (default 0.35) ->
    LOW_CONFIDENCE -> RESTRICT, on the "research" permission for agent_research."""
    return _prop(pid, confidence=0.2, **kw)


def _gov(sqlite_store, **kwargs):
    return ChainmailGovernor(
        kwargs.pop("envelope", None) or build_demo_envelope(),
        config=kwargs.pop("config", GovernorConfig()),
        embedding=JaccardEmbeddingEngine(),
        auto_embedding=False,
        audit=AuditSink(sqlite_store=sqlite_store),
        **kwargs,
    )


def _is_restricted(governor, agent_id="agent_research", perm=None):
    perm = perm or make_permission("research")
    return perm in governor._active_restrictions(agent_id)


# -- durability across restart -------------------------------------------

def test_restriction_survives_restart(tmp_path):
    db = str(tmp_path / "chainmail.db")

    store_a = SQLiteStore(db)
    g_a = _gov(store_a)
    r1 = g_a.evaluate(_restrict_prop("p1"))
    assert r1.decision == Decision.RESTRICT
    assert r1.restricted_permissions == {make_permission("research")}
    store_a.close()

    store_b = SQLiteStore(db)
    g_b = _gov(store_b)
    assert _is_restricted(g_b)
    # the permission check itself also reflects it
    r2 = g_b.evaluate(_prop("p2"))
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.AUTHORITY_ABUSE in r2.signals


def test_restriction_survives_envelope_and_key_change(tmp_path):
    """Neither an envelope/policy change nor a signing-key rotation lifts a
    restriction -- it's a consequence of the agent's behaviour, not of the
    policy or key that happened to be active when it was imposed."""
    import dataclasses

    db = str(tmp_path / "chainmail.db")
    reg = KeyRegistry()
    secret1 = b"restriction-key-one-secret"
    reg.add_key("k1", "agent_research", ALGO_HMAC, secret1)
    store = SQLiteStore(db)

    env_a = build_demo_envelope()
    g_a = _gov(store, envelope=env_a, config=GovernorConfig(require_signature=True),
              verifier=CompositeVerifier(reg))
    imposing = sign_proposal(_restrict_prop("p1"), "k1", algorithm=ALGO_HMAC,
                             hmac_secret=secret1, nonce="restrict-nonce-1")
    r1 = g_a.evaluate(imposing)
    assert r1.decision == Decision.RESTRICT

    # policy/envelope changes AND the agent's key rotates
    env_b = dataclasses.replace(build_demo_envelope(), max_fleet_steps=999)
    assert env_b.fingerprint() != env_a.fingerprint()
    secret2 = b"restriction-key-two-secret"
    reg.rotate("k1", "k2", secret2, algorithm=ALGO_HMAC)
    g_b = _gov(store, envelope=env_b, config=GovernorConfig(require_signature=True),
              verifier=CompositeVerifier(reg))

    assert _is_restricted(g_b)
    later = sign_proposal(_prop("p2"), "k2", algorithm=ALGO_HMAC, hmac_secret=secret2,
                          nonce="restrict-nonce-2")
    r2 = g_b.evaluate(later)
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.AUTHORITY_ABUSE in r2.signals


# -- multi-process correctness --------------------------------------------

def test_second_governor_observes_restriction_from_first(tmp_path):
    """No __init__-time load and no in-memory cache: a restriction imposed by
    one governor is visible to a second, already-running governor sharing
    the same store on its very next evaluate() call -- not just after its
    own restart."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g1 = _gov(store)
    g2 = _gov(store)  # already constructed BEFORE g1 imposes anything

    assert not _is_restricted(g2)
    r1 = g1.evaluate(_restrict_prop("p1"))
    assert r1.decision == Decision.RESTRICT

    # g2 never reloaded anything -- it just asks the store fresh
    assert _is_restricted(g2)
    r2 = g2.evaluate(_prop("p2"))
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.AUTHORITY_ABUSE in r2.signals


# -- fail closed on persistence errors -------------------------------------

def test_failed_restriction_commit_cannot_continue_or_report_restrict(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    def _boom(**kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    store.impose_restriction = _boom
    r = g.evaluate(_restrict_prop("p1"))
    assert r.decision == Decision.HUMAN
    assert RiskSignal.RESTRICTION_STORE_UNAVAILABLE in r.signals
    assert r.restricted_permissions is None
    # and the failed attempt must not have been applied in memory either
    assert not _is_restricted(g)


def test_failed_restriction_read_fails_closed(tmp_path):
    """A read failure (not just a write failure) while checking restrictions
    must also fail closed -- an evaluate() call must never silently proceed
    as if there were no restrictions just because the store couldn't be
    read."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    def _boom(**kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    store.active_restrictions = _boom
    r = g.evaluate(_prop("p1"))
    assert r.decision == Decision.HUMAN
    assert RiskSignal.RESTRICTION_STORE_UNAVAILABLE in r.signals


# -- clearing ---------------------------------------------------------------

def test_clear_restriction_survives_restart(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store_a = SQLiteStore(db)
    g_a = _gov(store_a)
    r1 = g_a.evaluate(_restrict_prop("p1"))
    assert r1.decision == Decision.RESTRICT
    rid = store_a.active_restrictions(namespace="default", agent_id="agent_research")[0]["restriction_id"]

    result = g_a.clear_restriction("agent_research", rid, authorised_by="ops:alice",
                                   reason="reviewed, false positive")
    assert result == "cleared"
    assert not _is_restricted(g_a)
    store_a.close()

    store_b = SQLiteStore(db)
    g_b = _gov(store_b)
    assert not _is_restricted(g_b)
    r2 = g_b.evaluate(_prop("p2"))
    assert r2.decision == Decision.CONTINUE


def test_clear_restriction_is_idempotent(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)
    r1 = g.evaluate(_restrict_prop("p1"))
    rid = store.active_restrictions(namespace="default", agent_id="agent_research")[0]["restriction_id"]

    first = g.clear_restriction("agent_research", rid, authorised_by="ops:alice", reason="r1")
    second = g.clear_restriction("agent_research", rid, authorised_by="ops:bob", reason="r2")
    assert first == "cleared"
    assert second == "already_cleared"
    # only one CLEARED event was recorded, from the first (authoritative) call
    events = store.restriction_history(namespace="default", agent_id="agent_research",
                                       restriction_id=rid)
    cleared_events = [e for e in events if e["event_type"] == "CLEARED"]
    assert len(cleared_events) == 1
    assert cleared_events[0]["actor"] == "ops:alice"


def test_stale_release_cannot_clear_a_newer_restriction(tmp_path):
    """Each restriction gets its own restriction_id; releasing one can never
    touch another, even for the same agent and permission."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    r1 = g.evaluate(_restrict_prop("p1"))
    assert r1.decision == Decision.RESTRICT
    old_rid = store.active_restrictions(namespace="default", agent_id="agent_research")[0]["restriction_id"]

    stale_result = g.clear_restriction("agent_research", old_rid, authorised_by="ops:alice",
                                       reason="clearing the first one")
    assert stale_result == "cleared"
    assert not _is_restricted(g)

    # a second, independent restriction gets imposed later
    r2 = g.evaluate(_restrict_prop("p3"))
    assert r2.decision == Decision.RESTRICT
    new_rid = store.active_restrictions(namespace="default", agent_id="agent_research")[0]["restriction_id"]
    assert new_rid != old_rid

    # replaying the OLD release against the (already-cleared) old id is idempotent
    # and must not be interpreted as touching the new restriction
    replayed = g.clear_restriction("agent_research", old_rid, authorised_by="attacker",
                                   reason="replayed stale release")
    assert replayed == "already_cleared"
    assert _is_restricted(g)  # the new restriction is untouched


def test_clear_wrong_agent_is_rejected(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)
    r1 = g.evaluate(_restrict_prop("p1"))
    assert r1.decision == Decision.RESTRICT
    rid = store.active_restrictions(namespace="default", agent_id="agent_research")[0]["restriction_id"]

    result = g.clear_restriction("agent_deploy", rid, authorised_by="ops:alice", reason="wrong agent")
    assert result == "wrong_agent"
    assert _is_restricted(g)


def test_history_survives_clearing(tmp_path):
    """Clearing a restriction updates its current-state row in place -- it is
    never deleted -- and the append-only event log keeps both the IMPOSED
    and CLEARED events for investigation."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)
    r1 = g.evaluate(_restrict_prop("p1"))
    rid = store.active_restrictions(namespace="default", agent_id="agent_research")[0]["restriction_id"]

    g.clear_restriction("agent_research", rid, authorised_by="ops:alice", reason="done")

    row = store._conn.execute(
        "SELECT status, source_proposal_id, cleared_by, cleared_reason FROM restrictions "
        "WHERE restriction_id = ?", (rid,),
    ).fetchone()
    assert row is not None  # row still exists -- never deleted
    assert row[0] == "CLEARED"
    assert row[1] == "p1"
    assert row[2] == "ops:alice"
    assert row[3] == "done"

    events = store.restriction_history(namespace="default", agent_id="agent_research", restriction_id=rid)
    event_types = [e["event_type"] for e in events]
    assert event_types == ["IMPOSED", "CLEARED"]


# -- schema migration --------------------------------------------------------

def test_existing_v3_database_migrates_to_v4(tmp_path):
    db = str(tmp_path / "v3.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO schema_version (version) VALUES (3)")
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
            id INTEGER PRIMARY KEY AUTOINCREMENT, deployment_namespace TEXT NOT NULL,
            agent_id TEXT NOT NULL, nonce TEXT NOT NULL, key_id TEXT,
            envelope_fingerprint TEXT, claimed_at REAL NOT NULL,
            UNIQUE (deployment_namespace, agent_id, nonce)
        )
    """)
    conn.execute("""
        CREATE TABLE replay_proposal_ids (
            id INTEGER PRIMARY KEY AUTOINCREMENT, deployment_namespace TEXT NOT NULL,
            proposal_id TEXT NOT NULL, agent_id TEXT NOT NULL, envelope_fingerprint TEXT,
            claimed_at REAL NOT NULL, UNIQUE (deployment_namespace, proposal_id)
        )
    """)
    conn.execute("INSERT INTO replay_nonces (deployment_namespace, agent_id, nonce, "
                 "claimed_at) VALUES ('default', 'a', 'existing-nonce', 1000.0)")
    conn.commit()
    conn.close()

    store = SQLiteStore(db)
    version = store._conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert version == SQLiteStore.SCHEMA_VERSION

    # pre-existing v3 data is untouched
    assert store.claim_nonce(namespace="default", agent_id="a", nonce="existing-nonce") is False
    assert store.claim_nonce(namespace="default", agent_id="a", nonce="fresh-nonce") is True

    # new v4 restriction tables exist and are usable
    rid = store.impose_restriction(
        namespace="default", agent_id="agent_research", permission_name="research",
        permission_scope="*", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp", expiry_kind="human",
        expiry_value=None,
    )
    active = store.active_restrictions(namespace="default", agent_id="agent_research")
    assert any(r["restriction_id"] == rid for r in active)


# -- development mode is unaffected ------------------------------------------

def test_development_mode_without_sqlite_keeps_in_memory_behaviour(make_governor):
    """No SQLiteStore wired in at all -- restrictions still work exactly as
    before this commit, purely in-memory, per-process."""
    g = make_governor()
    r1 = g.evaluate(_restrict_prop("dev-1"))
    assert r1.decision == Decision.RESTRICT
    assert g.audit.sqlite is None
    restricted_perms = {p for p, _, _ in g.restricted.get("agent_research", [])}
    assert make_permission("research") in restricted_perms
    r2 = g.evaluate(_prop("dev-2"))
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.AUTHORITY_ABUSE in r2.signals


# -- production mode requires durable restriction storage -------------------

def test_production_mode_requires_durable_restriction_storage():
    import dataclasses

    from chainmail import RestrictPolicy

    # production_mode also rejects TTL_STEPS (see test_crypto.py); use
    # TTL_WALLCLOCK so this test isolates the durable-storage requirement.
    env = dataclasses.replace(build_demo_envelope(), restrict_policy=RestrictPolicy.TTL_WALLCLOCK)

    with pytest.raises(ValueError, match="production_mode"):
        ChainmailGovernor(
            env,
            config=GovernorConfig.production(),
            verifier=CompositeVerifier(KeyRegistry()),
            execution_boundary=DenyAllExecutionBoundary(),
            auto_embedding=False,
        )
    g = ChainmailGovernor(
        env,
        config=GovernorConfig.production(),
        verifier=CompositeVerifier(KeyRegistry()),
        execution_boundary=DenyAllExecutionBoundary(),
        audit=AuditSink(sqlite_store=SQLiteStore()),
        auto_embedding=False,
    )
    assert g.security_report()["durable_restriction_protection"] is True
