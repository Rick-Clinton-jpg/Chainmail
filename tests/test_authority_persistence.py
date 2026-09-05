"""Durable live authority, permission budgets, and step (runtime) budgets.

Covers: restart does not restore surrendered authority or renew a consumed
budget, concurrent governor processes cannot both spend the last unit of a
budget or multiply it, a failed durable consumption never partially mutates
state, corrupted/deleted storage fails closed, cross-namespace isolation,
an agent cannot select another agent's budget via proposal fields, a
policy/envelope fingerprint change does not restore consumed authority, a
long delegation chain cannot launder authority beyond the original root
ceiling, contextual similarity cannot expand authority, and schema
migration from v4 leaves v5's new tables usable without disturbing existing
data (and v5 -> v6's additive mac/key_id columns are usable the same way).
"""

import sqlite3
import threading

import pytest

from chainmail import (
    AuthorityEnvelope, Authority, AuditSink, ChainmailGovernor, Decision,
    DenyAllExecutionBoundary, GovernorConfig, GovernorVote, Permission, Proposal, QuorumAggregator,
    RiskSignal, SQLiteStore, build_demo_envelope, make_permission,
)

from conftest import JaccardEmbeddingEngine

OBJ = "Build a secure multi-agent governance prototype"


def _narrowable_envelope():
    """A small envelope where 'root' can delegate to 'sub' -- unlike the
    demo envelope, whose roles hold disjoint permission sets and forbid
    self-delegation, so it cannot exercise a real authority-narrowing
    delegation. agent_root holds an unlimited deploy:staging (so it can
    legitimately offer any amount); agent_sub's own envelope ceiling caps
    deploy:staging at max_budget=5, so a delegation from agent_root must be
    clamped down to that ceiling regardless of what's offered."""
    return AuthorityEnvelope(
        objective=OBJ,
        agent_authorities={
            "agent_root": Authority(permissions={make_permission("deploy", "staging")}),
            "agent_sub": Authority(permissions={make_permission("deploy", "staging", max_budget=5)}),
        },
        allowed_delegations={"root": {"sub"}, "sub": set()},
        agent_roles={"agent_root": "root", "agent_sub": "sub"},
        max_fleet_steps=100,
    )


def _prop(pid, agent, perm, action="push_staging", confidence=0.85, **kw):
    return Proposal(pid, agent, action, perm, OBJ, confidence, **kw)


def _gov(sqlite_store, **kwargs):
    envelope = kwargs.pop("envelope", None) or build_demo_envelope()
    config = kwargs.pop("config", GovernorConfig())
    return ChainmailGovernor(
        envelope, config=config, embedding=JaccardEmbeddingEngine(), auto_embedding=False,
        audit=AuditSink(sqlite_store=sqlite_store), **kwargs,
    )


DEPLOY = make_permission("deploy", "staging", max_budget=5)  # agent_deploy's ceiling permission


# -- restart never restores authority or renews a budget --------------------

def test_restart_does_not_restore_surrendered_authority(tmp_path):
    db = str(tmp_path / "chainmail.db")
    env = _narrowable_envelope()
    g1 = _gov(SQLiteStore(db), envelope=env)
    # agent_root narrows agent_sub's authority to nothing -- a real
    # authority-reducing delegation (unlike revoke_delegation, which only
    # ever restores UP TO the envelope ceiling).
    ok, _ = g1.register_delegation("agent_root", "agent_sub", "narrow", Authority(permissions=set()))
    assert ok
    assert g1._get_live_auth("agent_sub").permissions == set()

    g2 = _gov(SQLiteStore(db), envelope=env)  # "restart": a fresh governor, same store
    assert g2._get_live_auth("agent_sub").permissions == set()
    assert not g2._get_live_auth("agent_sub").can(DEPLOY)


def test_restart_does_not_renew_permission_budget(tmp_path):
    db = str(tmp_path / "chainmail.db")
    g1 = _gov(SQLiteStore(db))
    for i in range(5):
        r = g1.evaluate(_prop(f"p{i}", "agent_deploy", DEPLOY))
        assert r.decision.value == "CONTINUE", r.reason
    r = g1.evaluate(_prop("p-over", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.BUDGET_EXHAUSTED in r.signals

    g2 = _gov(SQLiteStore(db))  # "restart"
    r = g2.evaluate(_prop("p-after-restart", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.BUDGET_EXHAUSTED in r.signals


def test_restart_does_not_renew_step_budget(tmp_path):
    import dataclasses
    db = str(tmp_path / "chainmail.db")
    env = dataclasses.replace(build_demo_envelope(), max_fleet_steps=2)
    g1 = _gov(SQLiteStore(db), envelope=env)
    assert g1.evaluate(_prop("p1", "agent_research", make_permission("research"))).decision.value \
        == "CONTINUE"
    assert g1.evaluate(_prop("p2", "agent_research", make_permission("research"))).decision.value \
        == "CONTINUE"
    r = g1.evaluate(_prop("p3", "agent_research", make_permission("research")))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.FLEET_BUDGET_EXHAUSTED in r.signals

    g2 = _gov(SQLiteStore(db), envelope=env)  # "restart"
    r = g2.evaluate(_prop("p4", "agent_research", make_permission("research")))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.FLEET_BUDGET_EXHAUSTED in r.signals


# -- concurrency: the last unit of a budget can only go to one winner -------

def test_two_governors_racing_for_the_last_budget_unit_only_one_wins(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g1 = _gov(store)
    g2 = _gov(store)
    # Drain to exactly one unit remaining.
    for i in range(4):
        assert g1.evaluate(_prop(f"drain{i}", "agent_deploy", DEPLOY)).decision.value == "CONTINUE"

    results = [None, None]

    def go(g, idx, pid):
        results[idx] = g.evaluate(_prop(pid, "agent_deploy", DEPLOY)).decision.value

    t1 = threading.Thread(target=go, args=(g1, 0, "race-a"))
    t2 = threading.Thread(target=go, args=(g2, 1, "race-b"))
    t1.start(); t2.start()
    t1.join(); t2.join()

    continues = results.count("CONTINUE")
    assert continues == 1, f"expected exactly one winner, got {results}"
    humans = results.count("HUMAN")
    assert humans == 1


def test_multiple_processes_cannot_multiply_a_budget(tmp_path):
    """Simulates several 'processes' (separate governor instances sharing one
    store) each independently believing they see full budget -- only 5 total
    CONTINUEs may ever be granted for a max_budget=5 permission, regardless
    of how many governor instances evaluate concurrently."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    governors = [_gov(store) for _ in range(5)]
    outcomes = []
    lock = threading.Lock()

    def hammer(g, base):
        for i in range(4):  # 5 governors x 4 = 20 attempts against a budget of 5
            r = g.evaluate(_prop(f"m{base}-{i}", "agent_deploy", DEPLOY))
            with lock:
                outcomes.append(r.decision.value)

    threads = [threading.Thread(target=hammer, args=(g, i)) for i, g in enumerate(governors)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count("CONTINUE") == 5


# -- transaction failure never partially mutates state ----------------------

def test_failed_atomic_consumption_does_not_partially_mutate_state(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    def _boom(**kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    store.consume_permission_budget = _boom
    before = g._get_live_auth("agent_deploy").budget_remaining.get(DEPLOY.key())
    r = g.evaluate(_prop("p1", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.AUTHORITY_STORE_UNAVAILABLE in r.signals
    after = g._get_live_auth("agent_deploy").budget_remaining.get(DEPLOY.key())
    assert after == before  # nothing was consumed by the failed attempt


def test_failed_delegation_publish_leaves_no_partial_state(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    def _boom(**kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    store.replace_live_authority = _boom
    before = g._get_live_auth("agent_coder").copy()
    ok, msg = g.register_delegation("agent_research", "agent_coder", "x",
                                    Authority(permissions={make_permission("research")}))
    assert not ok
    after = g._get_live_auth("agent_coder")
    assert after.permissions == before.permissions


# -- fail closed on unavailable / corrupted / deleted storage ---------------

def test_corrupted_storage_fails_closed(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    def _boom(**kwargs):
        raise sqlite3.DatabaseError("database disk image is malformed")

    store.get_live_authority_rows = _boom
    r = g.evaluate(_prop("p1", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.AUTHORITY_STORE_UNAVAILABLE in r.signals


def test_deleted_storage_fails_closed(tmp_path):
    # Closing/deleting the whole store makes every durable call raise,
    # starting with whichever check runs first (replay claim, before the
    # authority check) -- the specific signal is an artifact of evaluation
    # order, not the property under test: fail closed, never CONTINUE,
    # when the store this governor depends on is gone.
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)
    store.close()
    r = g.evaluate(_prop("p1", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert r.signals and all(s.name.endswith("_STORE_UNAVAILABLE") for s in r.signals)


# -- scoping: namespace, agent identity ---------------------------------

def test_cross_namespace_state_does_not_leak(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g_a = _gov(store, deployment_namespace="tenant-a")
    g_b = _gov(store, deployment_namespace="tenant-b")

    for i in range(5):
        assert g_a.evaluate(_prop(f"a{i}", "agent_deploy", DEPLOY)).decision.value == "CONTINUE"
    r = g_a.evaluate(_prop("a-over", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"

    # tenant-b's agent_deploy has its own, untouched budget.
    r = g_b.evaluate(_prop("b1", "agent_deploy", DEPLOY))
    assert r.decision.value == "CONTINUE"


def test_agent_identity_cannot_select_another_agents_budget(tmp_path):
    """A proposal's required_permission cannot be used to reach a different
    agent's durable budget row -- rows are always scoped by proposal.agent_id,
    never by anything the proposal itself supplies as a lookup key."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)
    # agent_research has no deploy:staging permission at all.
    r = g.evaluate(_prop("p1", "agent_research", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.AUTHORITY_ABUSE in r.signals
    # agent_deploy's budget is untouched by that attempt.
    assert g._get_live_auth("agent_deploy").budget_remaining.get(DEPLOY.key()) == 5


# -- envelope/policy fingerprint change does not restore authority ----------

def test_envelope_fingerprint_change_does_not_restore_consumed_budget(tmp_path):
    import dataclasses
    db = str(tmp_path / "chainmail.db")
    g1 = _gov(SQLiteStore(db))
    for i in range(5):
        assert g1.evaluate(_prop(f"p{i}", "agent_deploy", DEPLOY)).decision.value == "CONTINUE"
    assert g1.evaluate(_prop("p-over", "agent_deploy", DEPLOY)).decision.value == "HUMAN"

    # A different envelope (different fingerprint, same known agents/perms)
    # must not reset the durably-consumed budget.
    changed_env = dataclasses.replace(build_demo_envelope(), max_fleet_steps=999)
    g2 = _gov(SQLiteStore(db), envelope=changed_env)
    assert g1.envelope._construction_fingerprint != g2.envelope._construction_fingerprint
    r = g2.evaluate(_prop("p-after-policy-change", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.BUDGET_EXHAUSTED in r.signals


# -- delegation chains cannot launder authority ------------------------------

def test_long_delegation_chain_cannot_exceed_root_ceiling(tmp_path):
    """agent_research holds no 'deploy' permission at all, so it cannot
    offer (let alone inflate) one via delegation -- durable persistence
    must not change this math."""
    db = str(tmp_path / "chainmail.db")
    g = _gov(SQLiteStore(db))
    huge = Permission("deploy", "staging", max_budget=9999)
    ok, msg = g.register_delegation("agent_research", "agent_coder", "x",
                                    Authority(permissions={huge}))
    assert not ok


def test_repeated_delegation_below_hop_ceilings_still_respects_root_ceiling(tmp_path):
    """agent_root legitimately holds an *unlimited* deploy:staging and
    offers exactly that to agent_sub -- but agent_sub's own envelope
    ceiling caps deploy:staging at max_budget=5. clamp_to_ceiling must
    clamp to agent_sub's ceiling regardless of what's offered, and that
    clamped value -- not the unlimited offer -- is what's durably
    published."""
    db = str(tmp_path / "chainmail.db")
    env = _narrowable_envelope()
    g = _gov(SQLiteStore(db), envelope=env)
    unlimited = Permission("deploy", "staging", max_budget=None)
    ok, msg = g.register_delegation("agent_root", "agent_sub", "unlimited-offer",
                                    Authority(permissions={unlimited}))
    assert ok
    live = g._get_live_auth("agent_sub")
    matched = live.resolve(make_permission("deploy", "staging"))
    assert matched is not None
    assert matched.max_budget == 5

    # Durable across a restart too -- the clamped value, not the offer.
    g2 = _gov(SQLiteStore(db), envelope=env)
    matched2 = g2._get_live_auth("agent_sub").resolve(make_permission("deploy", "staging"))
    assert matched2.max_budget == 5


# -- contextual similarity cannot expand authority ---------------------------

def test_contextual_similarity_cannot_grant_authority_agent_lacks(tmp_path):
    db = str(tmp_path / "chainmail.db")
    g = _gov(SQLiteStore(db))
    # agent_research has no deploy:staging permission; a perfectly on-topic,
    # high-confidence objective fragment must not grant it anyway.
    r = g.evaluate(_prop("p1", "agent_research", DEPLOY,
                        confidence=0.99))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.AUTHORITY_ABUSE in r.signals


# -- production mode -------------------------------------------------------

def test_production_mode_requires_durable_authority_storage():
    from chainmail import CompositeVerifier, KeyRegistry, RestrictPolicy
    import dataclasses
    env = dataclasses.replace(build_demo_envelope(), restrict_policy=RestrictPolicy.TTL_WALLCLOCK)
    with pytest.raises(ValueError, match="production_mode"):
        ChainmailGovernor(
            env, config=GovernorConfig.production(),
            verifier=CompositeVerifier(KeyRegistry()),
            execution_boundary=DenyAllExecutionBoundary(),
            auto_embedding=False,
        )
    g = ChainmailGovernor(
        env, config=GovernorConfig.production(),
        verifier=CompositeVerifier(KeyRegistry()),
        execution_boundary=DenyAllExecutionBoundary(),
        audit=AuditSink(sqlite_store=SQLiteStore()),
        auto_embedding=False,
    )
    assert g.security_report()["durable_authority_and_budgets"] is True


# -- schema migration ---------------------------------------------------

def test_v4_database_upgrades_to_v5_without_disturbing_existing_data(tmp_path):
    db = str(tmp_path / "chainmail.db")
    store_v4 = SQLiteStore(db)
    store_v4.impose_restriction(
        namespace="default", agent_id="agent_research", permission_name="research",
        permission_scope="*", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    store_v4.claim_nonce(namespace="default", agent_id="agent_research", nonce="n1")
    store_v4._conn.execute("UPDATE schema_version SET version = 4")
    store_v4._conn.commit()
    store_v4.close()

    store_v5 = SQLiteStore(db)  # triggers the (no-op, purely additive) v4->current hop
    assert store_v5._conn.execute(
        "SELECT version FROM schema_version"
    ).fetchone()[0] == SQLiteStore.SCHEMA_VERSION
    # Pre-existing v4 data survived untouched.
    assert store_v5.active_restrictions(namespace="default", agent_id="agent_research")
    assert store_v5.claim_nonce(namespace="default", agent_id="agent_research", nonce="n1") is False
    # New v5 tables are usable.
    assert store_v5.is_authority_initialized(namespace="default", agent_id="agent_research") is False
    assert store_v5.initialize_agent_authority(
        namespace="default", agent_id="agent_research",
        permissions=[("research", "*", None)], envelope_fingerprint="fp1") is True


def test_v5_database_upgrades_to_v6_with_mac_columns_usable(tmp_path):
    """A v5 database (live_authority/live_authority_agents without mac/
    key_id columns) upgrades to v6 by adding those columns -- purely
    additive, no data migration -- and a key_provider attached afterwards
    can immediately read/write authenticated rows against it."""
    from chainmail.persistence import InMemoryKeyProvider

    db = str(tmp_path / "chainmail.db")
    store_v5 = SQLiteStore(db)
    store_v5.initialize_agent_authority(
        namespace="default", agent_id="agent_research",
        permissions=[("research", "*", 5)], envelope_fingerprint="fp1")
    # Simulate a genuine pre-v6 table shape (no mac/key_id columns yet) --
    # SQLiteStore always creates the current (v6) shape, so rebuild the
    # table the way v5 actually left it before the migration this test
    # exercises existed.
    store_v5._conn.executescript("""
        ALTER TABLE live_authority RENAME TO live_authority_v5;
        CREATE TABLE live_authority (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deployment_namespace TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            permission_name TEXT NOT NULL,
            permission_scope TEXT NOT NULL,
            max_budget INTEGER,
            remaining INTEGER,
            source TEXT NOT NULL,
            envelope_fingerprint TEXT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            UNIQUE (deployment_namespace, agent_id, permission_name, permission_scope)
        );
        INSERT INTO live_authority (deployment_namespace, agent_id, permission_name,
            permission_scope, max_budget, remaining, source, envelope_fingerprint,
            created_at, updated_at)
        SELECT deployment_namespace, agent_id, permission_name, permission_scope,
            max_budget, remaining, source, envelope_fingerprint, created_at, updated_at
        FROM live_authority_v5;
        DROP TABLE live_authority_v5;
    """)
    store_v5._conn.execute("UPDATE schema_version SET version = 5")
    store_v5._conn.commit()
    cols_before = {row[1] for row in
                   store_v5._conn.execute("PRAGMA table_info(live_authority)").fetchall()}
    assert "mac" not in cols_before
    store_v5.close()

    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store_v6 = SQLiteStore(db, key_provider=key_provider)
    cols_after = {row[1] for row in
                  store_v6._conn.execute("PRAGMA table_info(live_authority)").fetchall()}
    assert {"mac", "key_id"} <= cols_after
    # Pre-existing v5 row has no mac yet -- reading it with a key_provider
    # now attached must fail closed, not silently trust an unauthenticated
    # legacy row now that authentication is turned on.
    with pytest.raises(sqlite3.Error):
        store_v6.get_live_authority_rows(namespace="default", agent_id="agent_research")
    # A freshly written row is authenticated and readable.
    store_v6.replace_live_authority(
        namespace="default", agent_id="agent_research",
        permissions=[("research", "*", 5)], source="delegation", envelope_fingerprint="fp2")
    rows = store_v6.get_live_authority_rows(namespace="default", agent_id="agent_research")
    assert rows[0]["remaining"] == 5


def test_v6_database_upgrades_to_v7_with_mac_columns_usable(tmp_path):
    """A v6 database (restrictions/replay_nonces/replay_proposal_ids/
    step_counters without mac/key_id columns -- only live_authority/
    live_authority_agents had them at v6) upgrades to v7 by adding those
    columns to the remaining tables -- purely additive, no data migration
    -- and a key_provider attached afterwards can immediately read/write
    authenticated rows against them."""
    from chainmail.persistence import InMemoryKeyProvider

    db = str(tmp_path / "chainmail.db")
    store_v6 = SQLiteStore(db)
    store_v6.impose_restriction(
        namespace="default", agent_id="agent_research", permission_name="research",
        permission_scope="*", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    # Simulate a genuine pre-v7 `restrictions` shape (no mac/key_id yet).
    store_v6._conn.executescript("""
        ALTER TABLE restrictions RENAME TO restrictions_v6;
        CREATE TABLE restrictions (
            restriction_id TEXT PRIMARY KEY,
            deployment_namespace TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            permission_name TEXT NOT NULL,
            permission_scope TEXT NOT NULL,
            permission_max_budget INTEGER,
            status TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            source_proposal_id TEXT NOT NULL,
            envelope_fingerprint TEXT,
            expiry_kind TEXT NOT NULL,
            expiry_value REAL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            cleared_by TEXT,
            cleared_reason TEXT,
            cleared_policy_version TEXT
        );
        INSERT INTO restrictions (restriction_id, deployment_namespace, agent_id,
            permission_name, permission_scope, permission_max_budget, status,
            reason_code, source_proposal_id, envelope_fingerprint, expiry_kind,
            expiry_value, created_at, updated_at, cleared_by, cleared_reason,
            cleared_policy_version)
        SELECT restriction_id, deployment_namespace, agent_id, permission_name,
            permission_scope, permission_max_budget, status, reason_code,
            source_proposal_id, envelope_fingerprint, expiry_kind, expiry_value,
            created_at, updated_at, cleared_by, cleared_reason, cleared_policy_version
        FROM restrictions_v6;
        DROP TABLE restrictions_v6;
    """)
    store_v6._conn.execute("UPDATE schema_version SET version = 6")
    store_v6._conn.commit()
    cols_before = {row[1] for row in
                   store_v6._conn.execute("PRAGMA table_info(restrictions)").fetchall()}
    assert "mac" not in cols_before
    store_v6.close()

    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store_v7 = SQLiteStore(db, key_provider=key_provider)
    cols_after = {row[1] for row in
                  store_v7._conn.execute("PRAGMA table_info(restrictions)").fetchall()}
    assert {"mac", "key_id"} <= cols_after
    # Pre-existing v6 row has no mac -- reading it now that authentication
    # is turned on must fail closed, not silently trust it.
    with pytest.raises(sqlite3.Error):
        store_v7.active_restrictions(namespace="default", agent_id="agent_research")
    # A freshly-imposed restriction is authenticated and readable.
    store_v7.impose_restriction(
        namespace="default", agent_id="agent_research", permission_name="research",
        permission_scope="*", permission_max_budget=None, reason_code="TEST2",
        source_proposal_id="p2", envelope_fingerprint="fp2", expiry_kind="human",
        expiry_value=None,
    )
    assert len(store_v7._conn.execute(
        "SELECT 1 FROM restrictions WHERE reason_code = 'TEST2'"
    ).fetchall()) == 1


def test_v7_database_upgrades_to_v8_with_initialization_ledger_usable(tmp_path):
    """A v7 database (no initialization_ledger table at all) upgrades to
    v8 by creating that table fresh -- no ALTER needed, since it's a brand
    new table rather than new columns on an existing one -- and a
    key_provider attached afterwards can immediately use it."""
    from chainmail.persistence import InMemoryKeyProvider

    db = str(tmp_path / "chainmail.db")
    store_v7 = SQLiteStore(db)
    store_v7.initialize_agent_authority(
        namespace="default", agent_id="agent_research",
        permissions=[("research", "*", 5)], envelope_fingerprint="fp1")
    store_v7._conn.execute("DROP TABLE initialization_ledger")
    store_v7._conn.execute("UPDATE schema_version SET version = 7")
    store_v7._conn.commit()
    assert not store_v7._table_exists(store_v7._conn, "initialization_ledger")
    store_v7.close()

    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store_v8 = SQLiteStore(db, key_provider=key_provider)
    assert store_v8._table_exists(store_v8._conn, "initialization_ledger")
    store_v8.verify_integrity_ledger()  # empty ledger, does not raise

    # agent_research was initialized before authentication was turned on --
    # no ledger entry exists for it, so the cross-check in
    # is_authority_initialized must fail closed rather than silently
    # trusting the pre-existing, now-unverifiable marker row.
    with pytest.raises(sqlite3.Error):
        store_v8.is_authority_initialized(namespace="default", agent_id="agent_research")

    # A freshly-initialized agent gets a matching marker + ledger entry.
    assert store_v8.initialize_agent_authority(
        namespace="default", agent_id="agent_new",
        permissions=[("research", "*", 5)], envelope_fingerprint="fp2") is True
    assert store_v8.is_authority_initialized(namespace="default", agent_id="agent_new") is True
    store_v8.verify_integrity_ledger()


# -- freshness rule: no previously-resolved Authority reused across hops/decisions --
#
# ChainmailGovernor._evaluate_locked() fetches live_auth/current_auth once,
# early (around the permission/budget *check*, step 10-11) -- but the
# durable-path *consumption* decision (15b) re-resolves authority fresh
# against the store right at that point, rather than reusing the object
# fetched several steps earlier. This matters because real time (and real
# elapsed work: contextual-risk checks, quorum collection) passes between
# the two, during which another governor process sharing the same store can
# durably revoke or narrow the agent's authority.

def test_upstream_revocation_blocks_a_downstream_consume_racing_against_it(tmp_path):
    """A quorum transport is a natural place for another process's action to
    land mid-evaluate(): its collect() call is where this test revokes
    agent_sub's authority via a *second* governor sharing the same store,
    while the *first* governor's evaluate() call is paused exactly between
    fetching live_auth (step 10) and the durable consume (15b). Without the
    freshness re-check at 15b, the first governor would still consume budget
    and (if an execution boundary were wired in) execute, using the
    Authority object it resolved before the revocation landed."""
    db = str(tmp_path / "chainmail.db")
    env = _narrowable_envelope()
    store = SQLiteStore(db)
    revoker = _gov(store, envelope=env)  # a separate governor "process"

    class RevokeDuringQuorum:
        def collect(self, own):
            ok, msg = revoker.register_delegation(
                "agent_root", "agent_sub", "revoke-mid-flight", Authority(permissions=set()))
            assert ok, msg
            return [own]

    g = _gov(store, envelope=env, quorum=QuorumAggregator(), quorum_transport=RevokeDuringQuorum())
    r = g.evaluate(_prop("p1", "agent_sub", make_permission("deploy", "staging")))
    assert r.decision == Decision.HUMAN
    assert RiskSignal.AUTHORITY_ABUSE in r.signals
    # And the revocation, not a stale pre-revocation view, is what's reported.
    assert not r.effective_authority.can(make_permission("deploy", "staging"))


def _three_tier_envelope():
    """agent_admin -> agent_mid -> agent_leaf, so a *middle* agent's
    authority (the thing register_delegation checks with is_subset_of) can
    itself be narrowed by an upstream actor, independent of the envelope
    ceiling. Used only by the delegation-side freshness test."""
    return AuthorityEnvelope(
        objective=OBJ,
        agent_authorities={
            "agent_admin": Authority(permissions={make_permission("deploy", "staging")}),
            "agent_mid": Authority(permissions={make_permission("deploy", "staging")}),
            "agent_leaf": Authority(permissions={make_permission("deploy", "staging")}),
        },
        allowed_delegations={"admin": {"mid"}, "mid": {"leaf"}, "leaf": set()},
        agent_roles={"agent_admin": "admin", "agent_mid": "mid", "agent_leaf": "leaf"},
        max_fleet_steps=100,
    )


def test_upstream_narrowing_blocks_a_downstream_delegation_using_stale_authority(tmp_path):
    """register_delegation resolves from_auth fresh, inside the call, from
    the durable store -- never from anything the caller could have fetched
    and held onto earlier. A delegator (agent_mid) whose own authority is
    narrowed to nothing by a separate governor process, moments before it
    tries to delegate onward, cannot succeed: there is no code path by
    which a previously-resolved Authority object could reach
    register_delegation's is_subset_of check instead of a fresh read."""
    db = str(tmp_path / "chainmail.db")
    env = _three_tier_envelope()
    store = SQLiteStore(db)
    g1 = _gov(store, envelope=env)  # will attempt mid -> leaf
    g2 = _gov(store, envelope=env)  # narrows mid, as a separate process

    # Confirm agent_mid genuinely holds the permission before narrowing.
    assert g1._get_live_auth("agent_mid").can(make_permission("deploy", "staging"))

    ok, msg = g2.register_delegation("agent_admin", "agent_mid", "narrow-mid",
                                     Authority(permissions=set()))
    assert ok, msg
    assert not g1._get_live_auth("agent_mid").can(make_permission("deploy", "staging"))

    # g1 now attempts to delegate from agent_mid, which it never separately
    # "resolved and cached" -- register_delegation must see the narrowed
    # state, not the ceiling agent_mid started with.
    ok, msg = g1.register_delegation("agent_mid", "agent_leaf", "onward",
                                     Authority(permissions={make_permission("deploy", "staging")}))
    assert not ok
    assert "does not hold" in msg


def test_two_governors_racing_for_the_last_budget_unit_only_one_wins_v2(tmp_path):
    """Same guarantee as test_two_governors_racing_for_the_last_budget_unit_
    only_one_wins above, restated here under the freshness-rule section
    since it is the same atomic-consume mechanism the freshness re-check
    (15b) now gates -- kept as a second, independent instance rather than a
    duplicate to make this section self-contained."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g1 = _gov(store)
    g2 = _gov(store)
    for i in range(4):
        assert g1.evaluate(_prop(f"drain{i}", "agent_deploy", DEPLOY)).decision.value == "CONTINUE"

    results = [None, None]

    def go(g, idx, pid):
        results[idx] = g.evaluate(_prop(pid, "agent_deploy", DEPLOY)).decision.value

    t1 = threading.Thread(target=go, args=(g1, 0, "race-a"))
    t2 = threading.Thread(target=go, args=(g2, 1, "race-b"))
    t1.start(); t2.start()
    t1.join(); t2.join()
    assert results.count("CONTINUE") == 1
    assert results.count("HUMAN") == 1


def test_restart_after_partial_budget_consumption_survives_exactly(tmp_path):
    """Consume 2 of 5 units, then 'restart' (fresh governor, same store) --
    remaining must be exactly 3, never reset to the envelope ceiling (5)."""
    db = str(tmp_path / "chainmail.db")
    g1 = _gov(SQLiteStore(db))
    for i in range(2):
        assert g1.evaluate(_prop(f"p{i}", "agent_deploy", DEPLOY)).decision.value == "CONTINUE"

    g2 = _gov(SQLiteStore(db))  # "restart"
    remaining = g2._get_live_auth("agent_deploy").budget_remaining.get(DEPLOY.key())
    assert remaining == 3

    # And it keeps counting down correctly from exactly there, not from 5.
    for i in range(3):
        assert g2.evaluate(_prop(f"q{i}", "agent_deploy", DEPLOY)).decision.value == "CONTINUE"
    r = g2.evaluate(_prop("q-over", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.BUDGET_EXHAUSTED in r.signals


def test_store_unavailable_during_the_freshness_recheck_fails_closed(tmp_path):
    """Breaking the store specifically at the point the freshness re-check
    (15b) queries it -- not the earlier check at (10-11) -- must still fail
    closed. Simulated by making active_restrictions (called inside
    _effective_authority, which 15b calls fresh) raise only after the first
    successful call, so the early check at (10) succeeds and the freshness
    re-check at (15b) is what hits the failure."""
    db = str(tmp_path / "chainmail.db")
    store = SQLiteStore(db)
    g = _gov(store)

    real_active_restrictions = store.active_restrictions
    calls = {"n": 0}

    def flaky(**kwargs):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise sqlite3.OperationalError("disk I/O error")
        return real_active_restrictions(**kwargs)

    store.active_restrictions = flaky
    r = g.evaluate(_prop("p1", "agent_deploy", DEPLOY))
    assert r.decision.value == "HUMAN"
    assert RiskSignal.AUTHORITY_STORE_UNAVAILABLE in r.signals
    assert calls["n"] >= 2  # proves the freshness re-check really ran (and failed)
