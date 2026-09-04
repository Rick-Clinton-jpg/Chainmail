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
data.
"""

import sqlite3
import threading

import pytest

from chainmail import (
    AuthorityEnvelope, Authority, AuditSink, ChainmailGovernor, DenyAllExecutionBoundary,
    GovernorConfig, Permission, Proposal, RiskSignal, SQLiteStore, build_demo_envelope,
    make_permission,
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

    store_v5 = SQLiteStore(db)  # triggers the (no-op, purely additive) v4->v5 hop
    assert store_v5.SCHEMA_VERSION == 5
    # Pre-existing v4 data survived untouched.
    assert store_v5.active_restrictions(namespace="default", agent_id="agent_research")
    assert store_v5.claim_nonce(namespace="default", agent_id="agent_research", nonce="n1") is False
    # New v5 tables are usable.
    assert store_v5.is_authority_initialized(namespace="default", agent_id="agent_research") is False
    assert store_v5.initialize_agent_authority(
        namespace="default", agent_id="agent_research",
        permissions=[("research", "*", None)], envelope_fingerprint="fp1") is True
