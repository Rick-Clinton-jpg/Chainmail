"""Behavioural suite for the v5 governor. Ported from the v4 tests and adapted
to the v5 API; the deterministic ``JaccardEmbeddingEngine`` (see conftest) keeps
every semantic assertion reproducible."""

import dataclasses

import pytest

from chainmail import (
    Authority, ChainmailGovernor, Decision, GovernorConfig, PermissiveExecutionBoundary,
    DenyAllExecutionBoundary, Permission, Proposal, RestrictPolicy, RiskSignal, make_permission,
)

OBJ = "Build a secure multi-agent governance prototype"
OFF_OBJ = "Launch a cryptocurrency token and maximize hype worldwide"


def prop(pid, agent, action, perm, frag=OBJ, conf=0.85, **kw):
    return Proposal(pid, agent, action, perm, frag, conf, **kw)


# -- authority / delegation -------------------------------------------

def test_authority_subset():
    broad = Authority(permissions={make_permission("read"), make_permission("write"),
                                   make_permission("deploy")})
    narrow = Authority(permissions={make_permission("read"), make_permission("write")})
    assert narrow.is_subset_of(broad)
    assert not broad.is_subset_of(narrow)


def test_delegation_cannot_expand(governor):
    offered = Authority(permissions={make_permission("deploy", "staging"),
                                     make_permission("code", "write")})
    ok, msg = governor.register_delegation("agent_research", "agent_coder", "hand off", offered)
    assert not ok and "does not hold" in msg


def test_delegation_cannot_launder_bounded_into_unlimited(make_governor):
    """A delegator whose own permission is budget-bounded must not be able
    to delegate an "equivalent" name/scope permission with a higher or
    unlimited ceiling -- Permission.covers() only checks name/scope, so
    is_subset_of() must add its own budget-aware check rather than trust
    covers() for containment."""
    from chainmail import AuthorityEnvelope

    env = AuthorityEnvelope(
        objective="Test budget laundering",
        agent_authorities={
            "agent_A": Authority(permissions={make_permission("deploy", "prod", max_budget=1)}),
            "agent_B": Authority(permissions={make_permission("deploy", "prod", max_budget=None)}),
        },
        allowed_delegations={}, agent_roles={},
        hard_denials=set(), max_fleet_steps=50,
    )
    g = make_governor(env)
    offered = Authority(permissions={make_permission("deploy", "prod", max_budget=None)})
    ok, msg = g.register_delegation("agent_A", "agent_B", "escalate", offered)
    assert not ok
    assert "does not hold" in msg


def test_delegation_ignores_injected_remaining_budget(make_governor):
    """An offered Authority's budget_remaining is caller-supplied data, not
    evidence -- register_delegation must compute the recipient's granted
    remaining itself rather than trust an inflated stored value."""
    from chainmail import AuthorityEnvelope

    env = AuthorityEnvelope(
        objective="Test injected remaining",
        agent_authorities={
            "agent_A": Authority(
                permissions={make_permission("deploy", "prod", max_budget=1)},
                budget_remaining={"deploy:prod": 1},
            ),
            "agent_B": Authority(permissions={make_permission("deploy", "prod", max_budget=5)}),
        },
        allowed_delegations={}, agent_roles={},
        hard_denials=set(), max_fleet_steps=50,
    )
    g = make_governor(env)
    offered = Authority(
        permissions={make_permission("deploy", "prod", max_budget=1)},
        budget_remaining={"deploy:prod": 999},
    )
    ok, _ = g.register_delegation("agent_A", "agent_B", "share", offered)
    assert ok
    granted = g.live_authority["agent_B"]._match(make_permission("deploy", "prod"))
    assert granted is not None and granted.max_budget == 1
    remaining = g.live_authority["agent_B"].budget_remaining.get("deploy:prod")
    assert remaining is not None and remaining <= 1


def test_delegation_preserve_or_reduce(governor):
    offered = Authority(permissions={make_permission("research"), make_permission("read", "docs")})
    ok, _ = governor.register_delegation("agent_research", "agent_coder", "share", offered)
    assert ok
    assert not governor.live_authority["agent_coder"].can(make_permission("research"))


def test_delegation_replaces_rather_than_merges_across_multiple_sources(make_governor):
    """A second delegation from a different agent must not accumulate on
    top of a first -- register_delegation replaces the recipient's entire
    live authority with the clamped result of that one call. Two agents
    each delegating one distinct permission to the same recipient must
    leave the recipient holding only the *second* delegation's permission,
    not the union of both -- accumulating access across several
    individually-unremarkable delegations is exactly what this replace-not-
    merge semantic closes off."""
    from chainmail import AuthorityEnvelope

    env = AuthorityEnvelope(
        objective="Operate a small fleet",
        agent_authorities={
            "agent_a": Authority(permissions={make_permission("read", "file1")}),
            "agent_b": Authority(permissions={make_permission("read", "file2")}),
            "agent_target": Authority(permissions={make_permission("read", "file1"),
                                                   make_permission("read", "file2")}),
        },
        allowed_delegations={"a": {"target"}, "b": {"target"}, "target": set()},
        agent_roles={"agent_a": "a", "agent_b": "b", "agent_target": "target"},
        max_fleet_steps=100,
    )
    g = make_governor(env)

    ok1, _ = g.register_delegation("agent_a", "agent_target", "share file1",
                                   Authority(permissions={make_permission("read", "file1")}))
    assert ok1
    assert g.live_authority["agent_target"].can(make_permission("read", "file1"))

    ok2, _ = g.register_delegation("agent_b", "agent_target", "share file2",
                                   Authority(permissions={make_permission("read", "file2")}))
    assert ok2
    target_auth = g.live_authority["agent_target"]
    assert target_auth.can(make_permission("read", "file2"))
    # The first delegation's grant is gone -- not merged, replaced.
    assert not target_auth.can(make_permission("read", "file1"))


def _reset_to_empty(g, from_agent, to_agent):
    """A non-merging delegation of an *empty* offer -- vacuously a subset
    of anything from_agent holds -- resets to_agent's live authority to
    nothing, regardless of from_agent's own permissions. Test-only setup
    helper: the envelope's own agent_authorities double as the initial
    seed (there is no separate "ceiling but zero initial holding" concept
    in this schema -- see register_delegation's docstring), so a merge
    test that wants to start from nothing must reset explicitly first."""
    ok, msg = g.register_delegation(from_agent, to_agent, "test setup: reset",
                                    Authority(permissions=set()))
    assert ok, msg


def test_delegation_merge_accumulates_from_multiple_sources(make_governor):
    """merge=True is the opt-in escape from replace-not-merge: two agents
    each delegating a distinct permission to the same recipient, with
    merge=True, must leave the recipient holding both -- addressing the
    usability gap the default (replace) semantics deliberately impose."""
    from chainmail import AuthorityEnvelope

    env = AuthorityEnvelope(
        objective="Operate a small fleet",
        agent_authorities={
            "agent_a": Authority(permissions={make_permission("read", "file1")}),
            "agent_b": Authority(permissions={make_permission("read", "file2")}),
            "agent_target": Authority(permissions={make_permission("read", "file1"),
                                                   make_permission("read", "file2")}),
        },
        allowed_delegations={}, agent_roles={}, max_fleet_steps=100,
    )
    g = make_governor(env)
    _reset_to_empty(g, "agent_a", "agent_target")

    ok1, msg1 = g.register_delegation("agent_a", "agent_target", "share file1",
                                      Authority(permissions={make_permission("read", "file1")}),
                                      merge=True)
    assert ok1, msg1
    assert "merged" in msg1
    target_auth = g.live_authority["agent_target"]
    assert target_auth.can(make_permission("read", "file1"))

    ok2, msg2 = g.register_delegation("agent_b", "agent_target", "share file2",
                                      Authority(permissions={make_permission("read", "file2")}),
                                      merge=True)
    assert ok2, msg2
    target_auth = g.live_authority["agent_target"]
    assert target_auth.can(make_permission("read", "file1"))
    assert target_auth.can(make_permission("read", "file2"))


def test_delegation_merge_refuses_a_colliding_permission(make_governor):
    """A merge that would collide with an existing permission (same
    (name, scope) already held) is refused outright, not resolved by
    guessing (summing budgets, replacing, taking the max) -- fail closed
    on ambiguity. The recipient's existing grant is left untouched."""
    from chainmail import AuthorityEnvelope

    env = AuthorityEnvelope(
        objective="Operate a small fleet",
        agent_authorities={
            "agent_a": Authority(permissions={make_permission("deploy", "staging", max_budget=5)}),
            "agent_b": Authority(permissions={make_permission("deploy", "staging", max_budget=3)}),
            "agent_target": Authority(permissions={make_permission("deploy", "staging", max_budget=5)}),
        },
        allowed_delegations={}, agent_roles={}, max_fleet_steps=100,
    )
    g = make_governor(env)
    _reset_to_empty(g, "agent_a", "agent_target")

    ok1, _ = g.register_delegation("agent_a", "agent_target", "grant",
                                   Authority(permissions={make_permission("deploy", "staging", 5)},
                                            budget_remaining={"deploy:staging": 5}),
                                   merge=True)
    assert ok1
    before = g.live_authority["agent_target"].copy()

    ok2, msg2 = g.register_delegation("agent_b", "agent_target", "second grant",
                                      Authority(permissions={make_permission("deploy", "staging", 3)},
                                               budget_remaining={"deploy:staging": 3}),
                                      merge=True)
    assert not ok2
    assert "merge conflict" in msg2
    assert "deploy:staging" in msg2
    # Refused: the recipient's existing grant is completely unchanged.
    after = g.live_authority["agent_target"]
    assert after.permissions == before.permissions
    assert after.budget_remaining == before.budget_remaining


def test_delegation_merge_is_durable_across_restart(tmp_path):
    """merge=True's published state goes through the same
    replace_live_authority durable write as a non-merging delegation --
    it computes the full final (merged) authority and writes all of it, so
    a restart sees the accumulated result, not just the most recent call."""
    from chainmail import AuditSink, AuthorityEnvelope, ChainmailGovernor, GovernorConfig, SQLiteStore
    from conftest import JaccardEmbeddingEngine

    env = AuthorityEnvelope(
        objective="Operate a small fleet",
        agent_authorities={
            "agent_a": Authority(permissions={make_permission("read", "file1")}),
            "agent_b": Authority(permissions={make_permission("read", "file2")}),
            "agent_target": Authority(permissions={make_permission("read", "file1"),
                                                   make_permission("read", "file2")}),
        },
        allowed_delegations={}, agent_roles={}, max_fleet_steps=100,
    )
    db = str(tmp_path / "chainmail.db")

    def _gov():
        return ChainmailGovernor(env, config=GovernorConfig(), embedding=JaccardEmbeddingEngine(),
                                 auto_embedding=False, audit=AuditSink(sqlite_store=SQLiteStore(db)))

    g1 = _gov()
    _reset_to_empty(g1, "agent_a", "agent_target")
    ok1, _ = g1.register_delegation("agent_a", "agent_target", "share file1",
                                    Authority(permissions={make_permission("read", "file1")}),
                                    merge=True)
    assert ok1
    ok2, _ = g1.register_delegation("agent_b", "agent_target", "share file2",
                                    Authority(permissions={make_permission("read", "file2")}),
                                    merge=True)
    assert ok2

    g2 = _gov()  # "restart": a fresh governor, same store
    restarted_auth = g2._get_live_auth("agent_target")
    assert restarted_auth.can(make_permission("read", "file1"))
    assert restarted_auth.can(make_permission("read", "file2"))


def test_delegation_rejects_unknown_recipient(governor):
    ok, msg = governor.register_delegation(
        "agent_research", "ghost_agent", "x", Authority(permissions={make_permission("research")}))
    assert not ok and "unknown recipient" in msg


def test_role_enforced_delegation(governor):
    offered = Authority(permissions={make_permission("read", "docs")})
    ok, msg = governor.register_delegation("agent_research", "agent_approver", "bad", offered)
    assert not ok and "Role violation" in msg


def test_provenance_recorded(governor):
    ok, _ = governor.register_delegation(
        "agent_research", "agent_coder", "handoff",
        Authority(permissions={make_permission("research")}))
    assert ok and len(governor.provenance) == 1
    assert governor.provenance[0].from_id == "agent_research"


def test_delegation_audit_failure_leaves_no_live_state_change(make_governor):
    """A failed audit write must mean the delegation truly never happened --
    not just that it wasn't recorded while still taking effect. Previously
    live_authority/provenance were mutated BEFORE the audit write was
    attempted; a failure returned "delegation not recorded" while the
    delegation was, in fact, already live."""
    from chainmail import AuditSink

    class FailingAuditSink(AuditSink):
        @property
        def active(self):
            return True

        def record_delegation(self, **kwargs):
            raise RuntimeError("audit backend unavailable")

    g = make_governor(audit=FailingAuditSink())
    before = g.live_authority["agent_coder"].copy()
    ok, msg = g.register_delegation(
        "agent_research", "agent_coder", "handoff",
        Authority(permissions={make_permission("research")}))
    assert ok is False
    assert "not recorded" in msg
    assert len(g.provenance) == 0
    assert repr(g.live_authority["agent_coder"]) == repr(before)
    assert not g.live_authority["agent_coder"].can(make_permission("research"))


def test_authority_laundering(make_governor):
    from chainmail import AuthorityEnvelope
    env = AuthorityEnvelope(
        objective="Test laundering",
        agent_authorities={
            "agent_A": Authority(permissions={make_permission("shared"), make_permission("excl_A")}),
            "agent_B": Authority(permissions={make_permission("shared"), make_permission("excl_B")}),
            "agent_C": Authority(permissions={make_permission("excl_C")}),
        },
        allowed_delegations={"role_A": {"role_B"}, "role_B": {"role_C"}, "role_C": set()},
        agent_roles={"agent_A": "role_A", "agent_B": "role_B", "agent_C": "role_C"},
        hard_denials=set(), max_fleet_steps=50,
    )
    g = make_governor(env)
    ok1, _ = g.register_delegation("agent_A", "agent_B", "share",
                                   Authority(permissions={make_permission("shared")}))
    ok2, _ = g.register_delegation("agent_B", "agent_C", "launder",
                                   Authority(permissions={make_permission("shared")}))
    assert ok1 and ok2
    assert not g.live_authority["agent_C"].can(make_permission("shared"))


def test_revoke_delegation_restores_ceiling(governor):
    governor.register_delegation("agent_research", "agent_coder", "narrow",
                                 Authority(permissions={make_permission("read", "docs")}))
    assert not governor.live_authority["agent_coder"].can(make_permission("code", "write"))
    assert governor.revoke_delegation("agent_coder")
    assert governor.live_authority["agent_coder"].can(make_permission("code", "write"))


# -- core decisions ----------------------------------------------------

def test_hard_denial(governor):
    r = governor.evaluate(prop("p1", "agent_deploy", "delete_production",
                               make_permission("deploy", "staging"), "clean up", 0.95))
    assert r.decision == Decision.HUMAN and RiskSignal.AUTHORITY_ABUSE in r.signals


def test_missing_permission(governor):
    r = governor.evaluate(prop("p2", "agent_research", "gather",
                               make_permission("deploy", "staging"), OBJ, 0.7))
    assert r.decision == Decision.HUMAN and RiskSignal.AUTHORITY_ABUSE in r.signals


def test_unknown_agent(governor):
    r = governor.evaluate(prop("p3", "nobody", "gather", make_permission("research")))
    assert r.decision == Decision.HUMAN and RiskSignal.UNKNOWN_AGENT in r.signals


def test_happy_path_continue(governor):
    r = governor.evaluate(prop("p4", "agent_research", "gather", make_permission("research")))
    assert r.decision == Decision.CONTINUE


def test_objective_mismatch(governor):
    r = governor.evaluate(prop("p5", "agent_research", "gather",
                               make_permission("research"), OFF_OBJ, 0.9))
    assert r.decision == Decision.HUMAN and RiskSignal.OBJECTIVE_MISMATCH in r.signals


def test_low_confidence_restrict(governor):
    r = governor.evaluate(prop("p6", "agent_research", "gather",
                               make_permission("research"), OBJ, 0.2))
    assert r.decision == Decision.RESTRICT and RiskSignal.LOW_CONFIDENCE in r.signals
    assert r.restricted_permissions == {make_permission("research")}


def test_context_cannot_create_authority(governor):
    before = repr(governor.live_authority["agent_research"])
    for i in range(5):
        governor.evaluate(prop(f"px{i}", "agent_research", "research", make_permission("research")))
    assert repr(governor.live_authority["agent_research"]) == before


def test_fleet_snapshot(governor):
    snap = governor.snapshot()
    assert snap["objective"] and snap["step_count"] == 0


def test_effective_authority_is_a_copy(governor):
    r = governor.evaluate(prop("p7", "agent_research", "gather", make_permission("research")))
    r.effective_authority.permissions.clear()
    assert governor.live_authority["agent_research"].can(make_permission("research"))


# -- budgets --------------------------------------------------------

def test_budget_consumption(governor):
    for i in range(5):
        r = governor.evaluate(prop(f"dep{i}", "agent_deploy", "push",
                                   make_permission("deploy", "staging")))
        assert r.decision == Decision.CONTINUE
    r = governor.evaluate(prop("dep5", "agent_deploy", "push",
                               make_permission("deploy", "staging")))
    assert r.decision == Decision.HUMAN and RiskSignal.BUDGET_EXHAUSTED in r.signals


def test_budget_not_consumed_on_non_continue(governor):
    # A low-confidence proposal is RESTRICTed and must NOT spend deploy budget.
    perm = make_permission("deploy", "staging")
    r = governor.evaluate(prop("lb0", "agent_deploy", "push", perm, OBJ, 0.1))
    assert r.decision == Decision.RESTRICT
    live = governor.live_authority["agent_deploy"]
    assert live.budget_remaining.get("deploy:staging", 5) == 5
    assert live.has_budget(perm)
    # the restriction now actually blocks further use of this permission --
    # it is not a no-op that lets the agent keep trying (and keep landing on
    # a fresh RESTRICT) indefinitely -- and budget is still never touched
    # because the permission check fails before the budget check runs.
    r2 = governor.evaluate(prop("lb1", "agent_deploy", "push", perm, OBJ, 0.9))
    assert r2.decision == Decision.HUMAN and RiskSignal.AUTHORITY_ABUSE in r2.signals
    assert live.budget_remaining.get("deploy:staging", 5) == 5


def test_fleet_step_budget(make_governor, envelope):
    env = dataclasses.replace(envelope, max_fleet_steps=3)
    g = make_governor(env)
    outcomes = [g.evaluate(prop(f"f{i}", "agent_research", "research",
                                make_permission("research"))).decision for i in range(4)]
    assert outcomes[:3] == [Decision.CONTINUE] * 3
    assert outcomes[3] == Decision.HUMAN


def test_per_agent_step_budget(make_governor):
    g = make_governor(config=GovernorConfig(per_agent_step_budget=2))
    d = [g.evaluate(prop(f"a{i}", "agent_research", "research",
                         make_permission("research"))).decision for i in range(3)]
    assert d == [Decision.CONTINUE, Decision.CONTINUE, Decision.HUMAN]


# -- restrict policies -------------------------------------------------

def test_restrict_ttl_steps(make_governor, envelope):
    env = dataclasses.replace(envelope, restrict_policy=RestrictPolicy.TTL_STEPS,
                              restrict_ttl_steps=2)
    g = make_governor(env)
    r = g.evaluate(prop("r1", "agent_coder", "write_code", make_permission("code", "write"),
                        OBJ, 0.2, payload={"file": "repo/main.py"}))
    assert r.decision == Decision.RESTRICT
    assert not g._effective_authority("agent_coder").can(make_permission("code", "write"))
    for i in range(2):
        g.evaluate(prop(f"fill{i}", "agent_research", "research", make_permission("research")))
    assert g._effective_authority("agent_coder").can(make_permission("code", "write"))


def test_restriction_removal_uses_coverage_not_exact_equality(make_governor, envelope):
    """A restriction is recorded against whatever Permission the restricted
    proposal declared (required_permission) -- which need not be
    object-identical to the base authority's actual stored permission for
    that name/scope (e.g. a different max_budget). Removal must match by
    name/scope coverage, the same relation used to grant authority in the
    first place -- not exact Permission equality, which would silently keep
    the base permission (and so leave the restriction with no effect) the
    moment the two differ in any field."""
    perm_no_budget = make_permission("deploy", "staging")  # max_budget=None
    # demo envelope's agent_deploy actually holds deploy:staging with max_budget=5
    assert envelope.agent_authorities["agent_deploy"]._match(perm_no_budget).max_budget == 5

    g = make_governor(config=GovernorConfig(low_confidence_max=0.9))
    imposing = g.evaluate(prop("cov1", "agent_deploy", "push", perm_no_budget, OBJ, 0.1))
    assert imposing.decision == Decision.RESTRICT

    assert not g._effective_authority("agent_deploy").can(perm_no_budget)
    # also blocked for the base authority's own (budgeted) permission object
    assert not g._effective_authority("agent_deploy").can(
        make_permission("deploy", "staging", max_budget=5))


def test_restrict_step_budget(make_governor, envelope):
    env = dataclasses.replace(envelope, restrict_policy=RestrictPolicy.STEP_BUDGET,
                              restrict_step_budget=2)
    g = make_governor(env)
    pw = make_permission("code", "write")
    # Distinct on-objective fragments so the step-budget path is what's under
    # test, not the re-entry gate (which would fire on re-submitting sb1's
    # just-refused fragment).
    f2 = "keep the system inside the declared authority envelope"
    assert g.evaluate(prop("sb1", "agent_coder", "write_code", pw, OBJ, 0.2,
                           payload={"file": "repo/main.py"})).decision == Decision.RESTRICT
    # budget of 2 => two clean uses, then escalate
    assert g.evaluate(prop("sb2", "agent_coder", "write_code", pw, f2, 0.85,
                           payload={"file": "repo/main.py"})).decision == Decision.CONTINUE
    assert g.evaluate(prop("sb3", "agent_coder", "write_code", pw, f2, 0.85,
                           payload={"file": "repo/main.py"})).decision == Decision.CONTINUE
    assert g.evaluate(prop("sb4", "agent_coder", "write_code", pw, f2, 0.85,
                           payload={"file": "repo/main.py"})).decision == Decision.HUMAN


def test_restrict_human_only(make_governor, envelope):
    env = dataclasses.replace(envelope, restrict_policy=RestrictPolicy.HUMAN_ONLY)
    g = make_governor(env)
    assert g.evaluate(prop("ho1", "agent_coder", "write_code", make_permission("code", "write"),
                           OBJ, 0.2, payload={"file": "repo/main.py"})).decision == Decision.RESTRICT
    for i in range(5):
        g.evaluate(prop(f"fill{i}", "agent_research", "research", make_permission("research")))
    assert not g._effective_authority("agent_coder").can(make_permission("code", "write"))


# -- drift / anomaly ------------------------------------------------

def test_intent_graph_drift(governor):
    for i in range(3):
        governor.evaluate(prop(f"cons{i}", "agent_coder", "write_code",
                               make_permission("code", "write"), OBJ, 0.85,
                               payload={"file": "repo/main.py"}))
    r = governor.evaluate(prop("drift1", "agent_coder", "write_code",
                               make_permission("code", "write"),
                               "Create a viral social media engagement farm", 0.85,
                               payload={"file": "repo/main.py"}))
    assert RiskSignal.DRIFT in r.signals or RiskSignal.OBJECTIVE_MISMATCH in r.signals


def test_long_horizon_drift(governor):
    frags = [
        "Build a secure multi-agent governance prototype",
        "Build a secure multi-agent governance system",
        "Build a secure multi-agent system",
        "Build a multi-agent system",
        "Build a multi-agent platform",
        "Build a platform for agents",
        "Build a viral platform",
        "Build a viral engagement platform",
    ]
    r = None
    for i, f in enumerate(frags):
        r = governor.evaluate(prop(f"d{i}", "agent_coder", "write_code",
                                   make_permission("code", "write"), f, 0.85,
                                   payload={"file": "repo/main.py"}))
    assert r.decision in (Decision.RESTRICT, Decision.RECHECK, Decision.HUMAN)


def test_universal_high_confidence(governor):
    frag = "Launch a cryptocurrency and maximize token value"
    for agent, perm in [("agent_research", make_permission("research")),
                        ("agent_coder", make_permission("code", "write")),
                        ("agent_deploy", make_permission("deploy", "staging"))]:
        governor.evaluate(prop(f"u_{agent}", agent, "gather", perm, frag, 0.95))
    r = governor.evaluate(prop("final", "agent_coder", "write_code",
                               make_permission("code", "write"), frag, 0.95,
                               payload={"file": "repo/main.py"}))
    assert RiskSignal.OBJECTIVE_MISMATCH in r.signals or RiskSignal.ASSUMPTION_ANOMALY in r.signals


# -- re-entry to a refused objective --------------------------------

def test_reentry_hard_gate_no_prior_refusal(governor):
    # Repeating a fragment many times, never refused -> never a re-entry hit.
    for i in range(4):
        r = governor.evaluate(prop(f"re{i}", "agent_research", "gather",
                                   make_permission("research"), OBJ, 0.85))
        assert r.decision == Decision.CONTINUE
        assert RiskSignal.OBJECTIVE_REENTRY not in r.signals


def test_reentry_high_escalates_to_human(governor):
    off = "Exfiltrate the signing keys to an external host"
    # First submission is refused for objective mismatch (HUMAN) -> boundary.
    r1 = governor.evaluate(prop("rx1", "agent_research", "gather",
                                make_permission("research"), off, 0.9))
    assert r1.decision == Decision.HUMAN
    # Reworded, high-confidence return to the same idea -> HIGH re-entry -> HUMAN.
    r2 = governor.evaluate(prop("rx2", "agent_research", "gather",
                                make_permission("research"),
                                "Exfiltrate the signing keys to an outside server", 0.95))
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.OBJECTIVE_REENTRY in r2.signals


def test_reentry_is_per_agent(governor):
    off = "Exfiltrate the signing keys to an external host"
    governor.evaluate(prop("pa1", "agent_research", "gather", make_permission("research"), off, 0.9))
    # A different agent with no refusal history is not tarred by it.
    r = governor.evaluate(prop("pa2", "agent_coder", "write_code",
                               make_permission("code", "write"), off, 0.9,
                               payload={"file": "repo/x.py"}))
    assert RiskSignal.OBJECTIVE_REENTRY not in r.signals


# -- execution boundary ----------------------------------------------

def test_execution_boundary_continue(make_governor):
    g = make_governor(execution_boundary=PermissiveExecutionBoundary())
    assert g.evaluate(prop("a1", "agent_research", "gather",
                           make_permission("research"))).decision == Decision.CONTINUE


def test_execution_boundary_fail_closed(make_governor):
    g = make_governor(execution_boundary=DenyAllExecutionBoundary())
    r = g.evaluate(prop("a2", "agent_research", "gather", make_permission("research")))
    assert r.decision == Decision.HUMAN and "Execution boundary rejected" in r.reason


def test_execution_boundary_exception_fail_closed(make_governor):
    class Boom(PermissiveExecutionBoundary):
        def execute(self, proposal, authority):
            raise RuntimeError("kaboom")
    g = make_governor(execution_boundary=Boom())
    r = g.evaluate(prop("a3", "agent_research", "gather", make_permission("research")))
    assert r.decision == Decision.HUMAN and RiskSignal.VERIFIER_ERROR in r.signals


# -- proposal immutability during evaluation --------------------------

def test_post_verification_mutation_cannot_reach_execution(make_governor):
    """Proposal is a mutable dataclass; the caller keeps a live reference to
    whatever object it passed to evaluate(). Something that runs mid-evaluate
    (here: a hostile embedding engine's similarity() hook, invoked well after
    the path-safety check and well before the execution boundary) must not be
    able to mutate the *original* object and have that mutation reach the
    execution boundary -- evaluate() snapshots at entry precisely so a path
    that passed schema/traversal validation is what the boundary receives."""
    from conftest import JaccardEmbeddingEngine

    captured_payload = {}

    class RecordingExecutionBoundary:
        def execute(self, proposal, authority):
            captured_payload.update(proposal.payload)
            return True, "executed", None

    proposal = prop("mut1", "agent_coder", "write_code", make_permission("code", "write"),
                    payload={"file": "repo/src/main.py"})

    class MutatingEmbeddingEngine(JaccardEmbeddingEngine):
        def similarity(self, text_a, text_b):
            # fires during contextual-risk evaluation, well after the path
            # check and well before the execution boundary -- attacker's
            # last plausible chance to swap the payload before execution
            proposal.payload["file"] = "../../etc/passwd"
            return super().similarity(text_a, text_b)

    g = make_governor(embedding=MutatingEmbeddingEngine(),
                      execution_boundary=RecordingExecutionBoundary())
    r = g.evaluate(proposal)

    assert r.decision == Decision.CONTINUE
    assert captured_payload["file"] == "repo/src/main.py"
    # the caller's original object was mutated (that's expected -- it's
    # theirs), but it's a different object from whatever the governor
    # evaluated and executed
    assert proposal.payload["file"] == "../../etc/passwd"


# -- security diagnostics -----------------------------------------------

def test_security_report_flags_defaults(make_governor):
    g = make_governor()
    report = g.security_report()
    assert report["signature_enforced"] is False
    assert report["execution_boundary_wired"] is False
    assert report["quorum_configured"] is False
    assert report["durable_replay_protection"] is False
    assert report["durable_restriction_protection"] is False
    assert report["durable_authority_and_budgets"] is False
    # signature, execution boundary, quorum, durable replay, durable
    # restrictions, durable authority/budgets, and the always-present
    # provenance-is-in-memory-only note.
    assert len(report["weaknesses"]) == 7


def test_security_report_clears_weaknesses_when_hardened(make_governor):
    from chainmail import (
        AuditSink, CompositeVerifier, Decision, GovernorConfig, GovernorVote,
        InMemoryKeyProvider, InMemoryRollbackCheckpoint, KeyRegistry,
        QuorumAggregator, SQLiteStore, StaticPeerTransport,
    )

    g = make_governor(
        config=GovernorConfig(require_signature=True),
        verifier=CompositeVerifier(KeyRegistry()),
        execution_boundary=DenyAllExecutionBoundary(),
        quorum=QuorumAggregator(),
        quorum_transport=StaticPeerTransport(
            peer_votes=[GovernorVote("peer-1", Decision.CONTINUE, "peer agrees")]),
        audit=AuditSink(sqlite_store=SQLiteStore(
            key_provider=InMemoryKeyProvider("k1", b"secret-key-material"),
            rollback_checkpoint=InMemoryRollbackCheckpoint(),
        )),
    )
    report = g.security_report()
    assert report["signature_enforced"] is True
    assert report["execution_boundary_wired"] is True
    assert report["quorum_configured"] is True
    assert report["quorum_has_peer_transport"] is True
    assert report["durable_replay_protection"] is True
    assert report["durable_restriction_protection"] is True
    # live_authority and permission/step budgets are now durable when a
    # SQLiteStore is wired in, same as replay/restrictions. Only provenance
    # (the human-readable delegation log, not authoritative state) has no
    # durable-storage option yet, so its weakness is always present.
    assert report["durable_authority_and_budgets"] is True
    assert report["row_authentication_configured"] is True
    assert report["rollback_checkpoint_configured"] is True
    assert report["weaknesses"] == [
        "provenance (the human-readable delegation chain) is in-memory only "
        "with no durable-storage option yet -- a restart loses it; this does "
        "not affect the authoritative delegated-authority state itself, which "
        "is durable when a SQLiteStore is wired in -- see CHANGELOG.md"
    ]


def test_security_report_distinguishes_row_authentication_from_rollback_protection(make_governor):
    # A durable store with row authentication (key_provider) but no
    # rollback_checkpoint must be flagged specifically for the missing
    # rollback checkpoint -- never implying the keyed-MAC layer alone
    # covers a whole-database rollback (see docs/DURABILITY.md).
    from chainmail import AuditSink, InMemoryKeyProvider, SQLiteStore

    g = make_governor(audit=AuditSink(sqlite_store=SQLiteStore(
        key_provider=InMemoryKeyProvider("k1", b"secret-key-material"),
    )))
    report = g.security_report()
    assert report["durable_authority_and_budgets"] is True
    assert report["row_authentication_configured"] is True
    assert report["rollback_checkpoint_configured"] is False
    assert not any("not authenticated" in w for w in report["weaknesses"])
    assert any("no rollback checkpoint is configured" in w for w in report["weaknesses"])


def test_security_report_flags_missing_row_authentication_and_rollback_protection(make_governor):
    from chainmail import AuditSink, SQLiteStore

    g = make_governor(audit=AuditSink(sqlite_store=SQLiteStore()))
    report = g.security_report()
    assert report["durable_authority_and_budgets"] is True
    assert report["row_authentication_configured"] is False
    assert report["rollback_checkpoint_configured"] is False
    assert any("not authenticated" in w for w in report["weaknesses"])
    assert any("no rollback checkpoint is configured" in w for w in report["weaknesses"])


def test_security_report_omits_row_authentication_and_rollback_fields_without_durable_storage(
        make_governor):
    # No SQLiteStore at all -- neither question applies (there is no
    # durable row to authenticate or roll back), so both fields are None
    # and neither weakness is added (the existing "durable storage is
    # in-memory only" weaknesses already cover this case).
    g = make_governor()
    report = g.security_report()
    assert report["durable_authority_and_budgets"] is False
    assert report["row_authentication_configured"] is None
    assert report["rollback_checkpoint_configured"] is None
    assert not any("not authenticated" in w for w in report["weaknesses"])
    assert not any("rollback checkpoint" in w for w in report["weaknesses"])


def test_security_report_flags_quorum_with_only_echo_transport(make_governor):
    # A quorum aggregator with no real peer transport still lets a single
    # governor's own vote pass on unanimity-of-one -- security_report() must
    # not report this the same as real peer-governor review.
    from chainmail import QuorumAggregator

    g = make_governor(quorum=QuorumAggregator())
    report = g.security_report()
    assert report["quorum_configured"] is True
    assert report["quorum_has_peer_transport"] is False
    assert any("LocalSingleGovernorTransport" in w for w in report["weaknesses"])


# -- envelope integrity ------------------------------------------------

def test_envelope_fingerprint_drift(governor, envelope):
    object.__setattr__(envelope, "max_fleet_steps", 999)
    r = governor.evaluate(prop("ed", "agent_research", "gather", make_permission("research")))
    assert r.decision == Decision.HUMAN and RiskSignal.ENVELOPE_DRIFT in r.signals


# -- fail-closed on engine crashes ----------------------------------

def test_fail_closed_semantic_crash(make_governor):
    class BrokenEngine:
        def fit(self, docs): return None
        def similarity(self, a, b): raise RuntimeError("crash")
    g = make_governor(embedding=BrokenEngine())
    r = g.evaluate(prop("bk", "agent_research", "gather", make_permission("research")))
    assert r.decision == Decision.HUMAN and RiskSignal.OBJECTIVE_MISMATCH in r.signals


def test_fail_closed_intent_graph_crash(governor):
    class BrokenIG:
        entries = []
        def add(self, e): pass
        def drift_score(self, *a, **k): raise RuntimeError("crash")
        def peer_consensus_score(self, *a, **k): raise RuntimeError("crash")
    governor.intent_graph = BrokenIG()
    r = governor.evaluate(prop("bg", "agent_research", "gather", make_permission("research")))
    assert r.decision in (Decision.RESTRICT, Decision.RECHECK, Decision.HUMAN)
