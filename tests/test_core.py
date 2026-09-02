"""Proposal structural validation (payload size/shape bounds) and Authority
permission matching (deterministic selection among overlapping permissions)."""

import pytest

from chainmail import (
    Authority, Decision, GovernorConfig, Permission, Proposal, RiskSignal, TfidfEmbeddingEngine,
    make_permission,
)

OBJ = "Build a secure multi-agent governance prototype"


def _kwargs(payload):
    return dict(
        agent_id="agent_research", action="gather", required_permission=make_permission("research"),
        objective_fragment=OBJ, confidence=0.85, payload=payload,
    )


def test_payload_within_limits_accepted():
    Proposal("p-ok", **_kwargs({"file": "repo/a.py", "n": 3, "tags": ["a", "b"]}))


def test_deeply_nested_payload_rejected():
    deep = {}
    cursor = deep
    for _ in range(50):
        cursor["n"] = {}
        cursor = cursor["n"]
    with pytest.raises(ValueError, match="payload exceeds size/shape limits"):
        Proposal("p-deep", **_kwargs(deep))


def test_wide_flat_payload_rejected():
    huge = {str(i): i for i in range(50_000)}
    with pytest.raises(ValueError, match="payload exceeds size/shape limits"):
        Proposal("p-wide", **_kwargs(huge))


def test_huge_string_value_rejected():
    with pytest.raises(ValueError, match="payload exceeds size/shape limits"):
        Proposal("p-str", **_kwargs({"x": "a" * 200_000}))


def test_many_medium_siblings_rejected_by_total_node_budget():
    # Not deep (depth 2) and no single field is huge, but the total node
    # count across many siblings must still be bounded.
    wide_list = list(range(20_000))
    with pytest.raises(ValueError, match="payload exceeds size/shape limits"):
        Proposal("p-siblings", **_kwargs({"items": wide_list}))


def test_long_payload_key_rejected():
    with pytest.raises(ValueError, match="payload exceeds size/shape limits"):
        Proposal("p-key", **_kwargs({"x" * 300: 1}))


def test_governor_re_validates_a_hostile_payload_reaching_evaluate_without_construction(make_governor):
    # structural_problems() is re-checked by the governor (not just at
    # Proposal() construction) precisely so a proposal built via
    # Proposal.__new__ or deserialized without the constructor can't skip
    # this bound. Build one bypassing __post_init__ to prove the governor
    # itself still catches it -- and, critically, catches it *before*
    # anything would serialise/walk the payload (signature verification's
    # canonical_signing_bytes, schema validation's nested-payload check).
    deep = {}
    cursor = deep
    for _ in range(50):
        cursor["n"] = {}
        cursor = cursor["n"]
    p = Proposal.__new__(Proposal)
    p.proposal_id = "p-bypass"
    p.agent_id = "agent_research"
    p.action = "gather"
    p.required_permission = make_permission("research")
    p.objective_fragment = OBJ
    p.confidence = 0.85
    p.assumptions = []
    p.parent_proposal_id = None
    p.signature = None
    p.nonce = None
    p.payload = deep

    g = make_governor(config=GovernorConfig(), embedding=TfidfEmbeddingEngine())
    result = g.evaluate(p)
    assert result.decision == Decision.HUMAN
    assert RiskSignal.INVALID_PROPOSAL in result.signals


# -- Authority._match(): deterministic selection among overlapping permissions --

def test_match_is_deterministic_regardless_of_set_insertion_order():
    wildcard = Permission("deploy", "*", max_budget=None)
    specific = Permission("deploy", "prod", max_budget=2)
    required = Permission("deploy", "prod")

    for members in ([wildcard, specific], [specific, wildcard]):
        matched = Authority(permissions=set(members))._match(required)
        assert matched == specific


def test_match_prefers_the_more_restrictive_bounded_permission_over_unbounded():
    # Two overlapping permissions can both legitimately cover the same
    # requirement (e.g. acquired via separate delegations). Whichever one
    # governs a budget check must not depend on Set iteration order --
    # the bounded one is deterministically preferred (fail-closed).
    unbounded = Permission("deploy", "prod", max_budget=None)
    bounded = Permission("deploy", "prod", max_budget=5)
    a = Authority(permissions={unbounded, bounded})
    matched = a._match(Permission("deploy", "prod"))
    assert matched == bounded


def test_match_picks_the_smaller_budget_among_two_bounded_matches():
    tight = Permission("deploy", "prod", max_budget=1)
    loose = Permission("deploy", "prod", max_budget=100)
    for members in ({tight, loose}, {loose, tight}):
        matched = Authority(permissions=members)._match(Permission("deploy", "prod"))
        assert matched == tight


def test_has_budget_and_consume_budget_use_the_deterministic_match():
    tight = Permission("deploy", "prod", max_budget=1)
    loose_wildcard = Permission("deploy", "*", max_budget=None)
    a = Authority(permissions={tight, loose_wildcard})
    required = Permission("deploy", "prod")
    assert a.has_budget(required) is True
    assert a.consume_budget(required) is True
    assert a.budget_remaining[tight.key()] == 0
    assert a.has_budget(required) is False   # the tight match is now exhausted,
    assert a.consume_budget(required) is False  # not silently falling back to the wildcard
