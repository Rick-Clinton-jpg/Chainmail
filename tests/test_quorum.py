"""Quorum aggregation -- fail-closed rules."""

import pytest

from chainmail import (
    Decision, GovernorVote, QuorumAggregator, RiskSignal, StaticPeerTransport, make_permission,
    Proposal,
)

OBJ = "Build a secure multi-agent governance prototype"


def V(gid, decision, w=1.0):
    return GovernorVote(gid, decision, "r", weight=w)


def test_no_votes_is_human():
    d, _, sigs = QuorumAggregator().aggregate([])
    assert d == Decision.HUMAN and RiskSignal.QUORUM_REJECTED in sigs


def test_unanimous_continue():
    d, _, _ = QuorumAggregator().aggregate([V("g1", Decision.CONTINUE)] * 3)
    assert d == Decision.CONTINUE


def test_any_human_vote_dominates_regardless_of_weight():
    q = QuorumAggregator(threshold=0.5, require_human_on_disagreement=False)
    d, _, _ = q.aggregate([V("g1", Decision.CONTINUE, w=9.0), V("g2", Decision.HUMAN, w=0.1)])
    assert d == Decision.HUMAN


def test_disagreement_escalates_when_configured():
    q = QuorumAggregator(threshold=0.5, require_human_on_disagreement=True)
    d, reason, _ = q.aggregate([V("g1", Decision.CONTINUE, w=2.0), V("g2", Decision.RESTRICT)])
    assert d == Decision.HUMAN and "disagreement" in reason.lower()


def test_no_threshold_met_is_human():
    q = QuorumAggregator(threshold=0.8)
    d, _, sigs = q.aggregate([V("g1", Decision.CONTINUE), V("g2", Decision.RESTRICT)])
    assert d == Decision.HUMAN and RiskSignal.QUORUM_REJECTED in sigs


def test_restrict_can_win_a_quorum():
    q = QuorumAggregator(threshold=0.5, require_human_on_disagreement=False)
    d, _, _ = q.aggregate([V("g1", Decision.RESTRICT, w=3.0), V("g2", Decision.CONTINUE, w=1.0)])
    assert d == Decision.RESTRICT


# -- integration with the governor -----------------------------------

def test_governor_single_self_vote_passes(make_governor):
    g = make_governor(quorum=QuorumAggregator())
    p = Proposal("q1", "agent_research", "gather", make_permission("research"), OBJ, 0.85)
    r = g.evaluate(p)
    assert r.decision == Decision.CONTINUE
    assert r.quorum_votes == {"governor-0": "CONTINUE"}


def test_governor_hostile_peer_forces_human(make_governor):
    transport = StaticPeerTransport([GovernorVote("peer-1", Decision.HUMAN, "suspicious")])
    g = make_governor(quorum=QuorumAggregator(), quorum_transport=transport)
    p = Proposal("q2", "agent_research", "gather", make_permission("research"), OBJ, 0.85)
    r = g.evaluate(p)
    assert r.decision == Decision.HUMAN
