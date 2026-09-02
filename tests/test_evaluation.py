"""The adversarial mutation harness must kill every standard mutant against a
correctly-configured governor, and must report survivors when the boundary is
deliberately weakened."""

import pytest

from chainmail import (
    ChainmailGovernor, GovernorConfig, Proposal, TfidfEmbeddingEngine, make_permission,
)
from chainmail.evaluation import MutationRunner, standard_mutant_family


def _factory(envelope):
    def make():
        return ChainmailGovernor(envelope, config=GovernorConfig(),
                                 embedding=TfidfEmbeddingEngine(), auto_embedding=False)
    return make


def _good_proposal():
    return Proposal("seed", "agent_coder", "write_code", make_permission("code", "write"),
                    "Implement the delegation guard for the governance prototype", 0.85,
                    payload={"file": "repo/src/guard.py"})


def test_standard_family_all_killed(envelope):
    p = _good_proposal()
    report = MutationRunner(_factory(envelope)).run(p, standard_mutant_family(p, envelope))
    assert report.passed, report.to_dict()
    assert report.score == 1.0
    assert not report.unexercised_invariants


def test_harness_detects_a_weakened_boundary(envelope):
    p = _good_proposal()
    # A governor that does not dedupe proposal ids should let the duplicate
    # mutant survive -> the report must fail.
    def make():
        return ChainmailGovernor(envelope, config=GovernorConfig(dedupe_proposal_ids=False),
                                 embedding=TfidfEmbeddingEngine(), auto_embedding=False)
    report = MutationRunner(make).run(p, standard_mutant_family(p, envelope))
    assert not report.passed
    assert "duplicate_proposal_id" in [s.name for s in report.survivors]


def test_family_includes_unknown_action_when_allowlist_present():
    import dataclasses
    from chainmail import build_demo_envelope
    base = build_demo_envelope()
    env = dataclasses.replace(base, allowed_actions={
        "write_code", "deploy_service", "gather_requirements", "research", "push_staging",
    })
    p = Proposal("seed", "agent_coder", "write_code", make_permission("code", "write"),
                 "Implement the delegation guard for the governance prototype", 0.85,
                 payload={"file": "repo/src/guard.py"})
    fam = standard_mutant_family(p, env)
    assert "unknown_action" in [m.name for m in fam]
    report = MutationRunner(_factory(env)).run(p, fam)
    assert report.passed, report.to_dict()
    assert "unknown_or_unpermitted_action_denied" in report.exercised_invariants
