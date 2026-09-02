"""The adversarial mutation harness must kill every standard mutant against a
correctly-configured governor, and must report survivors when the boundary is
deliberately weakened."""

import pytest

from chainmail import (
    ALGO_HMAC, ChainmailGovernor, CompositeVerifier, Decision, GovernorConfig, KeyRegistry,
    Proposal, RiskSignal, TfidfEmbeddingEngine, make_permission, sign_proposal,
)
from chainmail.evaluation import Mutation, MutationRunner, standard_mutant_family
from chainmail.execution_boundary import ExecutionBoundary, PermissiveExecutionBoundary


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


def test_hard_denial_mutation_skipped_when_unreachable_via_allowlist():
    # An allowlist that excludes every hard-denied action would let the
    # hard_denial mutant survive as UNKNOWN_ACTION instead of AUTHORITY_ABUSE
    # -- exercising the wrong invariant and reporting misleading coverage.
    # The family must not include a mutation it cannot genuinely exercise.
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
    assert "hard_denial" not in [m.name for m in fam]


def test_harness_never_lets_execution_reach_a_real_boundary(envelope):
    # Even when the caller's factory wires a real (non-denying) execution
    # boundary, the harness must forcibly replace it -- a mutant that
    # survives every check up to CONTINUE must never actually execute.
    class _ExplodingBoundary(ExecutionBoundary):
        def execute(self, proposal, authority):
            raise AssertionError("the mutation harness executed a real action")

    def make():
        gov = ChainmailGovernor(envelope, config=GovernorConfig(),
                                 embedding=TfidfEmbeddingEngine(), auto_embedding=False)
        gov.execution_boundary = _ExplodingBoundary()
        return gov

    p = Proposal("seed", "agent_coder", "write_code", make_permission("code", "write"),
                 "Implement the delegation guard for the governance prototype", 0.85,
                 payload={"file": "repo/src/guard.py"})
    report = MutationRunner(make).run(p, standard_mutant_family(p, envelope))
    assert report.passed, report.to_dict()


def test_signal_specificity_catches_a_family_that_targets_the_wrong_signal():
    # A mutation whose expected_signals names a signal the governor never
    # actually raises for it must be reported as a survivor, even though the
    # decision itself lands in `accepted` -- that is exactly the false
    # invariant-coverage this field exists to close.
    import dataclasses
    from chainmail import build_demo_envelope
    envelope = dataclasses.replace(build_demo_envelope(), allowed_actions={"write_code"})
    p = Proposal("seed", "agent_coder", "write_code", make_permission("code", "write"),
                 "Implement the delegation guard for the governance prototype", 0.85,
                 payload={"file": "repo/src/guard.py"})
    bogus = Mutation(
        "bogus_signal", "payload_schema_enforced",
        lambda proposal: Proposal(
            "mut-bogus", proposal.agent_id, "totally_unregistered_action_xyz",
            proposal.required_permission, proposal.objective_fragment, proposal.confidence,
            payload=dict(proposal.payload)),
        expected_signals={RiskSignal.SCHEMA_VIOLATION},
    )
    report = MutationRunner(_factory(envelope)).run(p, [bogus])
    assert not report.passed
    assert report.survivors[0].name == "bogus_signal"
    assert report.survivors[0].decision == "HUMAN"
    assert "UNKNOWN_ACTION" in report.survivors[0].signals


def test_resign_is_threaded_through_mutants_and_primers(envelope):
    # Under require_signature=True, every mutated/primer proposal must be
    # re-signed by the harness's resign callback, or every mutant would be
    # killed by SIGNATURE_MISSING rather than the invariant it targets.
    reg = KeyRegistry()
    secret = b"shared-secret-value"
    reg.add_key("k-hmac", "agent_coder", ALGO_HMAC, secret)

    def resign(proposal):
        # Preserve a nonce a mutation deliberately set (e.g. replayed_nonce)
        # instead of minting a fresh one on every re-sign.
        return sign_proposal(proposal, "k-hmac", algorithm=ALGO_HMAC, hmac_secret=secret,
                              nonce=proposal.nonce)

    def make():
        return ChainmailGovernor(
            envelope,
            config=GovernorConfig(require_signature=True),
            embedding=TfidfEmbeddingEngine(), auto_embedding=False,
            verifier=CompositeVerifier(reg),
        )

    signed_seed = resign(Proposal(
        "seed", "agent_coder", "write_code", make_permission("code", "write"),
        "Implement the delegation guard for the governance prototype", 0.85,
        payload={"file": "repo/src/guard.py"}))
    report = MutationRunner(make, resign=resign).run(
        signed_seed, standard_mutant_family(signed_seed, envelope))
    assert report.passed, report.to_dict()
    assert not any("SIGNATURE_MISSING" in o.signals for o in report.outcomes)
