"""The adversarial mutation harness must kill every standard mutant against a
correctly-configured governor, and must report survivors when the boundary is
deliberately weakened."""

import pytest

from chainmail import (
    ALGO_HMAC, AuditSink, Authority, ChainmailGovernor, CompositeVerifier, Decision,
    GovernorConfig, KeyRegistry, Proposal, RiskSignal, SQLiteStore, TfidfEmbeddingEngine,
    make_permission, sign_proposal,
)
from chainmail.evaluation import (
    AUTHORITY_LAUNDERING_INVARIANTS, Mutation, MutationRunner, authority_laundering_mutant_family,
    standard_mutant_family,
)
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


# -- authority-laundering mutant family (durable live authority/budgets) ----

def _laundering_factory(envelope):
    def make():
        return ChainmailGovernor(
            envelope, config=GovernorConfig(), embedding=TfidfEmbeddingEngine(),
            auto_embedding=False, audit=AuditSink(sqlite_store=SQLiteStore(":memory:")),
        )
    return make


def test_authority_laundering_family_all_killed_against_a_correct_governor():
    envelope, seed, family = authority_laundering_mutant_family()
    assert {m.name for m in family} == {
        "delegate_more_than_durable_remaining",
        "stale_authority_after_revocation",
        "forged_unlimited_required_permission",
        "multi_hop_delegation_launder",
        "concurrent_double_spend_last_unit",
    }
    report = MutationRunner(
        _laundering_factory(envelope), required_invariants=AUTHORITY_LAUNDERING_INVARIANTS,
    ).run(seed, family)
    assert report.passed, report.to_dict()
    assert report.score == 1.0
    assert not report.unexercised_invariants


def test_authority_laundering_family_requires_durable_storage():
    """Every mutation in this family sets up its attack by directly
    consuming durable budget (see evaluation._consume) -- run against a
    governor factory with no SQLiteStore wired in, priming raises
    (gov.audit.sqlite is None), which MutationRunner swallows per its
    documented "priming failure is not the mutation's verdict" contract.
    The family's own docstring says a durable factory is required; this
    proves it's not silently a no-op instead of an error the caller would
    notice -- least one mutation must NOT be killed when durability isn't
    wired in, since none of the intended attack setup actually happened."""
    envelope, seed, family = authority_laundering_mutant_family()

    def non_durable_factory():
        return ChainmailGovernor(envelope, config=GovernorConfig(),
                                 embedding=TfidfEmbeddingEngine(), auto_embedding=False)

    report = MutationRunner(non_durable_factory).run(seed, family)
    assert not report.passed


def test_authority_laundering_family_never_executes_a_real_action():
    """Same deny-and-record guarantee standard_mutant_family already has --
    MutationRunner.run() forcibly replaces the execution boundary
    regardless of what the factory wires in, so even a factory carrying a
    real (exploding) boundary must never reach it for real."""
    envelope, seed, family = authority_laundering_mutant_family()

    class _ExplodingBoundary(ExecutionBoundary):
        def execute(self, proposal, authority):
            raise AssertionError("the mutation harness executed a real action")

    def make():
        return ChainmailGovernor(
            envelope, config=GovernorConfig(), embedding=TfidfEmbeddingEngine(),
            auto_embedding=False, audit=AuditSink(sqlite_store=SQLiteStore(":memory:")),
            execution_boundary=_ExplodingBoundary(),
        )

    report = MutationRunner(make, required_invariants=AUTHORITY_LAUNDERING_INVARIANTS).run(
        seed, family)
    assert report.passed, report.to_dict()


def test_authority_laundering_family_detects_a_broken_is_subset_of_check():
    """Discriminating-power check: with Authority.is_subset_of forced to
    always report True (simulating a real regression -- a delegator could
    offer authority it doesn't durably hold), exactly the two mutations
    that specifically attack that check must survive, and no others --
    proving each mutation exercises what it claims to, not a vacuous pass
    that would 'kill' anything regardless of whether the governor is
    actually correct."""
    envelope, seed, family = authority_laundering_mutant_family()
    orig = Authority.is_subset_of
    Authority.is_subset_of = lambda self, other: True
    try:
        report = MutationRunner(_laundering_factory(envelope)).run(seed, family)
    finally:
        Authority.is_subset_of = orig
    assert not report.passed
    assert set(o.name for o in report.survivors) == {
        "delegate_more_than_durable_remaining", "multi_hop_delegation_launder",
    }
    # And every mutation NOT about is_subset_of is still correctly killed.
    survivor_names = {o.name for o in report.survivors}
    for outcome in report.outcomes:
        if outcome.name not in survivor_names:
            assert outcome.killed, outcome
