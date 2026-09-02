"""One test per numbered v4 -> v5 bug fix. See README.md and CHANGELOG.md."""

import dataclasses
import math

import pytest

from chainmail import (
    ALGO_HMAC, Authority, CompositeVerifier, Decision, GovernorConfig, HashChainLog,
    KeyRegistry, Permission, Proposal, RiskSignal, make_permission, sign_proposal,
)

OBJ = "Build a secure multi-agent governance prototype"


def _p(pid, **kw):
    kw.setdefault("agent_id", "agent_research")
    kw.setdefault("action", "gather")
    kw.setdefault("required_permission", make_permission("research"))
    kw.setdefault("objective_fragment", OBJ)
    kw.setdefault("confidence", 0.85)
    return Proposal(pid, kw.pop("agent_id"), kw.pop("action"), kw.pop("required_permission"),
                    kw.pop("objective_fragment"), kw.pop("confidence"), **kw)


# 1: HashChainLog.verify() was destructive.
def test_bug1_verify_non_destructive():
    log = HashChainLog()
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    log.append("t", {"n": 3})          # v4 raised ReceiptIntegrityError here
    assert log.verify().valid


# 2: signature must bind the whole proposal, not just the action string.
def test_bug2_signature_binds_permission(make_governor):
    reg = KeyRegistry()
    secret = b"k" * 16
    reg.add_key("kid", "agent_coder", ALGO_HMAC, secret)
    g = make_governor(verifier=CompositeVerifier(reg))
    honest = Proposal("b2a", "agent_coder", "write_code", make_permission("code", "write"),
                      OBJ, 0.85, payload={"file": "repo/x.py"})
    sign_proposal(honest, "kid", algorithm=ALGO_HMAC, hmac_secret=secret)
    forged = Proposal("b2b", "agent_coder", "write_code", make_permission("deploy", "staging"),
                      OBJ, 0.85, payload={"file": "repo/x.py"},
                      signature=honest.signature, nonce=honest.nonce)
    assert g.evaluate(forged).decision == Decision.HUMAN


# 3: nonce is consumed only after the signature is trusted.
def test_bug3_bad_signature_does_not_burn_nonce(make_governor):
    reg = KeyRegistry()
    secret = b"k" * 16
    reg.add_key("kid", "agent_research", ALGO_HMAC, secret)
    g = make_governor(verifier=CompositeVerifier(reg))
    # First: a forgery reusing a nonce we intend to use legitimately.
    bad = _p("b3a", signature="kid:deadbeef", nonce="shared-nonce")
    assert g.evaluate(bad).decision == Decision.HUMAN
    # The honest proposal with the same nonce must still be accepted.
    good = _p("b3b", nonce="shared-nonce")
    sign_proposal(good, "kid", algorithm=ALGO_HMAC, hmac_secret=secret, nonce="shared-nonce")
    assert g.evaluate(good).decision == Decision.CONTINUE


# 4: budget is consumed only when the final decision is CONTINUE.
def test_bug4_budget_survives_restrict(make_governor):
    g = make_governor()
    perm = make_permission("deploy", "staging")
    for i in range(10):
        r = g.evaluate(_p(f"b4-{i}", agent_id="agent_deploy", action="push",
                          required_permission=perm, confidence=0.05))
        assert r.decision == Decision.RESTRICT
    # ten RESTRICTs, zero spend: the full budget of 5 is still on the books.
    live = g.live_authority["agent_deploy"]
    assert live.budget_remaining.get("deploy:staging", 5) == 5
    assert live.has_budget(perm)


# 5: any HUMAN vote dominates even when disagreement is tolerated.
def test_bug5_quorum_human_dominates():
    from chainmail import GovernorVote, QuorumAggregator
    q = QuorumAggregator(threshold=0.5, require_human_on_disagreement=False)
    d, _, _ = q.aggregate([
        GovernorVote("g1", Decision.CONTINUE, "r", weight=5.0),
        GovernorVote("g2", Decision.HUMAN, "r", weight=1.0),
    ])
    assert d == Decision.HUMAN


# 6: delegation to an agent not in the envelope is rejected.
def test_bug6_delegation_unknown_agent(governor):
    ok, _ = governor.register_delegation(
        "agent_research", "not_a_real_agent", "x",
        Authority(permissions={make_permission("research")}))
    assert not ok
    assert "not_a_real_agent" not in governor.live_authority


# 7: NaN / out-of-range confidence is rejected as a malformed proposal.
def test_bug7_nan_confidence_rejected(governor):
    p = Proposal.__new__(Proposal)          # bypass __post_init__
    p.proposal_id = "b7"; p.agent_id = "agent_research"; p.action = "gather"
    p.required_permission = make_permission("research"); p.objective_fragment = OBJ
    p.confidence = float("nan"); p.assumptions = []; p.parent_proposal_id = None
    p.signature = None; p.nonce = None; p.payload = {}
    r = governor.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.INVALID_PROPOSAL in r.signals
    with pytest.raises(ValueError):
        Proposal("b7c", "a", "act", make_permission("x"), "frag", 1.5)


# 8: the result's effective_authority is a copy, not live state.
def test_bug8_result_authority_is_copy(governor):
    r = governor.evaluate(_p("b8"))
    r.effective_authority.permissions.clear()
    r.effective_authority.budget_remaining["research:*"] = -999
    assert governor.live_authority["agent_research"].can(make_permission("research"))


# 9: filesystem path fields are validated for traversal.
@pytest.mark.parametrize("bad_path", [
    "../../etc/passwd",
    "repo/../../secret",
    "repo/main.py\x00.txt",
    "C:\\Windows\\system32",
    "repo\\win\\path",
])
def test_bug9_path_traversal_blocked(governor, bad_path):
    r = governor.evaluate(_p("b9", agent_id="agent_coder", action="write_code",
                             required_permission=make_permission("code", "write"),
                             payload={"file": bad_path}))
    assert r.decision == Decision.HUMAN
    assert RiskSignal.PATH_TRAVERSAL in r.signals


def test_bug9_clean_relative_path_allowed(governor):
    r = governor.evaluate(_p("b9ok", agent_id="agent_coder", action="write_code",
                             required_permission=make_permission("code", "write"),
                             payload={"file": "repo/src/main.py"}))
    assert r.decision == Decision.CONTINUE


# 10: evaluate() is guarded by a lock -- concurrent callers stay consistent.
def test_bug10_thread_safety(make_governor):
    import threading
    env = dataclasses.replace(make_governor().envelope, max_fleet_steps=10_000)
    g = make_governor(env, config=GovernorConfig(dedupe_proposal_ids=True))
    errors = []

    def worker(base):
        try:
            for i in range(50):
                g.evaluate(_p(f"t{base}-{i}"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(b,)) for b in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert g.step_count == 8 * 50


# extra: proposal-id dedupe.
def test_proposal_id_dedupe(governor):
    p = _p("dup-1")
    assert governor.evaluate(p).decision == Decision.CONTINUE
    p2 = _p("dup-1")
    r = governor.evaluate(p2)
    assert r.decision == Decision.HUMAN and RiskSignal.PROPOSAL_DUPLICATE in r.signals


# extra: nonce replay with dedupe disabled.
def test_nonce_replay(make_governor):
    g = make_governor(config=GovernorConfig(dedupe_proposal_ids=False))
    a = _p("rp-a", nonce="reused-nonce")
    b = _p("rp-b", nonce="reused-nonce")
    assert g.evaluate(a).decision == Decision.CONTINUE
    r = g.evaluate(b)
    assert r.decision == Decision.HUMAN and RiskSignal.REPLAY_DETECTED in r.signals
