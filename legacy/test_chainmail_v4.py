
"""
Chainmail v4 --- Comprehensive Test Suite

Covers all v1/v2/v3 invariants plus v4 upgrades:
- SQLite persistence with WAL
- RESTRICT policy options (TTL, step-budget, HUMAN-only)
- Quorum / multi-governor voting
- Ed25519 protocol (with HMAC fallback)
- Envelope suggestion from historical runs
- All Armour-hardened patterns from v3
"""

import sys
import os
import logging
from dataclasses import replace

sys.path.insert(0, os.path.dirname(__file__))

from chainmail_v4 import (
    ChainmailV4, Authority, Permission, Proposal, Decision, RiskSignal,
    StructuredAssumption, PersistenceLog, ReceiptIntegrityError, ReceiptVerification,
    MockArmourBoundary, DenyAllArmourBoundary, TfidfEmbeddingEngine,
    HMACApprovalVerifier, NullApprovalVerifier, Ed25519ApprovalVerifier,
    ActionSchema, AuthorityEnvelope, RestrictPolicy,
    QuorumAggregator, GovernorVote, SQLitePersistence,
    make_permission, build_demo_envelope_v4, _sanitize, _contains_nested,
)

logging.disable(logging.CRITICAL)


# ---------------------------------------------------------------------------
# v1 + v2 + v3 Regression Tests
# ---------------------------------------------------------------------------

def test_authority_subset():
    print("=== test_authority_subset ===")
    broad = Authority(permissions={make_permission("read"), make_permission("write"), make_permission("deploy")})
    narrow = Authority(permissions={make_permission("read"), make_permission("write")})
    assert narrow.is_subset_of(broad)
    assert not broad.is_subset_of(narrow)
    print(" PASS")


def test_delegation_cannot_expand():
    print("=== test_delegation_cannot_expand ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    offered = Authority(permissions={make_permission("deploy", "staging"), make_permission("code", "write")})
    ok, msg = cm.register_delegation("agent_research", "agent_coder", "hand off", offered)
    assert not ok and "does not hold" in msg
    print(f" PASS: {msg}")


def test_delegation_preserve_or_reduce():
    print("=== test_delegation_preserve_or_reduce ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    offered = Authority(permissions={make_permission("research"), make_permission("read", "docs")})
    ok, msg = cm.register_delegation("agent_research", "agent_coder", "share", offered)
    assert ok
    assert not cm.live_authority["agent_coder"].can(make_permission("research"))
    print(f" PASS: {msg}")


def test_hard_denial():
    print("=== test_hard_denial ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("p1", "agent_deploy", "delete_production", make_permission("deploy", "staging"), "clean up", 0.95)
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.AUTHORITY_ABUSE in r.signals
    print(" PASS")


def test_missing_permission():
    print("=== test_missing_permission ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("p2", "agent_research", "gather_requirements", make_permission("deploy", "staging"), "push prototype", 0.7)
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.AUTHORITY_ABUSE in r.signals
    print(" PASS")


def test_happy_path_continue():
    print("=== test_happy_path_continue ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("p3", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    r = cm.evaluate(p)
    assert r.decision == Decision.CONTINUE
    print(" PASS")


def test_objective_mismatch():
    print("=== test_objective_mismatch ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("p4", "agent_coder", "gather_requirements", make_permission("research"), "Launch a cryptocurrency token and maximize hype", 0.9)
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.OBJECTIVE_MISMATCH in r.signals
    print(" PASS")


def test_low_confidence_restrict():
    print("=== test_low_confidence_restrict ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("p5", "agent_coder", "gather_requirements", make_permission("research"), "implement governance prototype", 0.2)
    r = cm.evaluate(p)
    assert r.decision == Decision.RESTRICT and RiskSignal.LOW_CONFIDENCE in r.signals
    print(" PASS")


def test_provenance_recorded():
    print("=== test_provenance_recorded ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    offered = Authority(permissions={make_permission("research")})
    ok, _ = cm.register_delegation("agent_research", "agent_coder", "handoff", offered)
    assert ok and len(cm.provenance) == 1
    assert cm.provenance[0].from_id == "agent_research"
    print(" PASS")


def test_context_cannot_create_authority():
    print("=== test_context_cannot_create_authority ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    before = repr(cm.live_authority["agent_research"])
    for i in range(5):
        p = Proposal(f"px{i}", "agent_research", "research", make_permission("research"), "secure multi-agent governance", 0.5)
        cm.evaluate(p)
    assert repr(cm.live_authority["agent_research"]) == before
    print(" PASS")


def test_fleet_snapshot():
    print("=== test_fleet_snapshot ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    snap = cm.snapshot()
    assert "objective" in snap and snap["step_count"] == 0
    print(" PASS")


def test_role_enforced_delegation():
    print("=== test_role_enforced_delegation ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    offered = Authority(permissions={make_permission("read", "docs")})
    ok, msg = cm.register_delegation("agent_research", "agent_approver", "bad", offered)
    assert not ok and "Role violation" in msg
    print(f" PASS: {msg}")


def test_budget_consumption():
    print("=== test_budget_consumption ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    for i in range(5):
        p = Proposal(f"dep{i}", "agent_deploy", "push_staging", make_permission("deploy", "staging"), "Build a secure multi-agent governance prototype", 0.8)
        r = cm.evaluate(p)
        assert r.decision == Decision.CONTINUE
    p6 = Proposal("dep5", "agent_deploy", "push_staging", make_permission("deploy", "staging"), "Build a secure multi-agent governance prototype", 0.8)
    r = cm.evaluate(p6)
    assert r.decision == Decision.HUMAN and RiskSignal.BUDGET_EXHAUSTED in r.signals
    print(" PASS")


def test_semantic_continuity():
    print("=== test_semantic_continuity ===")
    tfidf = TfidfEmbeddingEngine()
    text_a = "Implement secure multi-agent governance with cryptographic provenance chains"
    text_b = "Design safe distributed agent oversight using cryptographic provenance chains"
    corpus = [text_a, text_b, "Cooking recipes for beginners", "Gardening tips for summer"]
    tfidf.fit(corpus)
    assert tfidf.similarity(text_a, text_b) > 0.2
    print(" PASS")


def test_intent_graph_drift():
    print("=== test_intent_graph_drift ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    for i in range(3):
        p = Proposal(f"cons{i}", "agent_coder", "write_code", make_permission("code", "write"), "Build a secure multi-agent governance prototype", 0.85, payload={"file": "/repo/main.py"})
        cm.evaluate(p)
    p_drift = Proposal("drift1", "agent_coder", "write_code", make_permission("code", "write"), "Create a viral social media engagement farm", 0.85, payload={"file": "/repo/main.py"})
    r = cm.evaluate(p_drift)
    assert RiskSignal.DRIFT in r.signals or RiskSignal.OBJECTIVE_MISMATCH in r.signals
    print(" PASS")


def test_restrict_ttl():
    print("=== test_restrict_ttl ===")
    env = build_demo_envelope_v4()
    env.restrict_policy = RestrictPolicy.TTL_STEPS
    env.restrict_ttl_steps = 2
    cm = ChainmailV4(env)
    p = Proposal("r1", "agent_coder", "write_code", make_permission("code", "write"), "Build a secure multi-agent governance prototype", 0.2, payload={"file": "/repo/main.py"})
    r = cm.evaluate(p)
    assert r.decision == Decision.RESTRICT
    assert not cm._effective_authority("agent_coder").can(make_permission("code", "write"))
    for i in range(2):
        px = Proposal(f"fill{i}", "agent_research", "research", make_permission("research"), "governance research", 0.8)
        cm.evaluate(px)
    assert cm._effective_authority("agent_coder").can(make_permission("code", "write"))
    print(" PASS")


def test_signed_proposal():
    print("=== test_signed_proposal ===")
    env = build_demo_envelope_v4()
    key = b"test-secret"
    verifier = HMACApprovalVerifier({"test-key": key})
    cm = ChainmailV4(env, approval_verifier=verifier)
    p = Proposal("sig1", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    cm.sign_proposal(p, "test-key", key)
    assert cm.evaluate(p).decision == Decision.CONTINUE
    p2 = Proposal("sig2", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85, signature="key-1:fake_sig", nonce="nonce123")
    assert cm.evaluate(p2).decision == Decision.HUMAN
    print(" PASS")


def test_replay_attack():
    print("=== test_replay_attack ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("rep1", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85, nonce="nonce_abc_123")
    assert cm.evaluate(p).decision == Decision.CONTINUE
    r2 = cm.evaluate(p)
    assert r2.decision == Decision.HUMAN
    assert RiskSignal.REPLAY_DETECTED in r2.signals
    print(" PASS")


def test_persistence_hash_chain():
    print("=== test_persistence_hash_chain ===")
    log = PersistenceLog()
    log.append("test", {"msg": "first"})
    log.append("test", {"msg": "second"})
    result = log.verify()
    assert result.valid
    assert result.failed_record is None
    log.entries[1]["data"]["msg"] = "tampered"
    result2 = log.verify()
    assert not result2.valid
    assert result2.failed_record == 1
    print(" PASS")


def test_armour_continue():
    print("=== test_armour_continue ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, armour=MockArmourBoundary())
    p = Proposal("arm1", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    assert cm.evaluate(p).decision == Decision.CONTINUE
    print(" PASS")


def test_armour_fail_closed():
    print("=== test_armour_fail_closed ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, armour=DenyAllArmourBoundary())
    p = Proposal("arm2", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and "Armour boundary rejected" in r.reason
    print(" PASS")


def test_authority_laundering():
    print("=== test_authority_laundering ===")
    env = AuthorityEnvelope(
        objective="Test laundering",
        agent_authorities={
            "agent_A": Authority(permissions={make_permission("shared"), make_permission("exclusive_A")}),
            "agent_B": Authority(permissions={make_permission("shared"), make_permission("exclusive_B")}),
            "agent_C": Authority(permissions={make_permission("exclusive_C")}),
        },
        allowed_delegations={"role_A": {"role_B"}, "role_B": {"role_C"}, "role_C": set()},
        agent_roles={"agent_A": "role_A", "agent_B": "role_B", "agent_C": "role_C"},
        hard_denials=set(), max_fleet_steps=50,
    )
    cm = ChainmailV4(env)
    ok1, _ = cm.register_delegation("agent_A", "agent_B", "share", Authority(permissions={make_permission("shared")}))
    assert ok1
    ok2, msg2 = cm.register_delegation("agent_B", "agent_C", "launder", Authority(permissions={make_permission("shared")}))
    assert ok2
    assert not cm.live_authority["agent_C"].can(make_permission("shared"))
    print(f" PASS: {msg2}")


def test_long_horizon_drift():
    print("=== test_long_horizon_drift ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    fragments = [
        "Build a secure multi-agent governance prototype",
        "Build a secure multi-agent governance system",
        "Build a secure multi-agent system",
        "Build a multi-agent system",
        "Build a multi-agent platform",
        "Build a platform for agents",
        "Build a platform",
        "Build a viral platform",
        "Build a viral engagement platform",
    ]
    for i, frag in enumerate(fragments):
        p = Proposal(f"drift{i}", "agent_coder", "write_code", make_permission("code", "write"), frag, 0.85, payload={"file": "/repo/main.py"})
        r = cm.evaluate(p)
    assert r.decision in (Decision.RESTRICT, Decision.RECHECK, Decision.HUMAN)
    print(" PASS")


def test_universal_high_confidence():
    print("=== test_universal_high_confidence ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    for agent_id in ["agent_research", "agent_coder", "agent_deploy"]:
        perm = make_permission("research") if agent_id == "agent_research" else make_permission("code", "write") if agent_id == "agent_coder" else make_permission("deploy", "staging")
        p = Proposal(f"u_{agent_id}", agent_id, "gather_requirements", perm, "Launch a cryptocurrency and maximize token value", 0.95)
        cm.evaluate(p)
    p_final = Proposal("final", "agent_coder", "write_code", make_permission("code", "write"), "Launch a cryptocurrency and maximize token value", 0.95, payload={"file": "/repo/main.py"})
    r = cm.evaluate(p_final)
    assert RiskSignal.OBJECTIVE_MISMATCH in r.signals or RiskSignal.ASSUMPTION_ANOMALY in r.signals
    print(" PASS")


# ---------------------------------------------------------------------------
# v3 Armour-Hardened Tests
# ---------------------------------------------------------------------------

def test_envelope_fingerprint_drift():
    print("=== test_envelope_fingerprint_drift ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    object.__setattr__(env, "max_fleet_steps", 999)
    p = Proposal("env_drift", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN
    assert RiskSignal.ENVELOPE_DRIFT in r.signals
    print(" PASS")


def test_schema_unknown_keys():
    print("=== test_schema_unknown_keys ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("sch1", "agent_deploy", "deploy_service", make_permission("deploy", "staging"), "Build a secure multi-agent governance prototype", 0.85, payload={"target": "/app", "version": "1.0", "malicious_key": "bad"})
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SCHEMA_VIOLATION in r.signals
    print(" PASS")


def test_schema_missing_required():
    print("=== test_schema_missing_required ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("sch2", "agent_deploy", "deploy_service", make_permission("deploy", "staging"), "Build a secure multi-agent governance prototype", 0.85, payload={"version": "1.0"})
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SCHEMA_VIOLATION in r.signals
    print(" PASS")


def test_schema_nested_payload():
    print("=== test_schema_nested_payload ===")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    p = Proposal("sch3", "agent_deploy", "deploy_service", make_permission("deploy", "staging"), "Build a secure multi-agent governance prototype", 0.85, payload={"target": "/app", "version": {"nested": "value"}})
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SCHEMA_VIOLATION in r.signals
    print(" PASS")


def test_sanitize_bounded():
    print("=== test_sanitize_bounded ===")
    assert len(_sanitize("x" * 10000)) == 4096
    deep = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": 1}}}}}}}}}
    assert "<max-depth>" in str(_sanitize(deep))
    cyclic = []; cyclic.append(cyclic)
    assert _sanitize(cyclic) == ["<cycle>"]
    assert len(_sanitize(list(range(200)))) == 100
    print(" PASS")


def test_staged_persistence():
    print("=== test_staged_persistence ===")
    log = PersistenceLog()
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, persistence=log)
    p = Proposal("stage1", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    cm.evaluate(p)
    phases = [e["phase"] for e in log.entries if e["type"] == "proposal"]
    assert phases == ["started", "completed"]
    print(" PASS")


def test_corrupt_receipt_refuses_append():
    print("=== test_corrupt_receipt_refuses_append ===")
    log = PersistenceLog()
    log.entries.append({"not_a_valid_record": True, "hash": "fake", "prev_hash": "0" * 64})
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, persistence=log)
    p = Proposal("corrupt", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SANITIZATION_FAILURE in r.signals
    print(" PASS")


def test_approval_verifier_tampered():
    print("=== test_approval_verifier_tampered ===")
    key = b"secret-key"
    verifier = HMACApprovalVerifier({"key-1": key})
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, approval_verifier=verifier)
    p = Proposal("tamper", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    cm.sign_proposal(p, "key-1", key)
    assert cm.evaluate(p).decision == Decision.CONTINUE
    p_tampered = Proposal("tamper2", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85, signature="key-1:fake_sig", nonce="fresh_nonce_123")
    r = cm.evaluate(p_tampered)
    assert r.decision == Decision.HUMAN and RiskSignal.SIGNATURE_INVALID in r.signals
    print(" PASS")


def test_fail_closed_semantic_crash():
    print("=== test_fail_closed_semantic_crash ===")
    class BrokenEngine(TfidfEmbeddingEngine):
        def similarity(self, text_a, text_b):
            raise RuntimeError("intentional crash")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, embedding_engine=BrokenEngine())
    p = Proposal("broken", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.OBJECTIVE_MISMATCH in r.signals
    print(" PASS")


def test_fail_closed_intent_graph_crash():
    print("=== test_fail_closed_intent_graph_crash ===")
    class BrokenIntentGraph:
        def add(self, entry): pass
        def drift_score(self, *args, **kwargs): raise RuntimeError("crash")
        def peer_consensus_score(self, *args, **kwargs): raise RuntimeError("crash")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env)
    original = cm.intent_graph
    cm.intent_graph = BrokenIntentGraph()
    p = Proposal("broken_ig", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    r = cm.evaluate(p)
    assert r.decision in (Decision.RESTRICT, Decision.HUMAN, Decision.RECHECK)
    cm.intent_graph = original
    print(" PASS")


def test_envelope_mutable_collections_frozen():
    print("=== test_envelope_mutable_collections_frozen ===")
    actions = {"read"}
    methods = {"GET"}
    env = AuthorityEnvelope(
        objective="Test", agent_authorities={"agent_A": Authority(permissions={make_permission("read")})},
        allowed_delegations={"role_A": actions}, agent_roles={"agent_A": "role_A"}, hard_denials=methods,
    )
    fp = env.fingerprint()
    actions.add("invented")
    methods.add("POST")
    assert env.allowed_delegations["role_A"] == frozenset({"read"})
    assert env.hard_denials == frozenset({"GET"})
    assert env.fingerprint() == fp
    print(" PASS")


def test_receipt_sanitization_staged():
    print("=== test_receipt_sanitization_staged ===")
    log = PersistenceLog()
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, persistence=log)
    p = Proposal("sanitize", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    cm.evaluate(p)
    assert log.verify().valid
    completed = [e for e in log.entries if e["type"] == "proposal" and e["phase"] == "completed"][0]
    assert "execution_id" in completed
    print(" PASS")


# ---------------------------------------------------------------------------
# v4 Upgrade Tests
# ---------------------------------------------------------------------------

def test_sqlite_persistence():
    print("=== test_sqlite_persistence ===")
    sqlite = SQLitePersistence(":memory:")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, sqlite_persistence=sqlite)
    p = Proposal("sql1", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
    cm.evaluate(p)
    history = sqlite.get_proposal_history()
    assert len(history) == 2  # started + completed
    assert history[0]["phase"] == "started"
    assert history[1]["phase"] == "completed"
    print(" PASS")


def test_restrict_step_budget():
    print("=== test_restrict_step_budget ===")
    env = build_demo_envelope_v4()
    env.restrict_policy = RestrictPolicy.STEP_BUDGET
    env.restrict_step_budget = 2
    cm = ChainmailV4(env)
    # First restriction
    p1 = Proposal("sb1", "agent_coder", "write_code", make_permission("code", "write"), "Build a secure multi-agent governance prototype", 0.2, payload={"file": "/repo/main.py"})
    r1 = cm.evaluate(p1)
    assert r1.decision == Decision.RESTRICT
    # Two more uses should exhaust step budget
    p2 = Proposal("sb2", "agent_coder", "write_code", make_permission("code", "write"), "Build a secure multi-agent governance prototype", 0.85, payload={"file": "/repo/main.py"})
    r2 = cm.evaluate(p2)
    assert r2.decision == Decision.CONTINUE  # first use after restrict
    p3 = Proposal("sb3", "agent_coder", "write_code", make_permission("code", "write"), "Build a secure multi-agent governance prototype", 0.85, payload={"file": "/repo/main.py"})
    r3 = cm.evaluate(p3)
    assert r3.decision == Decision.CONTINUE  # second use
    p4 = Proposal("sb4", "agent_coder", "write_code", make_permission("code", "write"), "Build a secure multi-agent governance prototype", 0.85, payload={"file": "/repo/main.py"})
    r4 = cm.evaluate(p4)
    assert r4.decision == Decision.HUMAN  # budget exhausted
    print(" PASS")


def test_restrict_human_only():
    print("=== test_restrict_human_only ===")
    env = build_demo_envelope_v4()
    env.restrict_policy = RestrictPolicy.HUMAN_ONLY
    cm = ChainmailV4(env)
    p1 = Proposal("ho1", "agent_coder", "write_code", make_permission("code", "write"), "Build a secure multi-agent governance prototype", 0.2, payload={"file": "/repo/main.py"})
    r1 = cm.evaluate(p1)
    assert r1.decision == Decision.RESTRICT
    # Even after many steps, restriction should persist
    for i in range(5):
        px = Proposal(f"fill{i}", "agent_research", "research", make_permission("research"), "governance research", 0.8)
        cm.evaluate(px)
    assert not cm._effective_authority("agent_coder").can(make_permission("code", "write"))
    print(" PASS")


def test_quorum_unanimous():
    print("=== test_quorum_unanimous ===")
    quorum = QuorumAggregator(threshold=0.5, require_human_on_disagreement=True)
    votes = [
        GovernorVote("g1", Decision.CONTINUE, "ok"),
        GovernorVote("g2", Decision.CONTINUE, "ok"),
        GovernorVote("g3", Decision.CONTINUE, "ok"),
    ]
    decision, reason, signals = quorum.aggregate(votes)
    assert decision == Decision.CONTINUE
    print(" PASS")


def test_quorum_disagreement_escalates():
    print("=== test_quorum_disagreement_escalates ===")
    quorum = QuorumAggregator(threshold=0.5, require_human_on_disagreement=True)
    votes = [
        GovernorVote("g1", Decision.CONTINUE, "ok", weight=2.0),
        GovernorVote("g2", Decision.HUMAN, "suspicious", weight=1.0),
    ]
    decision, reason, signals = quorum.aggregate(votes)
    assert decision == Decision.HUMAN
    assert "disagreement" in reason.lower()
    print(" PASS")


def test_quorum_no_threshold():
    print("=== test_quorum_no_threshold ===")
    quorum = QuorumAggregator(threshold=0.8)
    votes = [
        GovernorVote("g1", Decision.CONTINUE, "ok", weight=1.0),
        GovernorVote("g2", Decision.RESTRICT, "caution", weight=1.0),
    ]
    decision, reason, signals = quorum.aggregate(votes)
    assert decision == Decision.HUMAN
    assert RiskSignal.QUORUM_REJECTED in signals
    print(" PASS")


def test_ed25519_verifier_without_crypto():
    print("=== test_ed25519_verifier_without_crypto ===")
    # Ed25519ApprovalVerifier should reject all proposals when cryptography is not installed
    verifier = Ed25519ApprovalVerifier({"key-1": b"dummy"})
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, approval_verifier=verifier)
    p = Proposal("ed1", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85, signature="key-1:fake", nonce="nonce1")
    r = cm.evaluate(p)
    assert r.decision == Decision.HUMAN
    assert RiskSignal.SIGNATURE_INVALID in r.signals
    print(" PASS")


def test_envelope_suggestion():
    print("=== test_envelope_suggestion ===")
    sqlite = SQLitePersistence(":memory:")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, sqlite_persistence=sqlite)
    # Generate some history
    for i in range(10):
        p = Proposal(f"hist{i}", "agent_research", "gather_requirements", make_permission("research"), "Build a secure multi-agent governance prototype", 0.85)
        cm.evaluate(p)
    suggestions = cm.suggest_envelope()
    assert "most_common_actions" in suggestions
    assert "decision_distribution" in suggestions
    print(" PASS")


def test_sqlite_delegation_logging():
    print("=== test_sqlite_delegation_logging ===")
    sqlite = SQLitePersistence(":memory:")
    env = build_demo_envelope_v4()
    cm = ChainmailV4(env, sqlite_persistence=sqlite)
    offered = Authority(permissions={make_permission("read", "docs")})
    cm.register_delegation("agent_research", "agent_coder", "share docs", offered)
    conn = sqlite._conn()
    cursor = conn.execute("SELECT * FROM delegations")
    rows = cursor.fetchall()
    assert len(rows) == 1
    assert rows[0][1] == "agent_research"
    assert rows[0][2] == "agent_coder"
    print(" PASS")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_TESTS = [
    # v1/v2/v3 regression
    test_authority_subset, test_delegation_cannot_expand, test_delegation_preserve_or_reduce,
    test_hard_denial, test_missing_permission, test_happy_path_continue, test_objective_mismatch,
    test_low_confidence_restrict, test_provenance_recorded, test_context_cannot_create_authority,
    test_fleet_snapshot, test_role_enforced_delegation, test_budget_consumption,
    test_semantic_continuity, test_intent_graph_drift, test_restrict_ttl, test_signed_proposal,
    test_replay_attack, test_persistence_hash_chain, test_armour_continue, test_armour_fail_closed,
    test_authority_laundering, test_long_horizon_drift, test_universal_high_confidence,
    # v3 Armour-hardened
    test_envelope_fingerprint_drift, test_schema_unknown_keys, test_schema_missing_required,
    test_schema_nested_payload, test_sanitize_bounded, test_staged_persistence,
    test_corrupt_receipt_refuses_append, test_approval_verifier_tampered,
    test_fail_closed_semantic_crash, test_fail_closed_intent_graph_crash,
    test_envelope_mutable_collections_frozen, test_receipt_sanitization_staged,
    # v4 upgrades
    test_sqlite_persistence, test_restrict_step_budget, test_restrict_human_only,
    test_quorum_unanimous, test_quorum_disagreement_escalates, test_quorum_no_threshold,
    test_ed25519_verifier_without_crypto, test_envelope_suggestion, test_sqlite_delegation_logging,
]


def run_all():
    print("\n" + "=" * 70)
    print("CHAINMAIL v4 --- TEST RUN")
    print("=" * 70 + "\n")
    failed = 0
    for t in ALL_TESTS:
        try:
            t()
            print()
        except AssertionError as e:
            print(f" FAIL: {e}\n")
            failed += 1
        except Exception as e:
            print(f" ERROR: {e}\n")
            failed += 1
    print("=" * 70)
    if failed == 0:
        print(f"ALL {len(ALL_TESTS)} TESTS PASSED")
        print("The links don't bend. The chain does.")
    else:
        print(f"{failed} TEST(S) FAILED")
        sys.exit(1)
    print("=" * 70)


if __name__ == "__main__":
    run_all()
