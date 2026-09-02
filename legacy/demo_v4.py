"""
Chainmail v4 --- Interactive Demo

Demonstrates all v4 capabilities:
- SQLite persistence with WAL
- RESTRICT policy options
- Quorum voting
- ActionSchema validation
- Envelope fingerprint drift
- Staged persistence
- Budget consumption
- IntentGraph drift
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from chainmail_v4 import (
    ChainmailV4, Authority, Proposal, Decision, RiskSignal,
    StructuredAssumption, PersistenceLog, MockArmourBoundary,
    HMACApprovalVerifier, SQLitePersistence, RestrictPolicy,
    QuorumAggregator, GovernorVote,
    make_permission, build_demo_envelope_v4,
)


def show(result, label=""):
    sigs = [s.value for s in result.signals] or ["NONE"]
    print(f"  [{result.decision.value:8}] {label}")
    print(f"   reason : {result.reason}")
    print(f"   signals: {sigs}")
    if result.effective_authority:
        print(f"   auth   : {result.effective_authority}")
    if result.quorum_votes:
        print(f"   quorum : {result.quorum_votes}")
    print()


def main():
    print("=" * 70)
    print("CHAINMAIL v4 DEMO")
    print("Thesis: The links don't bend. The chain does.")
    print("=" * 70)
    print()

    env = build_demo_envelope_v4()
    log = PersistenceLog()
    sqlite = SQLitePersistence(":memory:")
    armour = MockArmourBoundary()
    approval_key = b"demo-approval-key"
    verifier = HMACApprovalVerifier({"demo-key": approval_key})
    quorum = QuorumAggregator(threshold=0.5, require_human_on_disagreement=True)
    cm = ChainmailV4(env, armour=armour, persistence=log, sqlite_persistence=sqlite,
                     approval_verifier=verifier, quorum=quorum)

    print("Human-predeclared objective:")
    print(f"  {env.objective}")
    print()
    print("Hard envelope authorities:")
    for aid, auth in env.agent_authorities.items():
        print(f"  {aid:18} -> {auth}")
    print()
    print("RESTRICT policy:", env.restrict_policy.value)
    print()

    # --- Step 1: Good trajectory ---
    print("--- Step 1: Research agent (good trajectory) ---")
    p1 = Proposal("p1", "agent_research", "gather_requirements",
                  make_permission("research"), "secure multi-agent governance prototype", 0.88)
    cm.sign_proposal(p1, "demo-key", approval_key)
    show(cm.evaluate(p1), "research")

    # --- Step 2: Coder with schema-compliant payload ---
    print("--- Step 2: Coder with compliant payload ---")
    p2 = Proposal("p2", "agent_coder", "write_code",
                  make_permission("code", "write"),
                  "Build a secure multi-agent governance prototype", 0.82,
                  payload={"file": "/repo/governor.py", "mode": "w"})
    cm.sign_proposal(p2, "demo-key", approval_key)
    show(cm.evaluate(p2), "coder")

    # --- Step 3: Schema violation ---
    print("--- Step 3: Deploy with unknown payload key ---")
    p3 = Proposal("p3", "agent_deploy", "deploy_service",
                  make_permission("deploy", "staging"),
                  "Build a secure multi-agent governance prototype", 0.85,
                  payload={"target": "/app", "version": "1.0", "malicious": "true"})
    cm.sign_proposal(p3, "demo-key", approval_key)
    show(cm.evaluate(p3), "schema-violation")

    # --- Step 4: Objective drift ---
    print("--- Step 4: Coder drifts off objective ---")
    p4 = Proposal("p4", "agent_coder", "write_code",
                  make_permission("code", "write"),
                  "build a viral social media clone to farm engagement", 0.91,
                  payload={"file": "/repo/main.py"})
    cm.sign_proposal(p4, "demo-key", approval_key)
    show(cm.evaluate(p4), "drift")

    # --- Step 5: Low confidence ---
    print("--- Step 5: Deployer with low confidence ---")
    p5 = Proposal("p5", "agent_deploy", "deploy_service",
                  make_permission("deploy", "staging"),
                  "Build a secure multi-agent governance prototype", 0.18,
                  payload={"target": "/app"})
    cm.sign_proposal(p5, "demo-key", approval_key)
    show(cm.evaluate(p5), "low-confidence")

    # --- Step 6: Budget consumption ---
    print("--- Step 6: Deployer consumes staging budget ---")
    for i in range(3):
        p = Proposal(f"budget{i}", "agent_deploy", "deploy_service",
                     make_permission("deploy", "staging"),
                     "Build a secure multi-agent governance prototype", 0.85,
                     payload={"target": "/app"})
        cm.sign_proposal(p, "demo-key", approval_key)
        r = cm.evaluate(p)
        print(f"  deploy {i+1}: {r.decision.value} | auth: {cm.live_authority['agent_deploy']}")
    print()

    # --- Step 7: Replay attack ---
    print("--- Step 7: Replay attack ---")
    p_old = Proposal("replay", "agent_research", "gather_requirements",
                     make_permission("research"),
                     "Build a secure multi-agent governance prototype", 0.88)
    cm.sign_proposal(p_old, "demo-key", approval_key)
    print(f"  First use:  {cm.evaluate(p_old).decision.value}")
    print(f"  Replay:     {cm.evaluate(p_old).decision.value} ({[s.value for s in cm.evaluate(p_old).signals]})")
    print()

    # --- Step 8: Envelope drift ---
    print("--- Step 8: Envelope drift detection ---")
    object.__setattr__(env, "max_fleet_steps", 999)
    p_drift = Proposal("env_drift", "agent_research", "gather_requirements",
                       make_permission("research"),
                       "Build a secure multi-agent governance prototype", 0.88)
    cm.sign_proposal(p_drift, "demo-key", approval_key)
    show(cm.evaluate(p_drift), "envelope-drift")
    object.__setattr__(env, "max_fleet_steps", 50)

    # --- Step 9: SQLite history ---
    print("--- Step 9: SQLite proposal history ---")
    history = sqlite.get_proposal_history()
    print(f"  Total records: {len(history)}")
    phases = [h["phase"] for h in history]
    print(f"  Phases: {phases[:6]}...")
    print()

    # --- Step 10: Envelope suggestion ---
    print("--- Step 10: Envelope suggestion from history ---")
    suggestions = cm.suggest_envelope()
    print(f"  Most common actions: {suggestions['most_common_actions']}")
    print(f"  Decision distribution: {suggestions['decision_distribution']}")
    print(f"  Recommendations: {suggestions['recommendations']}")
    print()

    # --- Step 11: Fleet snapshot ---
    print("--- Fleet snapshot ---")
    snap = cm.snapshot()
    for k, v in snap.items():
        print(f"  {k}: {v}")
    print()

    # --- Step 12: Persistence integrity ---
    print("--- Persistence log integrity ---")
    ok = log.verify()
    print(f"  Chain valid: {ok.valid}")
    print(f"  Entries: {len(log.entries)}")
    print()

    print("=" * 70)
    print("Demo complete. THE AGENTS MAY BE FLUID. THE AUTHORITY IS NOT.")
    print("=" * 70)


if __name__ == "__main__":
    main()
