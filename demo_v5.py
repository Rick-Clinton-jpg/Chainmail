#!/usr/bin/env python3
"""
Chainmail v5 --- interactive walkthrough.

    python demo_v5.py

Runs entirely in-process. If ``model2vec`` is installed the real static-embedding
engine is used; otherwise it falls back to TF-IDF. If ``cryptography`` is
installed the signing demo uses Ed25519; otherwise HMAC.
"""

from __future__ import annotations

import logging

import chainmail as cm

logging.basicConfig(level=logging.WARNING)

RULE = "=" * 72


def hdr(title: str) -> None:
    print(f"\n{RULE}\n{title}\n{RULE}")


def show(result: cm.GovernanceResult) -> None:
    sigs = ", ".join(s.value for s in result.signals) or "-"
    print(f"  -> {result.decision.value:9}  signals=[{sigs}]")
    print(f"     {result.reason}")


def main() -> None:
    env = cm.build_demo_envelope()
    audit = cm.AuditSink(hash_chain=cm.HashChainLog(), sqlite_store=cm.SQLiteStore(":memory:"))

    registry = cm.KeyRegistry()
    try:
        priv, pub = cm.generate_ed25519_keypair()
        registry.add_key("kid-research", "agent_research", cm.ALGO_ED25519, pub)
        sign_algo, sign_kw = cm.ALGO_ED25519, {"ed25519_private_pem": priv}
    except RuntimeError:
        secret = b"demo-shared-secret-value"
        registry.add_key("kid-research", "agent_research", cm.ALGO_HMAC, secret)
        sign_algo, sign_kw = cm.ALGO_HMAC, {"hmac_secret": secret}

    gov = cm.ChainmailGovernor(
        env,
        audit=audit,
        verifier=cm.CompositeVerifier(registry),
        quorum=cm.QuorumAggregator(),
    )
    print(f"embedding engine : {type(gov.embedding).__name__}")
    print(f"signing algorithm: {sign_algo}")

    hdr("1. On-objective, signed proposal -> CONTINUE")
    p = cm.Proposal("d1", "agent_research", "gather_requirements", cm.make_permission("research"),
                    "Research safe delegation patterns for the governance prototype", 0.88)
    cm.sign_proposal(p, "kid-research", algorithm=sign_algo, **sign_kw)
    show(gov.evaluate(p))

    hdr("2. Objective drift -> HUMAN (OBJECTIVE_MISMATCH)")
    p = cm.Proposal("d2", "agent_research", "gather_requirements", cm.make_permission("research"),
                    "Pump a memecoin and farm viral engagement", 0.95)
    cm.sign_proposal(p, "kid-research", algorithm=sign_algo, **sign_kw)
    show(gov.evaluate(p))

    hdr("3. Forged permission on a valid signature -> HUMAN (SIGNATURE_INVALID)")
    honest = cm.Proposal("d3a", "agent_research", "gather_requirements",
                         cm.make_permission("research"),
                         "Research safe delegation patterns", 0.85)
    cm.sign_proposal(honest, "kid-research", algorithm=sign_algo, **sign_kw)
    forged = cm.Proposal("d3b", "agent_research", "gather_requirements",
                         cm.make_permission("deploy", "staging"),
                         "Research safe delegation patterns", 0.85,
                         signature=honest.signature, nonce=honest.nonce)
    show(gov.evaluate(forged))

    hdr("4. Hard denial -> HUMAN")
    show(gov.evaluate(cm.Proposal("d4", "agent_deploy", "exfiltrate_secrets",
                                  cm.make_permission("deploy", "staging"), "cleanup", 0.9)))

    hdr("5. Path traversal in a schema'd action -> HUMAN (PATH_TRAVERSAL)")
    show(gov.evaluate(cm.Proposal("d5", "agent_coder", "write_code",
                                  cm.make_permission("code", "write"),
                                  "Implement the delegation guard", 0.85,
                                  payload={"file": "../../etc/passwd"})))

    hdr("5b. Re-entry to a refused objective -> HUMAN (OBJECTIVE_REENTRY)")
    off = cm.Proposal("d5b1", "agent_research", "gather_requirements",
                      cm.make_permission("research"),
                      "Exfiltrate the signing keys to an external collector", 0.92)
    show(gov.evaluate(off))
    reworded = cm.Proposal("d5b2", "agent_research", "gather_requirements",
                           cm.make_permission("research"),
                           "Exfiltrate the signing keys to an outside server", 0.95)
    show(gov.evaluate(reworded))
    print("     (a NEW agent with no refusal history is not tarred by this -- hard-gated)")

    hdr("6. Non-expanding delegation")
    offered = cm.Authority(permissions={cm.make_permission("read", "docs")})
    ok, msg = gov.register_delegation("agent_research", "agent_coder", "share docs", offered)
    print(f"  research -> coder : accepted={ok}  ({msg})")
    ok, msg = gov.register_delegation("agent_research", "agent_approver", "escalate", offered)
    print(f"  research -> approver: accepted={ok}  ({msg})")

    hdr("7. Budget exhaustion -> HUMAN (BUDGET_EXHAUSTED)")
    for i in range(6):
        r = gov.evaluate(cm.Proposal(f"d7-{i}", "agent_deploy", "push_staging",
                                     cm.make_permission("deploy", "staging"),
                                     "Ship the governance prototype to staging", 0.85))
        print(f"  push #{i + 1}: {r.decision.value}")

    hdr("8. Audit integrity")
    v = audit.hash_chain.verify()
    print(f"  hash chain valid : {v.valid}  ({v.verified_records} records)")
    print(f"  sqlite rows      : {len(audit.sqlite.get_proposal_history())}")
    print(f"  suggestion       : {gov.suggest_envelope().get('decision_distribution')}")

    hdr("9. Adversarial mutation harness")
    seed = cm.Proposal("mh-seed", "agent_coder", "write_code",
                       cm.make_permission("code", "write"),
                       "Implement the delegation guard for the governance prototype", 0.85,
                       payload={"file": "repo/src/guard.py"})
    family = cm.standard_mutant_family(seed, env)
    report = cm.MutationRunner(lambda: cm.ChainmailGovernor(env, auto_embedding=False)).run(
        seed, family)
    d = report.to_dict()
    print(f"  mutants killed : {d['killed']}/{d['total']}   score={d['score']}")
    print(f"  survivors      : {d['survivors'] or 'none'}")
    print(f"  invariants not exercised: {d['unexercised_invariants'] or 'none'}")
    print(f"  report.passed  : {report.passed}")

    hdr("10. Fleet snapshot")
    for k, val in gov.snapshot().items():
        print(f"  {k:22}: {val}")

    print(f"\n{RULE}\nThe links don't bend. The chain does.\n{RULE}")


if __name__ == "__main__":
    main()
