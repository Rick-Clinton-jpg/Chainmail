# Chainmail v5.1

[![CI](https://github.com/Rick-Clinton-jpg/Chainmail/actions/workflows/ci.yml/badge.svg)](https://github.com/Rick-Clinton-jpg/Chainmail/actions/workflows/ci.yml)
&nbsp;License: [PolyForm Noncommercial 1.0.0](LICENSE.md)

**Policy-hard, context-fluid governance layer for long-running multi-agent systems.**

> The links don't bend. The chain does.

---

## What Chainmail is

An importable governance core (`chainmail.ChainmailGovernor`) plus an optional
thin service wrapper (`chainmail.service`). Agents propose actions; the governor
returns one of `CONTINUE` / `RESTRICT` / `RECHECK` / `HUMAN` after checking the
proposal against a human-declared **authority envelope**, cryptographic
authentication, replay protection, an action allow-list and payload schema
(including filesystem-path safety), contextual risk signals, an execution
boundary, and -- for high-stakes fleets -- multi-governor quorum.

v5 is the hardening release: every falsification criterion from v4 has a
regression test, the persistence layer is fixed and durable, signatures bind the
whole proposal, the semantic engine is a real embedding model, and an offline
adversarial mutation harness challenges the boundary on every CI run.

## What Chainmail is **not** — read this first

- **Not a sandbox.** It is a *policy* boundary. It decides whether an action is
  allowed; it does not contain, isolate, or execute anything. The actual action
  boundary is whatever execution handler you wire in via `GuardedExecutorAdapter`
  (any project with a compatible `(proposal, authority) -> (ok, message, output)`
  callable, e.g. a sibling project like [Armour](https://github.com/Rick-Clinton-jpg/Armour) —
  Chainmail has no dependency on it) — the built-in `PermissiveExecutionBoundary`
  authorises everything and is development-only.
- **Not a security boundary for untrusted agents across a network.** The service
  auth is a shared secret / per-caller token over a `0600` Unix socket — fine for
  co-located processes on one trusted host, not across a network. Put mTLS in
  front if you cross a host.
- **The contextual layer is a heuristic, not a proof.** Drift, objective
  mismatch, anomaly, and re-entry all rest on embedding cosine similarity against
  tuned thresholds. An agent that keeps its `objective_fragment` superficially
  on-topic can pass them. Treat these as tripwires; the deterministic checks
  (permissions, allow-list, hard denials, budgets, delegation math, signatures,
  schema, replay, envelope integrity) are the wall.
- **Governs declared intent, not behaviour.** `objective_fragment` and
  `required_permission` are self-reported by the agent. Chainmail checks the
  declared intent against policy; whether the action *does* what it says is the
  execution boundary's job.
- **Partially durable operational state.** Nonce/proposal-ID replay
  protection and restriction state are durable and atomic *when a
  `SQLiteStore` is wired into `AuditSink`* (see `SQLiteStore.claim_nonce`/
  `claim_proposal_id`/`impose_restriction`/`clear_restriction`); without
  one, or for `live_authority` and STEP_BUDGET restriction/permission
  budgets, state still lives only in RAM and a governor restart resets it.
  Multi-process quorum, KMS-backed keys, and durable budgets are tracked for
  v6.
- **No formal proof.** The no-authority-laundering property is tested by example
  and challenged by the mutation harness, not proven.

See [`CHANGELOG.md`](CHANGELOG.md) for the full list of fixes. The v4 code is
under [`legacy/`](legacy/) and is unmaintained.

---

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # core + cryptography + model2vec + pytest
```

Extras:

| Extra | Pulls in | Enables |
|---|---|---|
| `crypto` | `cryptography` | Ed25519 proposal signatures |
| `embeddings` | `model2vec`, `numpy` | real static-embedding semantic engine (default) |
| `embeddings-transformer` | `sentence-transformers`, `numpy` | transformer embeddings |
| `tracing` | `opentelemetry-sdk` | OpenTelemetry spans on `evaluate()` (`CHAINMAIL_TRACING=1`) |
| `dev` | all of the above + `pytest` | test suite + demo |

The core package has **no required dependencies**; without extras it runs with
TF-IDF similarity and a null (dev-only) verifier.

---

## Quick start

```python
import chainmail as cm

env = cm.build_demo_envelope()
gov = cm.ChainmailGovernor(env)            # auto-selects the best embedding engine

p = cm.Proposal(
    proposal_id="p-1",
    agent_id="agent_research",
    action="gather_requirements",
    required_permission=cm.make_permission("research"),
    objective_fragment="Research safe delegation patterns for the prototype",
    confidence=0.88,
)
result = gov.evaluate(p)
print(result.decision, result.signals)     # Decision.CONTINUE []
```

```bash
python demo_v5.py          # narrated walkthrough
pytest -q                  # 101 tests
```

---

## Core invariants

1. **Hard envelope** — humans predeclare the objective and per-agent ceiling
   authority before any agent runs.
2. **Non-expanding delegation** — delegation preserves or reduces authority and
   is constrained by the `allowed_delegations` role map; it is reduced to the
   recipient's envelope ceiling.
3. **Central authority** — live permissions exist only in the governance plane.
4. **Context can only tighten** — signals produce `RESTRICT` / `RECHECK` /
   `HUMAN`; they never grant permissions.
5. **Consensus is evidence, not a vote** — cross-agent agreement is an anomaly
   signal, not a majority decision.
6. **Fail-closed** — missing permission, hard denial, signature/replay/schema/
   path/envelope/quorum failure, audit-write failure, or a verifier exception →
   `HUMAN`.
7. **Budget bounded** — a metered permission is consumed only on `CONTINUE` and
   exhausts to `HUMAN`. Fleet-wide and per-agent step budgets apply.
8. **Replay prevention** — nonces are single-use; the check runs only after the
   signature is trusted.
9. **Tamper-evident provenance** — append-only, hash-chained, fsync'd log,
   re-verified on startup.
10. **Envelope integrity** — any post-construction mutation of the envelope is
    detected by fingerprint and forces `HUMAN`.
11. **Signature binds the whole proposal** — `proposal_id`, `agent_id`, `action`,
    `required_permission`, `objective_fragment`, `parent_proposal_id`, `payload`,
    and `nonce`.
12. **Quorum is fail-closed** — any `HUMAN` vote dominates; no single governor
    can force `CONTINUE`.
13. **Unknown actions fail closed** — when the envelope declares `allowed_actions`,
    any action outside it is `HUMAN` (`UNKNOWN_ACTION`).
14. **Re-entry is hard-gated** — a reworded return to an objective this agent was
    already refused (`RESTRICT`/`HUMAN`) escalates, but *only* when the agent's
    lineage holds a real prior refusal. Similarity alone never raises risk.
    (Design borrowed from [`intent-layer`](https://github.com/Rick-Clinton-jpg/intent-layer).)

---

## Architecture

```
Agent / harness     Intent & planning     Fluid work inside the envelope
      |
chainmail.governor  Trajectory            Objective continuity, authority flow,
                                          delegation, drift, cross-agent anomaly,
                                          schema + path safety, envelope
                                          integrity, replay, quorum
      |
chainmail.execution_boundary  Action        Single-action execution boundary
      |
OS / APIs           Effect                Trusted handlers
```

| Module | Responsibility |
|---|---|
| `core` | value types: `Decision`, `RiskSignal`, `Permission`, `Authority`, `Proposal`, `ActionSchema`, `GovernanceResult` |
| `config` | `GovernorConfig` — every threshold, window, and bound |
| `envelope` | `AuthorityEnvelope` + tamper-evident fingerprint |
| `embeddings` | `EmbeddingEngine` protocol; model2vec / sentence-transformers / TF-IDF; `auto_embedding_engine()` |
| `intent` | `IntentGraph` — bounded drift, peer-consensus, and hard-gated re-entry scoring |
| `crypto` | `KeyRegistry`, `CompositeVerifier` (Ed25519 + HMAC), canonical signing payload, `sign_proposal` |
| `persistence` | `HashChainLog`, `SQLiteStore` (audit + durable replay claims + durable restrictions), `AuditSink`, PII scrubbing |
| `redaction` | `scrub_pii` — typed PII redaction for audit surfaces |
| `quorum` | `QuorumAggregator` (fail-closed), `VoteTransport` |
| `execution_boundary` | `ExecutionBoundary`, `PermissiveExecutionBoundary`, `DenyAllExecutionBoundary`, `GuardedExecutorAdapter` |
| `evaluation` | offline adversarial mutation harness (`MutationRunner`, `standard_mutant_family`) |
| `tracing` | optional, additive OpenTelemetry spans on `evaluate()` |
| `governor` | `ChainmailGovernor` — the policy-hard core |
| `service` | `UnixSocketGovernorServer`, `GovernorClient`, wire protocol, per-caller tokens |

---

## Configuration

```python
from chainmail import GovernorConfig

cfg = GovernorConfig(
    objective_overlap_min=0.25,   # < this similarity -> OBJECTIVE_MISMATCH
    low_confidence_max=0.35,      # <= this confidence -> LOW_CONFIDENCE
    drift_max=0.6,                # > this drift score -> DRIFT
    peer_disagreement_max=0.3,    # < this peer consensus -> HIGH_DISAGREEMENT
    anomaly_confidence_min=0.9,   # high confidence + low overlap -> ASSUMPTION_ANOMALY
    anomaly_overlap_max=0.4,
    reentry_high=0.7,            # confidence-weighted sim to a refused objective -> HUMAN
    reentry_medium=0.45,         # ... -> RESTRICT   (both hard-gated on real refusal history)
    require_signature=False,      # True -> unsigned proposals escalate to HUMAN
    dedupe_proposal_ids=True,     # repeated proposal_id -> PROPOSAL_DUPLICATE
    per_agent_step_budget=0,      # 0 = disabled
    max_seen_nonces=200_000,      # LRU cap on replay set
    proposal_log_max=20_000,
    intent_graph_max=50_000,
)
gov = ChainmailGovernor(env, config=cfg)
```

The defaults match model2vec / TF-IDF similarity ranges: on-objective fragments
score ~0.4–0.8, off-objective ~0.0–0.1.

Set `AuthorityEnvelope(..., allowed_actions={"write_code", "deploy_service", ...})`
to turn on the action allow-list (unknown action → `HUMAN`). Left unset, the
action string is a label and only `required_permission` gates.

---

## Cryptographic signing & key management

```python
from chainmail import (KeyRegistry, CompositeVerifier, ALGO_ED25519,
                       generate_ed25519_keypair, sign_proposal)

reg = KeyRegistry()
priv, pub = generate_ed25519_keypair()
reg.add_key("kid-research-2026a", "agent_research", ALGO_ED25519, pub,
            not_after=1_800_000_000)          # optional validity window

gov = ChainmailGovernor(env, verifier=CompositeVerifier(reg))

# agent / harness side:
sign_proposal(proposal, "kid-research-2026a",
              algorithm=ALGO_ED25519, ed25519_private_pem=priv)
```

* `reg.revoke(kid)` — immediate rejection of that key.
* `reg.rotate(old_kid, new_kid, new_material)` — register the successor, revoke
  the predecessor.
* A key is bound to one `agent_id`; a proposal signed with another agent's `kid`
  is rejected.
* HMAC (`ALGO_HMAC`, `hmac_secret=...`) is supported for shared-secret
  deployments. Ed25519 is recommended.

Without `require_signature=True`, unsigned proposals are still evaluated (the
signature layer is opt-in per deployment); a *present but invalid* signature is
always `HUMAN`.

---

## Persistence & audit

```python
from chainmail import AuditSink, HashChainLog, SQLiteStore

audit = AuditSink(
    hash_chain=HashChainLog("/var/lib/chainmail/audit.jsonl"),  # tamper-evidence
    sqlite_store=SQLiteStore("/var/lib/chainmail/audit.db"),    # queryable truth
)
gov = ChainmailGovernor(env, audit=audit)
```

* Each evaluation writes a `started` then a `completed` record. A write failure
  aborts the evaluation as `HUMAN` (`SANITIZATION_FAILURE`) — the action is not
  executed.
* `HashChainLog` re-loads and re-verifies its file on construction; a broken
  chain raises `ReceiptIntegrityError` rather than silently forking.
* `SQLiteStore.prune(before_timestamp=..., keep_last=...)` for retention.
* `gov.suggest_envelope()` mines the SQLite history for tuning hints.

---

## Governor as a service

```bash
CHAINMAIL_TOKEN=$(openssl rand -hex 16) \
python -m chainmail.service.server \
    --socket /run/chainmail.sock \
    --sqlite /var/lib/chainmail/audit.db \
    --hash-chain /var/lib/chainmail/audit.jsonl \
    --production \
    --hmac-key k1:agent_research:$(openssl rand -hex 32)
```

Without `--production`, the CLI starts a **development** governor: it prints a
warning to stderr, does not require or verify signatures, and uses the
built-in demo `AuthorityEnvelope` rather than a deployment-specific one — the
same demo objective and permission set the tests and `demo_v5.py` use, not
your application's actual authority boundaries. `--production` requires
`--sqlite` and at least one `--hmac-key kid:agent_id:hex_secret` or
`--ed25519-pubkey kid:agent_id:path_to_pem` (repeatable), and wires
`GovernorConfig.production()` plus a real `CompositeVerifier`.

```python
from chainmail.service import GovernorClient

with GovernorClient("/run/chainmail.sock", auth_token=token) as gov:
    result = gov.evaluate(proposal)      # -> result dict
    gov.register_delegation("agent_research", "agent_coder", "share", offered)
    snap = gov.snapshot()
```

* Framing: 4-byte big-endian length + UTF-8 JSON, one object per frame, 4 MiB cap.
* Auth: first frame must be `{"op":"auth","token":...}`, compared in constant
  time. The server refuses to start without a token unless `--allow-no-auth`.
* **Per-caller tokens are authorization-scoped, not just labels**: pass
  `auth_tokens={"tok-a": CallerIdentity(label="worker-1", agent_id="agent_research"),
  "tok-b": CallerIdentity(label="audit-bot", admin=True)}` to issue and revoke
  callers independently. Authentication alone grants only `ping`/`evaluate`;
  `register_delegation` additionally requires the caller be bound to the
  `from_agent` it's delegating as (or hold admin authority), and
  `revoke_delegation`/`snapshot`/`suggest_envelope` require admin authority —
  these are fleet-wide administrative operations, not something any
  authenticated caller should reach just by naming an agent in the request. A
  plain string value (`{"tok-a": "worker-1"}`, `--tokens '{"tok-a":"worker-1"}'`
  / `CHAINMAIL_TOKENS`) is shorthand for a label-only identity with none of
  that authority. `auth_token=` is the single-token shorthand and keeps full
  admin authority (it represents the one trusted local operator credential).
  Pattern adapted from [`Quorum/gate/agent_identity.py`](https://github.com/Rick-Clinton-jpg/Quorum).
* The socket file is created mode `0600`. This is a localhost trust boundary, not
  a public endpoint — put TLS / mTLS in front if you cross a host.
* One `ChainmailGovernor` is shared across all connections; it serialises
  `evaluate` internally.
* One thread per connection, capped by `UnixSocketGovernorServer(...,
  max_connections=128)` (default). A connection beyond the cap is refused
  (closed immediately) rather than spawning an unbounded number of threads.

---

## Semantic engine

`auto_embedding_engine()` (used when you don't pass `embedding=`) tries, in
order: **model2vec** (`minishlab/potion-base-8M`, ~30 MB, downloaded once to the
HuggingFace cache, pure-numpy) → **sentence-transformers** → **TF-IDF**. Force a
choice with `ChainmailGovernor(env, embedding=TfidfEmbeddingEngine())` or
`auto_embedding_engine(prefer="sentence-transformers")`.

Swap in your own by implementing `similarity(a, b) -> [0, 1]` and `fit(docs)`.

---

## Adversarial mutation harness

Passing the happy-path suite doesn't prove a boundary holds. `chainmail.evaluation`
takes one known-good proposal, generates a family of bounded hostile variants
(unknown/hard-denied action, permission self-escalation, path traversal, schema
smuggling, `NaN` confidence, nonce replay, duplicate id, off-objective swap), and
reports **mutation score** (fraction caught) and **invariant coverage** (which
named invariants were exercised). Nothing is executed — each variant is fed to
`evaluate()` and only the verdict is checked.

```python
from chainmail import ChainmailGovernor, MutationRunner, standard_mutant_family

family = standard_mutant_family(seed_proposal, envelope)
report = MutationRunner(lambda: ChainmailGovernor(envelope, auto_embedding=False)).run(
    seed_proposal, family)
assert report.passed          # no survivors, every claimed invariant exercised
print(report.to_dict())
```

CI runs this on the demo envelope and fails the build on any survivor.

---

## Audit-surface PII redaction

`chainmail.redaction.scrub_pii` is applied to every string that reaches the
hash-chain, the SQLite store, or a snapshot — emails, SSNs, card numbers, and
spelled-out emails become `[REDACTED]`. It is deliberately *not* an entropy
scrubber: commit hashes, nonces, execution ids, and UUIDs pass through untouched
because they are the point of an audit trail. (Adapted from
[`Quorum`](https://github.com/Rick-Clinton-jpg/Quorum).)

---

## Notes & known limitations

- Signature / replay / dedupe rejections happen **before** the step counter
  increments, so malformed or unauthenticated traffic cannot exhaust the fleet
  budget. A genuine authenticated proposal that is later denied still counts.
- Quorum's default `VoteTransport` is single-governor (`LocalSingleGovernorTransport`);
  real peer voting needs a `VoteTransport` implementation over your transport of
  choice. `StaticPeerTransport` is provided for tests.
- `GuardedExecutorAdapter` is a generic integration seam for any external
  execution-boundary handler; wire it to your executor callable.
- The demo envelope's agent authorities are deliberately disjoint, so demo
  delegations reduce to the empty set — that is the "non-expanding" invariant
  doing its job, not a bug.

---

## License

Copyright 2026 Rick Clinton.

[PolyForm Noncommercial License 1.0.0](LICENSE.md). Free to use, modify, and
share for any **noncommercial** purpose (personal projects, research, education,
non-profits, and evaluation). Commercial use requires a separate license from the
copyright holder.

---

## Roadmap to v6

| Priority | Item |
|---|---|
| Must | Network quorum transport (Raft / PBFT) with real peer governors |
| Must | mTLS / SPIFFE identity for the service instead of shared/per-caller tokens |
| Must | Durable `live_authority` and STEP_BUDGET/permission budgets with a store + local fallback, rebuilt from the audit log on restart — pattern from `Quorum/gate/firestore_*.py` (replay set and restrictions are already durable) |
| Should | Encrypted key material at rest in `KeyRegistry`; HSM/KMS backend |
| Should | Formal TLA+ model of the delegation invariants |
| Should | Wall-clock fleet budgets and sliding-window rate limits |
| Should | Atomic idempotency store (`claim`/`complete`/`release`) so a client retry can't re-run a `CONTINUE` — pattern from `Quorum/gate/idempotency.py` |
| Nice | Natural-language objective -> envelope generation |
| Nice | Prometheus metrics alongside the OTel spans |

---

*Origin: extracted from the Armour skeleton (27 Aug 2026). v2/v3/v4 on 2 Sep 2026.
v5 (package + service + hardening) on 2 Sep 2026.*
