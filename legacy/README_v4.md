# Chainmail v4

**Policy-hard, context-fluid governance layer for long-running multi-agent systems.**

> The links don't bend. The chain does.

> THE AGENTS MAY BE FLUID. THE AUTHORITY IS NOT.

---

## What's New in v4

| Feature | v3 | v4 |
|---------|----|----|
| Persistence | JSONL hash chain | **SQLite + WAL** + JSONL hash chain |
| RESTRICT policy | TTL only | **TTL / Step-budget / HUMAN-only** |
| Quorum voting | Not present | **Multi-governor voting** for high-stakes fleets |
| Crypto | HMAC only | **Ed25519 protocol** (HMAC fallback, crypto-ready) |
| Envelope suggestion | Not present | **Automatic suggestion** from historical runs |
| Embedding | TF-IDF fixed | **Pluggable EmbeddingEngine** interface |

---

## Architecture

```
Agent / harness     Intent & planning    Fluid work inside envelope
    |
Chainmail v4        Trajectory           Objective continuity, authority flow,
                                         delegation, drift, cross-agent anomaly,
                                         ActionSchema, envelope integrity, quorum
    |
Armour (or mock)    Action               Single-action execution boundary
    |
OS / APIs           Effect               Trusted handlers
```

---

## Core Invariants (v4)

1. **Hard envelope** — Human predeclares objective + per-agent authority before any agent runs.
2. **Non-expanding delegation** — Delegation preserves or reduces authority; never silently increases it.
3. **Role enforcement** — Delegation paths constrained by `allowed_delegations` role map.
4. **Central authority** — Live permissions live only in the governance plane.
5. **Context can only tighten** — Signals produce `RESTRICT` / `RECHECK` / `HUMAN`; never grant new permissions.
6. **Consensus is not truth** — Cross-agent agreement is anomaly evidence, not majority vote.
7. **Fail-closed** — Missing permission, hard denial, signature failure, replay, envelope drift, schema violation, or high-severity signal → `HUMAN`.
8. **Budget bounded** — Every permission with `max_budget` is consumed and exhausts to `HUMAN`.
9. **Replay prevention** — Cryptographic nonces; reuse rejected.
10. **Hash-chained provenance** — Append-only, hash-chained, fsync-ed log with structured diagnostics.
11. **Envelope integrity** — Post-construction mutation of the authority envelope is detected and rejected.
12. **Schema enforcement** — Unknown keys, missing required keys, and nested payloads are rejected before evaluation.
13. **Verifier resilience** — Exceptions in semantic engines, intent graphs, or Armour boundaries escalate to `HUMAN` without crashing.
14. **Quorum governance** — High-stakes fleets can require multi-governor agreement before `CONTINUE`.
15. **RESTRICT policy options** — Temporary restrictions can be TTL-based, step-budget-based, or HUMAN-only.

---

## Decisions

| Decision | Meaning |
|----------|---------|
| `CONTINUE` | Inside envelope, trajectory acceptable, Armour executed, quorum passed |
| `RESTRICT` | Continue but with tighter temporary limits (policy-configurable) |
| `RECHECK` | Anomaly; re-evaluate or sample another agent |
| `HUMAN` | Escalate — authority abuse, hard denial, signature/replay/envelope/schema/quorum failure, or high-severity signal |

---

## Quick Start

```bash
cd chainmail_v4
python test_chainmail_v4.py   # 40 tests
python demo_v4.py             # interactive walkthrough
```

**Requirements:** Python 3.9+ (stdlib only — no external packages required for core features).

**Optional:** `pip install cryptography` for Ed25519 asymmetric signatures.

---

## Files

| File | Description |
|------|-------------|
| `chainmail_v4.py` | Core governor + SQLite + quorum + pluggable crypto |
| `test_chainmail_v4.py` | 40-test suite |
| `demo_v4.py` | Interactive walkthrough |

---

## Key v4 Design Decisions

### SQLite Persistence with WAL

`SQLitePersistence` uses WAL (Write-Ahead Logging) mode for durability without blocking readers. It maintains two tables:
- `proposals` — every evaluation with phase, signals, overlap, drift
- `delegations` — every authority transfer with provenance

This enables the `suggest_envelope()` method to analyze historical runs and recommend adjustments.

### RESTRICT Policy Options

Three modes for temporary restrictions:
- `TTL_STEPS` (default) — Restriction auto-expires after N governor steps
- `STEP_BUDGET` — Permission gets N uses before HUMAN escalation
- `HUMAN_ONLY` — Permanent until explicit human review

Configure via `AuthorityEnvelope.restrict_policy`.

### Quorum / Multi-Governor Voting

`QuorumAggregator` collects votes from multiple governor instances:
- Unanimous `CONTINUE` → `CONTINUE`
- Any `HUMAN` with threshold met → `HUMAN`
- Disagreement with `require_human_on_disagreement=True` → `HUMAN`
- No threshold met → `HUMAN` with `QUORUM_REJECTED`

This is designed for high-stakes fleets where no single governor should have unilateral authority.

### Ed25519 Protocol

`Ed25519ApprovalVerifier` implements the `ApprovalVerifier` protocol using asymmetric cryptography. If the `cryptography` package is not installed, it gracefully falls back to rejecting all proposals (fail-closed). To use:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
verifier = Ed25519ApprovalVerifier({"agent-key": public_bytes})
```

### Pluggable EmbeddingEngine

The `EmbeddingEngine` protocol allows swapping TF-IDF for real embeddings:

```python
class SentenceTransformerEngine:
    def __init__(self, model_name="all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_name)
    def similarity(self, text_a, text_b):
        from numpy import dot
        from numpy.linalg import norm
        emb_a = self.model.encode(text_a)
        emb_b = self.model.encode(text_b)
        return float(dot(emb_a, emb_b) / (norm(emb_a) * norm(emb_b)))
    def fit(self, documents):
        pass  # Pre-trained model
```

---

## Research Question

> Can a continuously operating multi-agent system retain useful autonomy while remaining inside a human-defined objective and authority envelope?

v4 makes this experimentally approachable with:
- Production-grade persistence (SQLite WAL)
- Flexible restriction policies
- Distributed governance (quorum voting)
- Asymmetric cryptography ready
- Automatic envelope optimization suggestions

---

## Falsification Criteria

The prototype should be considered failed if any of the following become true under realistic adversarial pressure:

- An agent obtains authority it was never granted without `HUMAN` approval.
- A chain of delegations launders a higher authority than any single link held.
- Context signals expand the live authority set.
- The governor becomes a single point of undetectable compromise that rewrites its own envelope.
- A replayed proposal is accepted.
- A permission with exhausted budget is silently renewed.
- An envelope mutation after construction goes undetected.
- A nested payload smuggles a path traversal past schema validation.
- A verifier exception crashes the governor instead of escalating to `HUMAN`.
- A single compromised governor can force `CONTINUE` against quorum rules.

---

## Roadmap to v5

| Priority | Item |
|----------|------|
| Must | Real embedding model integration (sentence-transformers) |
| Must | Multi-process isolation: governor as service, agents over gRPC/Unix socket |
| Must | Full Ed25519 key management (key rotation, revocation lists) |
| Should | Formal TLA+ model of delegation invariants |
| Should | Integration with real Armour `GuardedExecutor` |
| Should | RESTRICT policy with time-based TTL (wall clock, not just steps) |
| Nice | Automatic envelope generation from natural language objective |
| Nice | Multi-governor consensus over network (Raft/PBFT) |
| Nice | Integration with Warden / Boundary Memory |

---

*Origin: extracted from the Armour skeleton after the OpenWorker comparison (27 Aug 2026).*
*Upgraded: 2 Sep 2026 (v2), 2 Sep 2026 (v3 with Armour PR #1 hardening), 2 Sep 2026 (v4 with SQLite, quorum, Ed2559 protocol).*
