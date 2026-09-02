# Changelog

## v5.1.0

Hardening pulled from the sibling projects (all PolyForm NC 1.0.0):
`Rick-Clinton-jpg/{intent-layer, Quorum, Armour}`.

### New

- **Hard-gated re-entry detection** (`IntentGraph.reentry_risk`, from
  `intent-layer`). A `RESTRICT`/`HUMAN` turn is recorded as a `safety_boundary`
  node; a later reworded return to it escalates (`OBJECTIVE_REENTRY` →
  `RESTRICT`/`HUMAN`). Hard gate: with no real prior refusal in the agent's
  lineage, similarity alone never raises risk. Per-agent. Config:
  `reentry_high` / `reentry_medium`.
- **Action allow-list** (`AuthorityEnvelope.allowed_actions`). When set, an
  action outside it fails closed (`UNKNOWN_ACTION` → `HUMAN`). Unset keeps the
  permission-centric model. Fingerprinted like the rest of the envelope.
- **Offline adversarial mutation harness** (`chainmail.evaluation`, idea from
  Armour's `evaluation.py`). `standard_mutant_family()` builds bounded hostile
  variants; `MutationRunner` reports mutation score + invariant coverage. CI
  fails on any survivor. Never executes a proposal.
- **Audit-surface PII redaction** (`chainmail.redaction.scrub_pii`, from
  `Quorum/gate/redaction.py`). Typed shapes only (email / SSN / card / spelled-out
  email); hashes, nonces, UUIDs pass through. Applied in `sanitize()` and to the
  delegation `reason` and (newly logged) `objective_fragment`.
- **Optional OpenTelemetry tracing** (`chainmail.tracing`, from
  `Quorum/gate/otel_tracing.py`). Additive and fail-safe: one span per
  `evaluate()` with the decision/signal-count/execution-id, plus a `trace_id`
  cross-referenced into each audit record. `CHAINMAIL_TRACING=1` + the `tracing`
  extra; a null span otherwise.
- **Per-caller service tokens** (`UnixSocketGovernorServer(auth_tokens=...)`,
  `--tokens` / `CHAINMAIL_TOKENS`, pattern from `Quorum/gate/agent_identity.py`).
  Issue/revoke callers independently; the resolved caller label is logged per
  connection. `auth_token=` stays as the single-token shorthand.

### Also

- The hash-chain proposal record now carries the (scrubbed) `objective_fragment`
  and the active `trace_id`.
- `RiskSignal` gains `OBJECTIVE_REENTRY` and `UNKNOWN_ACTION`.
- `pyproject.toml`: authors, project URLs, classifiers, `tracing` extra.
- `LICENSE.md` (PolyForm Noncommercial 1.0.0), `SECURITY.md`, and a GitHub
  Actions matrix (3.9–3.12) that also runs the mutation harness.
- 101 tests (was 91).

## v5.0.0

Promoted from a single module to an installable package (`src/chainmail/`) with an
optional governor-as-a-service wrapper (`chainmail.service`). The v4 files are
kept under `legacy/` for reference.

### Security / correctness fixes (each has a regression test in `tests/test_regressions.py`)

1. **Hash-chain verification was destructive.** `PersistenceLog.verify()` popped
   the `hash` key off every record and never restored it, so the second
   `append()` (which verifies first) saw an unhashed chain and every subsequent
   append raised `ReceiptIntegrityError`. `HashChainLog.verify()` is now
   non-destructive and `failed_record` is a 0-based index.
2. **Signatures only covered `proposal_id:agent_id:action:nonce`.** An attacker
   who observed a signed "read docs" proposal could rewrite `required_permission`,
   `payload`, or `objective_fragment` and the signature still verified. The
   canonical signing payload now binds every tamper-relevant field
   (`crypto.canonical_signing_bytes`).
3. **Replay nonce was consumed before the signature was checked**, so a forged
   proposal could burn a nonce the honest agent intended to use. Signature
   verification now precedes nonce consumption.
4. **Permission budget was consumed before the decision was known.** A proposal
   that ended up `RESTRICT` / `RECHECK` / `HUMAN` (or failed at the Armour
   boundary) still decremented `max_budget`. Budget is now consumed only when the
   final decision is `CONTINUE`.
5. **Quorum was not fail-closed.** With `require_human_on_disagreement=False`, a
   1-`CONTINUE` / 1-`HUMAN` split could return `CONTINUE`. Any `HUMAN` vote now
   dominates regardless of weight or threshold.
6. **Delegation to an unknown agent silently created live authority** for an
   agent absent from the envelope. Both delegator and recipient must now be in
   the envelope.
7. **No `Proposal` validation.** `NaN` confidence bypassed both the
   low-confidence and assumption-anomaly checks (`NaN < x` and `NaN > y` are both
   false). `Proposal` now rejects non-finite / out-of-range confidence and other
   structural defects, and the governor re-checks (`INVALID_PROPOSAL`).
8. **`GovernanceResult.effective_authority` handed back a live reference** to
   governor state; a caller could mutate permissions/budgets in place. It is now
   a copy, as is `provenance`'s authority.
9. **`ActionSchema.filesystem_path_fields` was declared but never enforced.**
   Path fields are now validated: no NUL/control bytes, no `..` segments, no
   backslash/drive paths, and (optionally) confinement to `allowed_path_roots`.
   Violations raise `PATH_TRAVERSAL`.
10. **`evaluate()` mutated shared state with no lock** while the SQLite layer
    assumed threads. The governor now serialises `evaluate` /
    `register_delegation` under a re-entrant lock.

### Also fixed / hardened

- `SQLiteStore` used `threading.local` connections against `:memory:`, giving
  each thread a *separate* database. It now holds one lock-guarded connection,
  adds indices on `agent_id` / `timestamp` / `proposal_id`, a `schema_version`
  table, versioned rows, and a `prune()` retention hook.
- `_seen_nonces`, `proposal_log`, and the intent graph were unbounded (a leak for
  a "long-running" system). All are now bounded (LRU / ring buffer), sized via
  `GovernorConfig`.
- The intent graph refit its private TF-IDF over the entire history on every
  `add`, i.e. O(n^2) per run. It now uses the governor's shared embedding engine
  and a bounded window.
- The governor's own TF-IDF engine was **never fitted** (all IDF = 1.0). The
  fallback engine is now fitted against a live corpus on an interval.
- Every risk threshold (`0.25`, `0.35`, `0.6`, ...) moved into `GovernorConfig`.
- `HashChainLog` now reloads and re-verifies its file on startup instead of
  forking a second genesis record.
- Repeated `proposal_id`s are rejected (`PROPOSAL_DUPLICATE`), configurable.
- Added per-agent step budgets (`FLEET_BUDGET_EXHAUSTED` split from
  `AGENT_BUDGET_EXHAUSTED`).
- `Ed25519ApprovalVerifier` docstring claimed an HMAC fallback it did not have.
  Replaced by `CompositeVerifier` + `KeyRegistry` with per-key `kid`, validity
  window, revocation, rotation, and algorithm dispatch.

### New

- **Real semantic engine**: `Model2VecEmbeddingEngine` (default via
  `auto_embedding_engine()`) -- `model2vec` static embeddings, ~30 MB, no torch,
  pure-numpy inference. `SentenceTransformerEmbeddingEngine` optional. TF-IDF is
  the always-available fallback.
- **`chainmail.service`**: `UnixSocketGovernorServer` + `GovernorClient`,
  length-prefixed JSON framing, shared-token auth, one governor shared safely
  across connections. `chainmail-governor` console entry point.
- `RestrictPolicy.TTL_WALLCLOCK` (wall-clock restriction expiry).
- `GuardedExecutorAdapter` seam for a real Armour `GuardedExecutor`.
- `revoke_delegation()`.
