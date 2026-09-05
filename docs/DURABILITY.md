# Durability integrity: keyed authentication and rollback detection

Status: **implemented, with an important remaining caveat about the
checkpoint mechanism itself.** Row-level keyed authentication covers every
table `SQLiteStore` treats as authoritative state: `live_authority`/
`live_authority_agents` (schema v6), `restrictions`/`replay_nonces`/
`replay_proposal_ids`/`step_counters` (schema v7) -- `SQLiteStore(key_provider
=...)`, `KeyProvider`/`InMemoryKeyProvider`, `RowIntegrityError`. Two keyed,
hash-chained, append-only ledgers -- `initialization_ledger` (schema v8) and
`restriction_ledger` (schema v9) -- close most of the "a row made to vanish
(deleted, or excluded by a status filter) is indistinguishable from having
never existed / never being ACTIVE" gap, for `live_authority_agents`'s
initialization marker and for `restrictions`'s status column respectively.
And a rollback checkpoint (schema v10) -- `SQLiteStore(rollback_checkpoint=
...)`, `RollbackCheckpoint`/`InMemoryRollbackCheckpoint`,
`RollbackDetectedError`, `advance_checkpoint` -- closes the one gap none of
the above can: a whole-database swap back to an earlier, internally-valid
backup. See "What this layer would need to do" below for exactly what each
piece does and does not catch. All of it is covered by the (now fully
un-skipped) tests in `tests/test_authority_integrity_spec.py`.

**The caveat:** the rollback-checkpoint *mechanism* (the protocol, the
construction-time comparison, the two-phase advance) is implemented and
correct, but `InMemoryRollbackCheckpoint` -- the only implementation this
repository ships -- is explicitly **not** a real checkpoint: its state lives
in process memory only, exactly as trustworthy as the SQLite file it's
supposed to be independent of. A real deployment must supply its own
`RollbackCheckpoint` backed by genuinely external, trusted state (a TPM/
secure-enclave counter, a remote attestation service, an operator-verified
out-of-band value) -- see "This explicitly requires an external trusted
checkpoint" below, which is unchanged by this implementation and remains the
central limitation of rollback detection in general, not something more
code here could remove. Deployments must also decide their own policy for
*when* to call `advance_checkpoint()` -- this repository does not wire it
into every write path (see below for why).

## Why this is out of scope for the durability work it follows

The durable live-authority/permission-budget/step-counter persistence
(`SQLiteStore` schema v5: `live_authority`, `live_authority_agents`,
`step_counters`) makes state survive a **process restart**, makes
consumption **atomic across concurrent processes sharing one file**, and
enforces a **freshness rule**: authority is resolved against the durable
store at each decision that depends on it (the permission/budget check, and
separately the durable consumption decision, each re-read fresh -- no
previously-resolved `Authority` object is reused across hops or across the
two), with store unavailability at any of those points failing closed
rather than falling back to an in-memory or cached view. See
`ChainmailGovernor._evaluate_locked`'s step 15b and
`tests/test_authority_persistence.py`'s freshness-rule section for the
concrete enforcement and its adversarial tests.

None of that says anything about whether the file itself can be tampered
with by something with direct filesystem access to it -- an operator
error, a compromised host, or a deliberate attack that edits, replaces, or
rolls back the SQLite file outside of Chainmail's own code path entirely.

Closing that gap requires a genuinely different mechanism (keyed MACs on
every durable row, held against a secret Chainmail's own code never persists
in the same file) and, for rollback specifically, a piece of trusted state
*outside* SQLite -- neither of which the schema-v5 work touches. Bundling it
into that change would have doubled its size and blurred two independently
reviewable properties (durability vs. tamper-evidence) into one commit.

## What this layer would need to do

### 1. Keyed authentication of durable rows

**Implemented for every authoritative table.** Every row `SQLiteStore`
treats as authoritative state -- `live_authority`/`live_authority_agents`
(schema v6), `restrictions`/`replay_nonces`/`replay_proposal_ids`/
`step_counters` (schema v7) -- carries an HMAC computed over its own
authoritative columns, keyed by a secret held **outside the SQLite file**
(an environment variable, an OS keyring entry, or an external KMS -- never a
column in the same database, via `SQLiteStore(key_provider=...)`).
`get_live_authority_rows`, `is_authority_initialized`, `active_restrictions`,
and `peek_step_counter` recompute the MAC on every read and raise
`RowIntegrityError` (a `sqlite3.Error` subclass, so it fails closed exactly
like every other durable-store failure `ChainmailGovernor` already handles)
on a mismatch; `claim_nonce`/`claim_proposal_id` verify the *existing* row
when a claim conflicts, so a forged "already claimed" row cannot be trusted
as a genuine prior claim. Every write path (`initialize_agent_authority`,
`replace_live_authority`, `consume_permission_budget`, `impose_restriction`,
`mark_expired`, `clear_restriction`, `claim_nonce`, `claim_proposal_id`,
`increment_step_counter`) writes or refreshes a valid MAC in the same
transaction as the write itself.

This detects: a row edited directly with a SQLite client or a raw file
editor, a row deleted and replaced with a forged one, and a row inserted
without going through `SQLiteStore`'s own write API. It does **not** detect
an edit made by someone who also has the key (the key, not the schema, is
the trust boundary) -- key custody outside the application is what this
buys you, not protection against a fully compromised host. It also does
**not**, by itself, detect a row being deleted, or otherwise made to vanish
from the specific query a decision reads, rather than edited in place --
that needs the same kind of durable, independently-verifiable "this
happened" record `HashChainLog` already provides for the audit trail, and
is exactly what the two ledgers below add.

Both `initialization_ledger` (schema v8) and `restriction_ledger` (schema
v9) share one mechanism (`_verify_hash_chain`, factored out once both
existed): a keyed, hash-chained, append-only table where each entry's `mac`
is computed over its own content *and* the previous entry's `mac`
(`LEDGER_GENESIS` for the very first entry ever written, globally across
every namespace/agent). Deleting or reordering an entry breaks the *next*
entry's chain linkage -- detectable without needing anything external, as
long as something was appended after the deleted entry. Both also share the
same residual limit: deleting the chain's **current tip** (the single most
recent entry, nothing chained after it yet) leaves everything before it
fully self-consistent, which is the same rollback/truncation problem as (2)
below and needs the same external checkpoint to close -- a purely internal
hash chain cannot bootstrap proof that nothing was ever appended after a
given point.

- **`live_authority_agents`'s initialization marker -- closed, with that
  residual limit.** Every `initialize_agent_authority` /
  `replace_live_authority` first-time-init call appends an
  `initialization_ledger` entry. `is_authority_initialized` cheaply
  cross-checks the marker row's presence against the ledger entry's
  presence for the same `(namespace, agent_id)` on every call (one indexed
  lookup, not a chain walk) and raises `RowIntegrityError` on disagreement
  -- so a marker deleted *alone* (its ledger entry left behind) is caught
  immediately (see `test_deleted_row_is_indistinguishable_from_never_
  having_existed_today_but_wont_be`). The full O(n) chain walk
  (`verify_integrity_ledger`, also run once automatically at `SQLiteStore`
  construction) additionally catches a marker *and* its ledger entry
  deleted **together**, as long as some other agent was initialized
  afterward (see `test_ledger_chain_catches_a_middle_entry_deleted_even_
  when_its_marker_is_also_deleted`); deleting the current tip is not caught
  (see `test_ledger_chain_does_not_catch_the_current_tip_being_deleted`).
- **`restrictions` status-flip -- closed, with that same residual limit.**
  Every `impose_restriction`/`mark_expired`/`clear_restriction` call appends
  a `restriction_ledger` entry (IMPOSED/EXPIRED/CLEARED). `active_
  restrictions` cheaply cross-checks, per call: for every `restriction_id`
  this agent's ledger has ever recorded a transition for, look at only its
  *latest* entry (one query per agent, not a full chain walk) -- if that
  latest transition is IMPOSED (the ledger's last word is "should still be
  ACTIVE") but the restriction_id is missing from what the ACTIVE query
  just returned, that disagreement is exactly a status column flipped
  directly, without a matching ledger entry (see
  `test_restriction_status_flip_is_now_caught_by_the_ledger_cross_check`,
  and `test_forged_ledger_entry_without_the_key_cannot_hide_a_status_flip`
  for why planting a matching-looking forged ledger row doesn't help --
  it fails its own mac check first). The full chain walk
  (`_verify_restriction_ledger_chain`, also part of `verify_integrity_
  ledger`) catches a transition entry deleted together with the
  `restrictions` row's own status flip, as long as another restriction's
  transition was recorded afterward (see `test_restriction_ledger_chain_
  catches_a_middle_entry_deleted`); deleting the current tip is not caught
  (see `test_restriction_ledger_does_not_catch_the_current_tip_being_
  deleted`).

### 2. A host-provided monotonic checkpoint for rollback detection

A keyed MAC alone cannot detect **rollback to an older, internally valid**
database -- restoring yesterday's (correctly MAC'd, at the time) backup
produces a file that passes every per-row check in (1), because every row
really was validly written, just earlier. Detecting that requires comparing
the database's own notion of "how far it has progressed" against an
independent, trusted high-water mark that a rollback cannot also roll back.

**Implemented.** `SQLiteStore` maintains its own local sequence number in
`rollback_checkpoint_state` (schema v10, a single row). `advance_checkpoint()`
bumps it, in two phases: the local bump commits first (a real, atomic SQLite
transaction), then that same new value is pushed to the configured
`RollbackCheckpoint.advance()`. At construction, `_check_rollback_checkpoint`
compares the local value against `RollbackCheckpoint.read()`:

- **local < external**: this file's own recorded progress is *behind* what
  the external, trusted checkpoint has already seen committed -- exactly
  what restoring an earlier backup looks like. Raises
  `RollbackDetectedError`; construction fails closed, like
  `SchemaVersionError` (see `test_rollback_to_an_earlier_valid_database_
  is_detected_with_a_checkpoint_configured`).
- **local > external**: *not* a rollback signal -- a previous process's
  `advance_checkpoint()` call committed the local bump but crashed (or the
  external call itself failed) before the external side landed. Self-heals
  by pushing the checkpoint forward to match what's already durably
  committed, rather than treating every ordinary crash as a permanent
  lockout (see `test_checkpoint_advances_atomically_with_the_state_it_
  protects`).
- **local == external**: consistent, nothing to do.

This is a genuine two-phase protocol, not two independent, racily-ordered
writes: the value pushed to the external checkpoint is always exactly the
value the just-completed local commit produced, and a failure of either
phase never leaves an *undetectable* gap -- either the next open sees
local == external (both phases landed), local > external (self-heals), or,
if the file were rolled back in between, local < external (the actual
rollback signal, still caught).

`SQLiteStore` does not decide *when* `advance_checkpoint()` should be
called, or wire it automatically into every authoritative write -- see
"Smallest correct next step" below for why: the answer depends entirely on
the cost and rate limits of whichever external mechanism a deployment
actually has (a TPM counter increment might be expensive; a remote
attestation call might be cheap enough to do after every proposal), and
there is no single policy that fits every deployment.

**This explicitly requires an external trusted checkpoint.** A key inside
the same trust boundary as the database (this repository's code, this
host's disk) cannot bootstrap rollback detection on its own -- if the
attacker can restore an old database file, they can equally well restore an
old copy of anything else stored next to it. The checkpoint's trust must
come from somewhere the rollback cannot also reach: a TPM counter, a remote
service, or an operator-verified out-of-band value. **`InMemoryRollbackCheckpoint`
is not that** -- it is a process-local reference implementation for
exercising the protocol in tests, exactly as untrustworthy as the database
it's meant to be independent of. Chainmail does not ship a genuinely
external mechanism today, and this document does not pretend a purely local
design could provide one -- see `RollbackCheckpoint`'s own docstring.

## What this layer would still NOT guarantee

- **Availability.** A host that can tamper with the file can still just
  delete it -- already fail-closed (see `test_deleted_storage_fails_closed`)
  and out of scope for a layer whose job is detecting *silent* tampering,
  not preventing denial of service.
- **Confidentiality.** MACs authenticate, they do not encrypt. A permission
  name, budget count, or agent id in a tampered row is still readable by
  whoever has filesystem access, key or no key.
- **Protection against a compromised key holder.** As stated above -- the
  key is the trust boundary. Anyone who can read the key can forge a valid
  row. Key rotation and custody are an operational concern this design does
  not solve.
- **Anything beyond what's in the row.** This authenticates *durable
  authority/budget/replay/restriction rows*, not the envelope, not proposals
  in flight, not the hash-chain audit log (which already has its own,
  separate hash-chain tamper-evidence via `HashChainLog`).
- **Rollback protection with only `InMemoryRollbackCheckpoint`.** As stated
  in "Status" and section 2 above -- a process-local checkpoint object
  provides zero real protection; it exists to test the mechanism, not to
  deploy with. A real deployment must supply its own `RollbackCheckpoint`.
- **A policy for when to call `advance_checkpoint()`.** The mechanism is
  correct regardless of how often it's called, but calling it too rarely
  widens the window an attacker's rollback could hide inside (state
  committed since the last `advance_checkpoint()` call has no local
  checkpoint value protecting it yet). Deciding that cadence is a
  deployment's own tradeoff against its checkpoint mechanism's cost, not
  something this repository can decide generically.

## Smallest correct next step, if/when this is picked up

Every numbered step below is done:

1. ~~Land `tests/test_authority_integrity_spec.py`'s tests un-skipped, one at
   a time, starting with row-level MAC verification~~ -- done for
   `live_authority`/`live_authority_agents` (schema v6),
   `restrictions`/`replay_nonces`/`replay_proposal_ids`/`step_counters`
   (schema v7), the `live_authority_agents` deleted-marker gap (schema v8's
   `initialization_ledger`), the `restrictions` status-flip gap (schema
   v9's `restriction_ledger`, generalizing the same mechanism), and rollback
   detection (schema v10's `rollback_checkpoint_state` /
   `RollbackCheckpoint`). Every test in `tests/test_authority_integrity_
   spec.py` is now un-skipped.
2. ~~Add a `key_provider` seam to `SQLiteStore.__init__`~~ -- done:
   `KeyProvider` (protocol) / `InMemoryKeyProvider` (a process-local
   reference implementation for tests and single-process deployments; a
   real deployment wanting rotated-out keys to survive a restart needs its
   own `KeyProvider` backed by a keyring, env var, or KMS).
3. ~~Treat rollback-checkpoint support as its own follow-on commit~~ -- done:
   `RollbackCheckpoint` (protocol) / `InMemoryRollbackCheckpoint` (a
   process-local reference implementation, **not real protection** -- see
   above) / `RollbackDetectedError` / `SQLiteStore.advance_checkpoint()`.
   What a deployment must still decide for itself, and this repository
   deliberately does not: **which** external checkpoint mechanism to use
   (there is still no one-size-fits-all answer -- a TPM counter, a remote
   attestation service, and an operator-verified value all have different
   cost/latency/availability tradeoffs), and **how often** to call
   `advance_checkpoint()` (this repository does not wire it into any
   write path automatically).

One thing this does **not** do, worth being explicit about: `rollback_
checkpoint_state`'s sequence number is an independent counter, not derived
from the ledgers' own content -- so it does not, by itself, close the
residual "current tip deleted" gap in `initialization_ledger` /
`restriction_ledger`. A surgical, live edit that deletes just the ledger's
tip row (without touching `rollback_checkpoint_state`) leaves the checkpoint
sequence untouched and therefore still consistent with the external
checkpoint -- `_check_rollback_checkpoint` has nothing to disagree with. The
checkpoint mechanism protects against restoring an **older, whole copy** of
the database file (the classic "rollback" this document is titled for),
which does revert `rollback_checkpoint_state` along with everything else and
is exactly what `local < external` catches; it is a different attack from
surgically editing rows in the *current* live file, which is what the
per-row MACs and ledger chains (section 1) exist for. Closing the ledgers'
tip-deletion gap specifically would need the checkpoint's own advanced value
to depend on the ledgers' current tip mac (e.g. hashing them together) --
not implemented, and left as a genuine open question for whoever picks this
up next, not a claim this document makes.
