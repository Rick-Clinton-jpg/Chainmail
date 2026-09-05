# Durability integrity: keyed authentication and rollback detection

Status: **partially implemented.** Row-level keyed authentication now covers
every table `SQLiteStore` treats as authoritative state: `live_authority`/
`live_authority_agents` (schema v6), `restrictions`/`replay_nonces`/
`replay_proposal_ids`/`step_counters` (schema v7) -- `SQLiteStore(key_provider
=...)`, `KeyProvider`/`InMemoryKeyProvider`, `RowIntegrityError`. On top of
that, a keyed, hash-chained, append-only `initialization_ledger` (schema v8)
closes most of the "deleted marker row is indistinguishable from never
initialized" gap for `live_authority_agents` -- see "What this layer would
need to do" below for exactly what it does and does not catch. All of the
above is covered by the un-skipped tests in
`tests/test_authority_integrity_spec.py`. Still not implemented: the
`restrictions` status-flip gap (same category, not yet given the same
ledger-style treatment) and the entire rollback-checkpoint half, which needs
external infrastructure this repository does not ship. This document
specifies what the remaining piece of the keyed-integrity layer would need
to guarantee, why it is a separate piece of work from the durable-authority/
budget persistence it builds on, and what it can and cannot honestly
promise. The still-skipped tests in `tests/test_authority_integrity_spec.py`
(not deleted) pin down what "done" looks like for the rest.

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
is what `initialization_ledger` (below) adds for one of the two known
instances of this gap.

- **`live_authority_agents`'s initialization marker -- closed, with a
  documented residual limit.** `initialization_ledger` (schema v8) is a
  keyed, hash-chained, append-only table: every `initialize_agent_authority`
  / `replace_live_authority` first-time-init call appends an entry chained
  onto the previous entry's `mac` (`LEDGER_GENESIS` for the very first ever
  written). `is_authority_initialized` cheaply cross-checks the marker
  row's presence against the ledger entry's presence for the same
  `(namespace, agent_id)` on every call (one indexed lookup, not a chain
  walk) and raises `RowIntegrityError` on disagreement -- so a marker
  deleted *alone* (its ledger entry left behind) is caught immediately (see
  `test_deleted_row_is_indistinguishable_from_never_having_existed_today_
  but_wont_be`). A full O(n) walk of the entire chain
  (`verify_integrity_ledger`, also run once automatically at `SQLiteStore`
  construction) additionally catches a marker *and* its ledger entry
  deleted **together**, as long as some other agent was initialized
  afterward (deleting entry N breaks entry N+1's `prev_mac` linkage -- see
  `test_ledger_chain_catches_a_middle_entry_deleted_even_when_its_marker_
  is_also_deleted`). What neither check catches: deleting the *current tip*
  -- the single most-recently-initialized agent's marker and ledger entry,
  removed together, with nothing chained after it yet -- which leaves the
  remaining chain fully self-consistent (see
  `test_ledger_chain_does_not_catch_the_current_tip_being_deleted`). That
  residual gap is the same rollback/truncation problem as (2) below, and
  needs the same external checkpoint to close -- a purely internal hash
  chain cannot bootstrap proof that nothing was ever appended after a given
  point.
- **`restrictions` status-flip -- still open.** `active_restrictions`
  filters on `status = 'ACTIVE'` in SQL before any MAC is checked, so
  flipping an ACTIVE row's `status` column directly (rather than one of the
  columns the query still returns) makes it vanish from the result
  silently, with no `RowIntegrityError` raised (see
  `test_restriction_status_flip_bypasses_mac_verification_known_gap`,
  un-skipped and passing -- it pins down the gap itself, not a guarantee).
  The MAC still catches a forged *new* ACTIVE restriction or an
  edited-in-place ACTIVE row. The same ledger-style cross-check that closed
  the marker-deletion instance above would generalize here (an append-only
  "restriction transition" ledger, cross-checked the same way), but hasn't
  been done yet -- a natural next slice of this same work.

### 2. A host-provided monotonic checkpoint for rollback detection

A keyed MAC alone cannot detect **rollback to an older, internally valid**
database -- restoring yesterday's (correctly MAC'd, at the time) backup
produces a file that passes every per-row check in (1), because every row
really was validly written, just earlier. Detecting that requires comparing
the database's own notion of "how far it has progressed" against an
independent, trusted high-water mark that a rollback cannot also roll back.

The design: a monotonic counter (or the highest `updated_at`/hash-chain tip
already committed) recorded by the **host**, outside the SQLite file --
another local file with its own integrity protection, a TPM/secure-enclave
monotonic counter, or a remote attestation service. On open, `SQLiteStore`
would compare its own most-recent committed marker against the host
checkpoint; a database that claims to be behind the checkpoint is a rollback
and construction fails closed. On every commit that advances authoritative
state, the checkpoint is advanced too, in the same logical step (not a
separate, racy write).

**This explicitly requires an external trusted checkpoint.** A key inside
the same trust boundary as the database (this repository's code, this
host's disk) cannot bootstrap rollback detection on its own -- if the
attacker can restore an old database file, they can equally well restore an
old copy of anything else stored next to it. The checkpoint's trust must
come from somewhere the rollback cannot also reach: a TPM counter, a remote
service, or an operator-verified out-of-band value. Chainmail does not ship
such a mechanism today, and this document does not pretend a purely local
design could provide one.

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

## Smallest correct next step, if/when this is picked up

1. ~~Land `tests/test_authority_integrity_spec.py`'s tests un-skipped, one at
   a time, starting with row-level MAC verification~~ -- done for
   `live_authority`/`live_authority_agents` (schema v6),
   `restrictions`/`replay_nonces`/`replay_proposal_ids`/`step_counters`
   (schema v7), and the `live_authority_agents` deleted-marker gap
   (schema v8's `initialization_ledger`). Still to un-skip: (a) generalize
   the same ledger-cross-check pattern to `restrictions`'s status-flip gap;
   (b) rollback detection, below (which also happens to be the residual
   limit the v8 ledger itself couldn't close -- see above).
2. ~~Add a `key_provider` seam to `SQLiteStore.__init__`~~ -- done:
   `KeyProvider` (protocol) / `InMemoryKeyProvider` (a process-local
   reference implementation for tests and single-process deployments; a
   real deployment wanting rotated-out keys to survive a restart needs its
   own `KeyProvider` backed by a keyring, env var, or KMS).
3. Treat rollback-checkpoint support as its own follow-on commit, gated on
   deciding which external checkpoint mechanism a given deployment actually
   has available -- there is no one-size-fits-all answer, so the seam should
   accept a pluggable `RollbackCheckpoint` protocol rather than hardcoding
   one implementation.
