# Changelog

## Unreleased

### Added — keyed row authentication for restrictions, replay tables, and step_counters (schema v7)

Second slice of the tamper-detection layer, extending schema v6's
`live_authority`/`live_authority_agents` row authentication to every
remaining table `SQLiteStore` treats as authoritative state:
`restrictions`, `replay_nonces`, `replay_proposal_ids`, `step_counters`.
Same opt-in, purely-additive shape (`mac`/`key_id` -- `mac_key_id` on
`replay_nonces`, which already has an unrelated `key_id` column for the
signing key that verified the claimed proposal's signature) and same
fail-closed contract (`RowIntegrityError`, a `sqlite3.Error` subclass) as
v6.

- `active_restrictions` verifies the MAC on every ACTIVE row it returns;
  `impose_restriction`/`mark_expired`/`clear_restriction` write or refresh
  a valid MAC on every write, including the ACTIVE -> EXPIRED/CLEARED
  transitions.
- `claim_nonce`/`claim_proposal_id` write a MAC on a new claim, and now
  verify the *existing* row when a claim hits the UNIQUE conflict --
  a row an attacker planted to pre-emptively block a nonce/proposal_id a
  legitimate agent hasn't used yet no longer looks like a genuine prior
  claim.
- `increment_step_counter`/`peek_step_counter` verify the pre-existing
  count before building on top of it (so a count reset to renew a step
  budget is caught) and refresh the MAC after every increment, inside the
  same transaction as the increment itself.

Honestly documented, not claimed as closed (see updated
`docs/DURABILITY.md`): `active_restrictions` filters on
`status = 'ACTIVE'` in SQL *before* any MAC is checked, so an attacker who
flips an ACTIVE row's `status` column directly (rather than editing one of
the columns the query still returns) makes it vanish from the result
silently -- the same category of gap as a deleted
`live_authority_agents` marker. New test
`test_restriction_status_flip_bypasses_mac_verification_known_gap` pins
this down explicitly rather than leaving it merely described in prose.

New migration test `test_v6_database_upgrades_to_v7_with_mac_columns_
usable` proves a genuine pre-v7 `restrictions` table upgrades cleanly and
that attaching a `key_provider` afterwards fails closed on a pre-existing
unauthenticated row.

9 new tests in `tests/test_authority_integrity_spec.py` (tampered/forged
rows for restrictions, replay_nonces, replay_proposal_ids, and
step_counters; the documented status-flip gap; transition/rotation/
non-adversarial regression coverage), plus the migration test above in
`tests/test_authority_persistence.py`.

225 passed, 5 skipped (was 215/5 before this commit).

### Added — keyed row authentication for durable live authority (schema v6)

First implemented slice of the tamper-detection layer `docs/DURABILITY.md`
scoped out of the original durable-authority/budget work (schema v5):
`live_authority` and `live_authority_agents` rows can now be authenticated
with a keyed HMAC, closing the gap where something with direct filesystem
access to the SQLite file could edit, replace, or insert a row without going
through `SQLiteStore`'s own write API.

New, additive-only schema v6: `mac`/`key_id` columns on both tables, both
nullable so a `SQLiteStore` opened without a `key_provider` (the default)
reads/writes exactly as schema v5 did -- authentication is entirely opt-in.
Existing v5 databases upgrade in place (`ALTER TABLE ... ADD COLUMN`, no
data migration needed).

New: `KeyProvider` (a `(key_id, key_bytes)` protocol -- `current()` for
signing, `get(key_id)` for verifying rows written under an earlier,
possibly-rotated-out key), `InMemoryKeyProvider` (a process-local reference
implementation for tests and single-process deployments), and
`RowIntegrityError`, deliberately a subclass of `sqlite3.Error` so every
existing `except sqlite3.Error` call site in `ChainmailGovernor` already
treats a failed-verification row exactly like any other durable-store
failure and fails closed (HUMAN, `AUTHORITY_STORE_UNAVAILABLE`) without
needing a new exception path threaded through the governor.

`get_live_authority_rows` and `is_authority_initialized` recompute and check
the MAC on every read that feeds an authorization decision.
`initialize_agent_authority`, `replace_live_authority`, and
`consume_permission_budget` write/refresh a valid MAC on every authoritative
write; `consume_permission_budget`'s MAC refresh happens via the same
`UPDATE ... RETURNING` statement's transaction as the budget decrement
itself, so no reader can ever observe a decremented `remaining` whose MAC
still reflects the pre-consume value.

Still open, and explicitly not claimed here (see the updated
`docs/DURABILITY.md`): `restrictions`/`replay_nonces`/`replay_proposal_ids`/
`step_counters` remain unauthenticated; a `live_authority_agents` marker row
that is *deleted* (not tampered, just absent) is still indistinguishable
from "never initialized" -- a per-row MAC cannot prove a row used to exist;
and rollback-to-an-older-database detection remains entirely unimplemented
(it needs external, host-provided trusted state this repository does not
ship).

Six of the seven tests in `tests/test_authority_integrity_spec.py` (design
spec, previously all skipped) are now un-skipped and real:
`test_tampered_live_authority_row_is_rejected`,
`test_tampered_row_without_the_key_cannot_forge_a_valid_mac`,
`test_unauthenticated_store_is_unaffected_by_row_verification`,
`test_consume_permission_budget_keeps_the_mac_current`,
`test_replace_live_authority_keeps_the_mac_current`,
`test_key_rotation_does_not_invalidate_existing_rows`. The remaining four
(the deleted-marker gap and the three rollback-checkpoint tests) stay
skipped, unchanged from before. New migration test
`test_v5_database_upgrades_to_v6_with_mac_columns_usable` (in `tests/
test_authority_persistence.py`) also asserts a genuine v5-shaped database
(no mac/key_id columns) upgrades cleanly and that attaching a
`key_provider` afterwards fails closed on the pre-existing unauthenticated
row rather than silently trusting it.

215 passed, 5 skipped (was 208/8 before this commit).

### Added — register_delegation(merge=True) to accumulate authority from multiple delegators

The previous commit documented that `register_delegation` replaces the
recipient's entire live authority rather than merging -- a deliberate
security property (no accumulation across many small, individually-
unremarkable delegations), but also a real usability gap: an agent that
legitimately needs authority from more than one source (e.g. two peers each
granting access to a different resource) had no way to receive it except
as a single delegation call carrying the full union itself.

New `merge: bool = False` keyword on `ChainmailGovernor.register_delegation`.
With `merge=True`, the offered (already role-checked, `is_subset_of`-checked,
ceiling-clamped) authority is unioned with whatever the recipient currently,
durably holds -- fresh read, same as everywhere else authority is resolved.
A merge that would collide with a permission already held (same
`(name, scope)`) is refused outright (fail closed) rather than guessing a
resolution -- summing budgets, one replacing the other, or taking the max
are all equally defensible and equally arbitrary, so none is chosen
automatically; the caller must `revoke_delegation` first or delegate
without `merge=True` to deliberately replace a colliding grant. The
default (`merge=False`) behavior, and every existing test asserting it, is
completely unchanged.

Wired through the service layer too: `GovernorClient.register_delegation`
and the wire protocol's `register_delegation` op both accept `merge`.

New tests: `test_delegation_merge_accumulates_from_multiple_sources`,
`test_delegation_merge_refuses_a_colliding_permission` (and that the
recipient's existing grant is left byte-for-byte unchanged on refusal),
`test_delegation_merge_is_durable_across_restart` (in `tests/
test_governor.py`), and `test_register_delegation_merge_over_wire` (in
`tests/test_service.py`, proving the parameter round-trips through the
actual Unix-socket protocol, not just the in-process API).

208 passed, 8 skipped (was 204/8 before this commit).

### Docs — clarified that register_delegation replaces, never merges, live authority

An external review raised "delegation chain amplification" (many small
delegations from different agents accumulating into broader combined
access) as a vulnerability. Verified against the actual code: it isn't
reachable. `register_delegation` does `self.live_authority[to_agent] =
new_auth` -- a full replacement of the recipient's entire live authority,
never a union with whatever it held before. A second delegation from a
different agent overwrites the first; the recipient ends up with only the
most recent delegation's (clamped) grant, never the combined set. This was
previously undocumented -- `register_delegation` had no docstring at all --
so the absence of a stated contract was a fair thing to flag even though
the specific attack doesn't work.

Added a full docstring to `ChainmailGovernor.register_delegation` stating
the replace-not-merge contract explicitly, and a note in README.md's Core
Invariants section (under "Non-expanding delegation"). New test
`test_delegation_replaces_rather_than_merges_across_multiple_sources` in
`tests/test_governor.py`: two agents each delegate one distinct permission
to the same recipient; the recipient ends up holding only the second
delegation's permission, proving the first grant was overwritten rather
than accumulated.

204 passed, 8 skipped (was 203/8 before this commit).

### Added — authority-laundering mutant family for the durable authority/budget path

`standard_mutant_family()` targets the deterministic per-proposal checks
against a caller-supplied flat envelope; it has no way to attack a real
delegation graph. New `authority_laundering_mutant_family()`
(`chainmail.evaluation`) is a self-contained second family, with its own
purpose-built 3-tier delegation envelope (`agent_root` -> `agent_mid` ->
`agent_leaf`), covering 5 laundering patterns against the durable live-
authority/permission-budget path and the freshness rule on top of it:

- delegating more authority than the delegator's current durable remaining
  (not its original ceiling)
- reusing authority after an upstream revocation (the freshness rule)
- forging `required_permission`'s own `max_budget` field to claim
  "unlimited" and bypass consumption, which resolves against the agent's
  actually-held permission and its real remaining, never the proposal's
  own claim
- multi-hop delegation laundering that looks individually valid at each
  hop (offered <= what the delegator once received) but tries to exceed
  what it currently, durably holds
- two governor instances racing to double-spend the last unit of a budget

Every mutation's setup consumes budget by calling `SQLiteStore.
consume_permission_budget` directly rather than through repeated
`gov.evaluate()` calls -- `MutationRunner.run()`'s deny-and-record
execution boundary downgrades every would-be `CONTINUE` to `HUMAN`, and a
`HUMAN` decision is recorded in the intent graph as a refusal boundary;
priming through real `evaluate()` calls would poison the target agent's
intent-graph history with harness-induced "refusals" before the real
attack proposal ever runs, triggering `OBJECTIVE_REENTRY` on it for a
reason unrelated to the invariant under test (discovered by running the
family and finding every mutant reported that signal instead of its
intended one -- fixed before landing, not shipped and found later).

New `AUTHORITY_LAUNDERING_INVARIANTS` (parallel to `STANDARD_INVARIANTS`).
`demo_v5.py` runs both families (step 9 standard, step 9b laundering).
Discriminating-power verified directly: with `Authority.is_subset_of`
patched to always return `True` (simulating a real regression), exactly
the two mutations that specifically attack that check survive and no
others -- proving the family isn't a vacuous pass.

New tests in `tests/test_evaluation.py`: all 5 laundering mutants killed
against a correct governor; the family requires durable storage (a
non-durable factory does not pass); the family never lets a real execution
boundary run; and the `is_subset_of`-break discriminating-power check
above. 203 passed, 8 skipped (was 199/8 before this commit).

Covers 5 of the laundering patterns worth testing, not an exhaustive
family -- see README.md's "Notes & known limitations" for what's not yet
covered (many small delegations accumulating, sibling agents recombining
partial permissions, re-entry after a prior refusal in a delegation
context, a policy/fingerprint change mid-chain, identity/namespace
substitution, a restart mid-delegation-chain).

### Added — durable live authority, permission budgets, and step (runtime) budgets

Live (delegated) authority, permission budgets, and fleet/per-agent step
budgets previously lived only in process memory: a restart reset delegated
authority to the envelope ceiling and renewed every budget, and running
multiple governor processes let each multiply budgets and hide delegations
from one another. This closes that gap the same way replay claims and
restriction state were already closed: SQLite schema v5, purely additive
(`live_authority`, `live_authority_agents`, `step_counters`), wired into
`ChainmailGovernor` whenever a `SQLiteStore` is configured.

Key guarantees (see `README.md`'s new "Durability" section and
`tests/test_authority_persistence.py`'s 17 tests for the adversarial
verification of each):

- A restart never restores surrendered authority or renews a consumed
  budget -- each agent's durable state is seeded from the envelope ceiling
  exactly once, tracked by an explicit initialization marker separate from
  whether the agent currently holds any permissions (so "zero permissions"
  is never mistaken for "never initialized").
- Budget consumption is a single atomic `UPDATE`, never check-then-write --
  two governor processes racing for the last unit of a budget: exactly one
  wins. This required moving the durable path's permission-budget
  consumption to *before* the execution boundary runs (right after quorum),
  not after, since the atomic UPDATE is the real cross-process enforcement
  point and must gate a real side effect rather than follow one; the
  non-durable in-memory path is unchanged.
- A policy/envelope change never resets consumed budget or restores
  delegated-away authority -- scoped by `(namespace, agent_id)` only, never
  by the envelope fingerprint, matching the replay/restriction precedent.
- `ChainmailGovernor.register_delegation`/`revoke_delegation` durably
  publish the new authority (atomic delete+reinsert) before mutating
  in-memory state; a durable-store failure fails the delegation closed.
- `GovernorConfig.production()` now also requires a real (non-permissive,
  non-absent) `execution_boundary` -- previously only signatures and
  durable storage were enforced, leaving `PermissiveExecutionBoundary` (or
  no boundary at all) able to silently authorise every `CONTINUE` even
  under a "production" config.
- New RiskSignals `AUTHORITY_STORE_UNAVAILABLE`, `STEP_STORE_UNAVAILABLE`
  for durable-store failures at their respective checks, distinct from the
  existing replay/restriction-store signals.
- `security_report()`'s `durable_authority_and_budgets` now reflects real
  state; the old unconditional "always in-memory" weakness is now
  conditional (mirroring replay/restrictions) plus a new always-present
  weakness scoped specifically to `provenance` (the human-readable
  delegation log, not authoritative state, which has no durable option).
- `demo_v5.py` now prints an explicit "DEVELOPMENT-ONLY DEMO -- REDUCED
  PROTECTION" banner naming exactly what it doesn't enforce, rather than
  relying solely on the governor's own startup log warning.
- `docs/DURABILITY.md`: a design spec (not implemented) for a keyed-
  authentication and rollback-checkpoint layer on top of this durability
  work -- what it would guarantee, what it explicitly cannot (rollback
  detection needs a *host-external* trusted checkpoint; a local key alone
  cannot bootstrap it), and why it's separate follow-on work. Paired with
  `tests/test_authority_integrity_spec.py`, skipped tests pinning down
  that design's "done" state for whoever implements it.

`tests/test_authority_persistence.py` (new, 17 tests): restart doesn't
restore authority or renew permission/step budgets; two/five governor
instances racing or hammering a budget concurrently never exceed it (25x
repeated with no flakiness); a failed atomic consumption or delegation
publish leaves state completely unchanged; corrupted or fully closed
storage fails closed; cross-namespace isolation; an agent cannot reach
another's budget via its own proposal fields; an envelope/fingerprint
change doesn't reset consumed budget; a delegator can't offer authority it
doesn't hold, and an unlimited offer is durably clamped to the recipient's
own ceiling across a restart; high-confidence contextual signals can't
grant authority an agent lacks; production mode requires durable authority
storage; and a v4 database upgrades to v5 without disturbing existing data.

### Fixed — Authority permission matching picked an arbitrary permission among overlapping matches (independent audit, P2)

`Authority._match()` returned the first permission in `self.permissions`
(a plain `Set[Permission]`) that `covers()` a required permission. More
than one permission can legitimately cover the same requirement -- e.g. a
wildcard-scope permission and a specific-scope one for the same name,
acquired through separate delegations. Set iteration order for objects
whose hash depends on strings varies with `PYTHONHASHSEED`, which Python
randomises per process by default: which permission "won" -- and therefore
which `max_budget`/remaining count governed `has_budget()` /
`consume_budget()` / `is_subset_of()` / `clamp_to_ceiling()` for that
requirement -- could differ between runs of the identical program with no
policy behind the difference.

Fix, in `src/chainmail/core.py`: `Authority._match()` now collects every
covering permission and, when there's more than one, deterministically
picks the most restrictive: a bounded (`max_budget` is not `None`)
permission always outranks an unbounded one, and among bounded matches the
smaller `max_budget` wins; remaining ties break on `(name, scope)`. Same
result every run, independent of hash seed or insertion order, and
fail-closed when genuinely ambiguous.

New tests in `tests/test_core.py`: the match is identical across both
insertion orders of an ambiguous {wildcard, specific} pair; a bounded
permission is preferred over an overlapping unbounded one; the smaller of
two bounded matches wins; and `has_budget()`/`consume_budget()` are shown
to actually use the deterministic match (exhausting the tight permission's
budget does not silently fall back to an overlapping wildcard).

### Fixed — a proposal's payload had no size/depth bound before signature verification and schema validation ran (independent audit, P2)

`Proposal.structural_problems()` -- checked at construction (`__post_init__`)
and re-checked by the governor for a proposal that reached it without going
through the constructor (e.g. over the wire) -- only verified `payload` was
a dict with string keys. No size, depth, or per-value bound existed. That
matters because `structural_problems()` runs *before* signature verification
(`_verify_signature` → `canonical_signing_bytes` → `json.dumps` on the
*entire* payload, signed or not, as long as `proposal.signature` is
non-empty) and before `ActionSchema.validate()`'s own nested-payload check --
so a deeply nested, very wide, or huge-string payload was fully serialised
or walked before anything got a chance to reject it. A bounded-effort DoS,
reachable by anyone who can get a `Proposal` to `evaluate()` (over the
service socket, or in-process).

Fix, in `src/chainmail/core.py`: new `_payload_within_limits()`, called from
`structural_problems()` right after the existing dict/string-key checks --
the earliest point in the pipeline, closing the gap regardless of whether a
signature is present. Bounds: max nesting depth 8 (checked directly, no
reliance on hitting Python's own recursion limit), max 10,000 total values
visited (a single shared counter, so deep-narrow, shallow-wide, and
many-medium-siblings shapes all hit the same ceiling), max string length
65,536, max payload-key length 256.

New `tests/test_core.py`: a normal payload is accepted; deep nesting, a wide
flat payload, a huge string value, many medium-sized list siblings (bounded
by the total node budget, not depth or single-value size), and an overlong
key are each rejected with the new message; and a proposal built via
`Proposal.__new__` (bypassing `__post_init__`) with a hostile payload is
still caught when the governor re-validates it in `evaluate()`.

### Fixed — the service accepted unlimited concurrent connections, one thread each (independent audit, P2)

`UnixSocketGovernorServer._accept_loop()` spawned a new daemon thread for
every accepted connection with no cap, and appended it to `_conn_threads`
which was never pruned. Any client that can reach the socket -- a buggy
integration retrying without backoff, or a malicious co-located process --
could exhaust server threads and file descriptors just by opening
connections and never closing them, and the never-pruned thread list leaked
memory over a long-running server's lifetime independent of that.

Fix, in `src/chainmail/service/server.py`: `UnixSocketGovernorServer` gained
a `max_connections: int = 128` constructor argument, enforced by a
`threading.Semaphore` acquired (non-blocking) before spawning each
connection's thread and released when that thread exits; a connection
beyond the cap is refused (closed immediately, logged) rather than
accepted. `_accept_loop()` now also prunes finished threads from
`_conn_threads` on every iteration instead of only ever appending to it.

New test `test_max_connections_caps_concurrent_connections` in
`tests/test_service.py`: with `max_connections=2`, a third concurrent
client is refused (`GovernorClientError`), and closing one of the first two
frees a slot for a new connection to succeed.

### Fixed — SQLiteStore silently accepted a newer, unrecognized schema version (independent audit, P2)

`SQLiteStore._init_db()` compared the database's stored `schema_version`
against `SCHEMA_VERSION` only to decide whether to *migrate forward*
(`row[0] < SCHEMA_VERSION`). A database with a *higher* stored version --
e.g. last written by a newer Chainmail release, then opened by an older one
after a downgrade, or two versions pointed at the same file -- fell through
unchecked into this code's `CREATE TABLE IF NOT EXISTS` / migration logic,
which has no knowledge of whatever shape a newer version introduced. That
risks silently misreading or corrupting data in an unrecognized shape
instead of refusing to start.

Fix, in `src/chainmail/persistence.py`: `_init_db()` now raises a new
`SchemaVersionError` (exported from `chainmail`) when the stored
`schema_version` exceeds `SCHEMA_VERSION`, naming both versions and telling
the operator to upgrade Chainmail or point at a different database, rather
than proceeding.

New test `test_sqlite_store_refuses_a_newer_schema_version` in
`tests/test_persistence.py`: creates a store at the current version, bumps
`schema_version` past it directly in the database, and asserts reopening
raises `SchemaVersionError`.

### Fixed — SQLiteStore defaulted to synchronous=NORMAL, a durability gap for a replay/restriction ledger (independent audit, P2)

`SQLiteStore` always set `PRAGMA synchronous=NORMAL`. With `journal_mode=WAL`
(also always set), NORMAL is a common, safe-against-corruption combination,
but it can still lose the most recently committed transaction(s) on an OS
crash or power loss between the WAL write and its checkpoint. For a store
whose whole purpose is durable replay-claim and restriction state --
`GovernorConfig.production()` requires it specifically so "a previously-
consumed signed proposal or nonce cannot become replayable again" -- that
gap is a real, if narrow, contradiction of the guarantee: a claim recorded
just before a crash could be gone on restart, silently re-opening a replay
window `production_mode` is supposed to close.

Fix, in `src/chainmail/persistence.py`: `SQLiteStore.__init__` gained a
`synchronous: str = "FULL"` keyword (validated to `FULL`/`NORMAL`/`OFF`),
applied via `PRAGMA synchronous=<value>`. **FULL is now the default** --
fsyncs on every commit, matching the durability the rest of the store
promises. Pass `synchronous="NORMAL"` explicitly to trade that for
throughput. The service CLI (`src/chainmail/service/server.py`) gained a
matching `--sqlite-synchronous {FULL,NORMAL,OFF}` flag (default `FULL`),
wired into its `SQLiteStore(...)` construction.

New tests in `tests/test_persistence.py`: synchronous defaults to `FULL`
(checked via `PRAGMA synchronous`, not just the stored attribute),
`synchronous="normal"` is honored (case-insensitively), and an invalid
value raises `ValueError` at construction. New tests in
`tests/test_service.py` cover the CLI flag: default and explicit `NORMAL`
both construct successfully, and an invalid value is rejected via
`argparse` (`SystemExit`), not a silent fallback.

### Fixed — HashChainLog.append() was not safe for multiple processes sharing one file (independent audit, P2)

`HashChainLog.append()` computed each new entry's `prev_hash` from its own
*in-memory* `self.entries`, and serialised concurrent appends only with a
`threading.RLock` -- scoped to one process. Two governor processes pointed
at the same `--hash-chain` file (a supported, documented configuration)
each track their own in-memory chain state; neither sees the other's
appends. Interleaved writes from two such processes produce a file where
some records' `prev_hash` doesn't match the record actually before them --
`verify()` on reload reports the chain broken, defeating the tamper-evidence
guarantee the log exists for. This reproduces with two plain `HashChainLog`
instances pointed at the same path, no real multiprocessing needed.

Fix, in `src/chainmail/persistence.py`: when a `filepath` is configured,
`append()` now takes an OS-level exclusive lock (`fcntl.flock`) on the file
for the read-then-write critical section, and reads the file's own last
line under that lock to determine `prev_hash` -- the file, not in-memory
state, is the source of truth for what the chain's tip actually is. If
another process appended entries this instance never loaded, it reloads
the full chain after writing so its own `entries`/`verify()` stay
consistent with what's on disk. The no-`filepath` (pure in-memory) path is
unchanged. Entry construction is factored into `HashChainLog._build_entry`,
shared by both paths.

New test `test_two_independent_instances_sharing_a_file_produce_a_valid_chain`
in `tests/test_persistence.py`: two independent `HashChainLog` instances
(simulating two processes) interleave appends to the same file; a fresh
reload verifies the resulting 4-entry chain is valid and in write order.

### Fixed — security_report() called a quorum "configured" even with no real peer transport (independent audit, P2)

`security_report()`'s `quorum_configured` was `self.quorum is not None` —
true the moment a caller passes `quorum=QuorumAggregator()`, regardless of
`quorum_transport`. The default `quorum_transport` is
`LocalSingleGovernorTransport`, which just echoes the evaluating governor's
own vote back to itself; `QuorumAggregator.aggregate()` still requires
unanimity to pass, so it isn't a no-op, but it is nowhere close to the
peer-governor review the report implied by calling quorum "configured" with
no accompanying weakness.

Fix, in `src/chainmail/governor.py`: `security_report()` now distinguishes
"quorum configured with a real peer transport" from "quorum configured with
only the echo transport" (new `quorum_has_peer_transport` field). The latter
adds a `weaknesses` entry naming `LocalSingleGovernorTransport` explicitly
and explaining the unanimity-of-one behavior, instead of reporting no
weakness at all.

`tests/test_governor.py::test_security_report_clears_weaknesses_when_hardened`
now wires a `StaticPeerTransport` with a peer vote (a "hardened" governor
should have a real peer transport, not just an aggregator) and asserts
`quorum_has_peer_transport is True`. New test
`test_security_report_flags_quorum_with_only_echo_transport` covers the
previously-unreported case directly.

### Fixed — the service CLI always started a dev-mode governor, silently (independent audit, P2)

`python -m chainmail.service.server` unconditionally built `ChainmailGovernor
(build_demo_envelope(), config=GovernorConfig(), ...)` — the built-in demo
envelope and a non-production config with `require_signature=False` — no
matter what flags an operator passed. Following the README's own example
(`--socket ... --sqlite ... --hash-chain ...`) got you a durable audit trail
wrapped around a governor that verified no signatures and enforced the demo
app's objective/permission set, not your deployment's. The only signal
anything was off was an internal `logger.warning` call, easy to miss at
default log levels.

Fix, in `src/chainmail/service/server.py`:
- New `--production` flag builds `GovernorConfig.production()` instead of
  `GovernorConfig()`. It requires `--sqlite` and at least one signing key
  (new `--hmac-key kid:agent_id:hex_secret` / `--ed25519-pubkey
  kid:agent_id:path_to_pem`, both repeatable) — missing either is a clear
  `argparse` error, not a silent fallback or the governor's generic
  `ValueError`.
- New `_build_verifier()` turns those key flags into a `CompositeVerifier`
  (`KeyRegistry`-backed), wired into the governor as `verifier=`.
- The demo envelope's default `RestrictPolicy.TTL_STEPS` is incompatible with
  `production_mode` (step-based expiry isn't durable/multi-process-safe, per
  the P1 #8 fix) — `--production` now swaps it to `TTL_WALLCLOCK` so the flag
  is actually usable without a hand-built envelope; a real deployment should
  still supply its own `AuthorityEnvelope`.
- Without `--production`, the CLI now prints an explicit warning to stderr
  (not just the internal logger) naming exactly what's not enforced.
- `main()` gained a private `_block=` parameter (defaults to the real
  `threading.Event().wait()`) purely so tests can make it return without
  patching the shared `threading.Event` class.

New tests in `tests/test_service.py`: `_build_verifier` returns `None` with no
keys, builds a working `CompositeVerifier` from an HMAC spec, and raises
`SystemExit` on a malformed spec; `--production` without `--sqlite` and
without a key both raise `SystemExit`; and an end-to-end CLI test asserting
the dev-mode warning prints without `--production` and does not print with
`--production --sqlite ... --hmac-key ...` (which must construct
successfully). README's service example updated to show `--production`.

### Fixed — the mutation harness could execute real actions and misreport invariant coverage (independent audit, P1 #12)

`MutationRunner.run()` evaluated every mutant against whatever governor the
caller's factory built, with whatever `execution_boundary` that factory
wired in -- a factory built for production use, with a real boundary,
would let a mutant that survives every earlier check actually execute. And
`killed` was computed as `result.decision in mut.accepted`: any
non-`CONTINUE` decision counted as a kill, regardless of *why* the governor
objected. A mutant caught for the wrong reason (a governor-wide gate like
`SIGNATURE_MISSING`, or -- concretely -- a `hard_denial` mutant landing on
`UNKNOWN_ACTION` instead of `AUTHORITY_ABUSE` when the envelope's
`allowed_actions` allowlist excludes every hard-denied action) read as
"killed," inflating the reported invariant coverage without the invariant
ever actually being exercised. Cloned mutants also carried no signature,
so under `require_signature=True` every mutant would be killed by
`SIGNATURE_MISSING` alone, masking whether the targeted invariant held.

Fix, in `src/chainmail/evaluation.py`:
- `MutationRunner.run()` now forcibly replaces `gov.execution_boundary`
  with a new internal `_DenyAndRecordBoundary` on every governor it builds,
  regardless of what the factory wired in. It always denies and records
  whether it was reached (`MutationOutcome.execution_attempted`), so this
  harness can never cause a real side effect no matter what governor it is
  handed.
- `Mutation` gained `expected_signals: Optional[Set[RiskSignal]]`, populated
  for every mutation in `standard_mutant_family()`. `killed` is now
  `decision in accepted AND (expected_signals is None OR signals intersect
  expected_signals)` -- a mutant caught for the wrong reason is reported as
  a survivor.
- `standard_mutant_family()` no longer includes a `hard_denial` mutation
  when no hard-denied action is reachable under the envelope's
  `allowed_actions` (previously it could silently target an action that
  would be rejected as `UNKNOWN_ACTION` instead, testing the wrong
  invariant).
- `MutationRunner` gained an optional `resign: Optional[Callable[[Proposal],
  Proposal]]` constructor argument, applied to every built/primed mutant
  and to `prime`'s replay/duplicate-proposal setup calls (`Mutation.prime`
  now takes `(governor, proposal, resign)`), so a family can be run
  correctly against a governor with `require_signature=True`.

New tests in `tests/test_evaluation.py`:
`test_hard_denial_mutation_skipped_when_unreachable_via_allowlist`,
`test_harness_never_lets_execution_reach_a_real_boundary` (asserts an
exploding real boundary is never invoked),
`test_signal_specificity_catches_a_family_that_targets_the_wrong_signal`,
and `test_resign_is_threaded_through_mutants_and_primers` (runs the
standard family against a `require_signature=True` governor and asserts no
mutant is killed by `SIGNATURE_MISSING`).

### Fixed — the v2→v3 replay migration dropped claim history instead of preserving it (independent audit, P1 #11)

The v2→v3 migration (narrowing nonce/proposal-ID uniqueness to no longer
include `envelope_fingerprint`, landed earlier in this Unreleased section)
handled a pre-v3 replay table by dropping it outright and letting it be
recreated empty. That's exactly backwards for a replay ledger: silently
losing claim history across a migration means a previously-consumed signed
proposal or nonce becomes replayable again the moment someone upgrades.

Fix: a pre-v3 replay table is now renamed out of the way
(`_rename_pre_v3_replay_tables`), the v3-shaped table created fresh, and
every row copied forward into the new columns
(`_migrate_replay_data_from_v2`) before the old table is dropped. v2's
`scope` string embedded `namespace` alongside `envelope_fingerprint` and
`agent_id`/`proposal_id`, which were already separate columns even in v2 --
so `namespace` is recovered exactly by stripping that known suffix, not
guessed. Because v3's uniqueness boundary is narrower (no longer includes
`envelope_fingerprint`), multiple v2 rows for the same nonce can collapse
onto one v3 row; migration uses `INSERT OR IGNORE` to tolerate that rather
than crash on the resulting conflict -- correctly, since they all represent
the same already-consumed identifier.

`test_existing_v2_scope_based_database_migrates_safely` now asserts the
old claim is still rejected as a replay after migrating, not just that the
new schema is usable. New test
`test_v2_rows_collapsing_under_v3_scope_do_not_crash_migration` covers the
collapse case directly.

### Fixed — delegation mutated live state before its audit write succeeded (independent audit, P1 #10)

`register_delegation()` set `self.live_authority[to_agent]` and appended to
`self.provenance` *before* attempting the audit write. A failed write
returned `(False, "delegation audit write failed; delegation not
recorded")` -- but the delegation was, at that point, already live: the
message was false.

Fix: reordered so the audit write is attempted first, using the already-computed
`new_auth` (a pure computation with no side effects, so there is nothing to
roll back). `live_authority` and `provenance` are only mutated after a
successful (or inactive) audit write; on failure, the delegation is never
published at all, matching the returned message. New test
`test_delegation_audit_failure_leaves_no_live_state_change`: a
`FailingAuditSink` forces the write to raise; confirms `live_authority`
and `provenance` are byte-for-byte unchanged from before the call.

### Changed — security_report() always names process-local authority/budget state as a weakness (independent audit, P1 #9)

`live_authority` (delegated authority), permission budgets, fleet/per-agent
step budgets, and provenance are still process-local: a restart resets
delegated authority to the envelope ceiling and renews all budgets, and
running multiple governor processes multiplies budgets and lets one
process's delegation be invisible to another's. Unlike replay protection and
restrictions, there is currently no durable-storage option for any of this
-- wiring a `SQLiteStore` into `AuditSink` does not change it -- and
`production_mode=True` does not (yet) refuse to start without it, so a
security report reading "no weaknesses" could previously be read as "safe to
run this way in production," which it is not.

This is a transparency fix, not new durability: full persistence
(atomic claim/consume operations for budgets, durable delegated authority)
is real future work, tracked in HANDOFF.md's roadmap alongside `live_authority`,
same as before. `security_report()` now unconditionally includes this in
`weaknesses` (it cannot be cleared by any current configuration) and reports
a new `durable_authority_and_budgets: False` field for programmatic checks.
Existing tests updated: "fully hardened" no longer means zero weaknesses --
it means every weakness that *can* currently be addressed has been.

### Fixed — production mode allowed TTL_STEPS restrictions, unsafe across processes (independent audit, P1 #8)

A `TTL_STEPS`-policy restriction's expiry is (deliberately, per the durable
restrictions changelog entry above) an absolute step number compared against
the *evaluating governor's own local* `step_count` -- that counter is
per-process, not durable, and not shared. In a multi-process deployment
(exactly what `production_mode` + durable storage exists for), a second
governor process with a different, often higher, local `step_count` can read
a sibling's still-active restriction and treat it as already expired,
silently lifting a restriction the operator believes is still in force.

Fix: `ChainmailGovernor.__init__` now rejects `production_mode=True`
combined with `envelope.restrict_policy == RestrictPolicy.TTL_STEPS` at
construction time, matching this codebase's existing production-mode
fail-closed pattern. `TTL_WALLCLOCK` (an absolute timestamp -- safe across
processes and restarts, since wall-clock time is shared) and `HUMAN_ONLY`
remain available for production; `TTL_STEPS` is still fine for a
single-process development `GovernorConfig()`, where there's no sibling
process to disagree with. Two existing production-mode tests
(`test_production_config_requires_durable_replay_storage`,
`test_production_mode_requires_durable_restriction_storage`) constructed
their governor with the demo envelope's default `TTL_STEPS` policy and now
use `TTL_WALLCLOCK` so they isolate the check they're actually testing. New
test `test_production_config_rejects_ttl_steps_restrictions`.

### Fixed — active restrictions removed authority by exact equality, not coverage (independent audit, P1 #7)

`_effective_authority()` computed `base.reduce_to(base.permissions - active)`
-- a plain set difference, which requires exact `Permission` equality (name,
scope, *and* `max_budget`) to remove anything. A restriction is recorded
against whatever `Permission` the restricted proposal declared
(`required_permission`), which need not be object-identical to the base
authority's actual stored permission for that name/scope. Confirmed with a
direct reproduction before fixing: restricting `agent_deploy` on
`deploy:staging` (declared with `max_budget=None`) left
`_effective_authority()` still granting the base authority's actual
`deploy:staging` permission (`max_budget=5`) -- the restriction had no
effect at all whenever the two objects differed in any field.

Fix: removal now uses the same name/scope *coverage* relation
(`Permission.covers`) used to grant authority in the first place, not exact
equality -- a base permission is dropped if it covers any actively
restricted requirement, regardless of budget metadata differences. Two
pre-existing tests (`test_bug4_budget_survives_restrict`,
`test_budget_not_consumed_on_non_continue`) were *accidentally* relying on
the bug: they used `make_permission("deploy", "staging")` (unmetered)
against `agent_deploy`'s actual metered permission and expected repeated
`RESTRICT` on the same permission, which only "worked" because the
restriction was silently not applying. Updated to assert the correct
behaviour: after a restriction, the next attempt at that permission is
blocked outright (`AUTHORITY_ABUSE`), not `RESTRICT`ed again as if nothing
happened -- with budget still untouched either way. New dedicated test
`test_restriction_removal_uses_coverage_not_exact_equality` isolates the
mechanism directly against `_effective_authority()`.

### Fixed — delegation budget containment ignored `max_budget`, and trusted a caller-supplied `budget_remaining` (independent audit, P0 #4 and #5)

`Permission.covers()` only compares `name`/`scope` -- by design, it exists to
find "the applicable permission entry", not to answer "is this contained
within that entry's budget". But `Authority.is_subset_of()` (delegation's
does-the-delegator-actually-hold-this check) and the recipient-envelope
reduction step in `register_delegation()` both used `covers()` as their only
containment test. Confirmed before fixing: an agent holding
`deploy:prod max_budget=1` could delegate `deploy:prod max_budget=None`
(unlimited) of the same name/scope, and `is_subset_of()` accepted it outright
-- turning a budget-bounded permission into unlimited authority purely by
relabelling its ceiling during delegation (P0 #4). Separately, an offered
`Authority`'s `budget_remaining` dict is caller-supplied data (e.g. via the
service layer), and the recipient-ceiling reduction step copied it through
uninspected -- an offer of `max_budget=1, budget_remaining=999` was accepted
and the `999` preserved (P0 #5).

Fix:
- `Authority.is_subset_of()` now also requires the claimed `max_budget` (and,
  when metered, the claimed remaining -- clamped to never exceed the
  claiming side's own ceiling first) to not exceed the source authority's
  own ceiling and remaining. An unmetered (`max_budget=None`) claim is never
  a subset of a metered source.
- New `Authority.clamp_to_ceiling()` replaces the unclamped `reduce_to()`
  call used for the recipient-envelope reduction step in
  `register_delegation()`. Unlike `reduce_to` (still used unchanged for
  restrictions, where it reduces an authority to a subset of its *own*
  permission objects), `clamp_to_ceiling` constructs new, independently
  budget-capped `Permission` objects against a *different* authority's
  ceiling, and computes the granted remaining itself rather than copying any
  stored value beyond that cap.

New tests (`tests/test_governor.py`):
- `test_delegation_cannot_launder_bounded_into_unlimited`: a delegator
  limited to `max_budget=1` attempts to delegate `max_budget=None` of the
  same permission; delegation is now rejected ("does not hold").
- `test_delegation_ignores_injected_remaining_budget`: an offer with
  `max_budget=1, budget_remaining=999` results in the recipient receiving
  `max_budget=1` and a remaining count that never exceeds it.

### Fixed — a caller-held proposal object could be mutated after verification and before execution (independent audit, P0 #3)

`Proposal` is a mutable dataclass (`sign_proposal()` itself mutates
`.nonce`/`.signature` in place). `evaluate()` operated on the exact object
the caller passed in, from the first check through to
`execution_boundary.execute()`, holding no copy of its own. Anything with a
live reference to that object -- a caller on another thread, or (as
demonstrated in the new test) a hostile pluggable component like an
embedding engine's `similarity()` hook that legitimately runs partway
through evaluation -- could mutate `payload` (e.g. a verified filesystem
path) after schema/traversal validation had already passed it, and the
execution boundary would receive the mutated value instead of what was
checked.

Fix: `_evaluate_locked()` now deep-copies the incoming proposal as its very
first action, before any check runs, and every subsequent check, the audit
log, and the execution boundary all operate on that snapshot. Nothing the
caller (or a mid-evaluation hook) does to the original object afterward can
reach a check or the executor. New test
(`test_post_verification_mutation_cannot_reach_execution` in
`tests/test_governor.py`): a hostile embedding engine mutates a verified
`"file": "repo/src/main.py"` payload to `"../../etc/passwd"` mid-evaluation;
confirms the execution boundary still receives `"repo/src/main.py"`.

### Fixed — proposal signature didn't bind confidence or assumptions (independent audit, P0 #2)

`Proposal.signing_dict()` omitted `confidence` and `assumptions`, even though
`confidence` alone decides `CONTINUE` vs `RESTRICT` (`low_confidence_max`),
feeds `ASSUMPTION_ANOMALY`, and factors into re-entry risk. Confirmed before
fixing: `signing_dict()` at core.py:361-377 genuinely excluded `confidence`. A
validly-signed proposal could have its `confidence` (or `assumptions`)
changed after signing without invalidating the signature. Both fields are now
included in the canonical signing payload. New tests
(`test_confidence_is_signed_not_forgeable`,
`test_assumptions_are_signed_not_forgeable` in `tests/test_crypto.py`): sign
at low confidence, mutate upward without resigning, confirm
`SIGNATURE_INVALID`; same for an injected assumption.

### Fixed — service authentication was not authorization (independent audit, P0 #6)

`UnixSocketGovernorServer._authenticate()` resolved a token to a caller
label, but `_serve_conn()` never passed that label into `_dispatch()` --
confirmed by reading server.py directly. Any authenticated caller, holding
any valid token, could call `register_delegation` with an arbitrary
`from_agent`, `revoke_delegation` for any agent, `snapshot` (full fleet
state), and `suggest_envelope`, regardless of which credential they held.

Fix: authenticated tokens now resolve to a `CallerIdentity(label, agent_id,
admin)` instead of a bare label string, and `_dispatch()` enforces
operation-level authorization against it:
- `register_delegation` requires the caller's `agent_id` to match the
  request's `from_agent`, or admin authority.
- `revoke_delegation`, `snapshot`, and `suggest_envelope` require admin
  authority -- fleet-wide administrative operations, not something any
  authenticated caller should reach by naming an agent in the request body.
- `ping`/`evaluate` are unaffected -- `evaluate` already has its own
  protection layer (known-agent check, signature verification when
  configured), and requiring caller/proposal agent identity to match here
  would break legitimate proxy/orchestrator deployments using one shared
  credential; the auth gap being fixed is specifically the admin/delegation
  surface that has no other layer of defense.
- Backward compatible: a plain string value in `auth_tokens` (the prior
  API) is still accepted, as shorthand for a label-only identity with *no*
  delegation or admin authority -- existing deployments regain those
  operations only by explicitly granting them per token, which is the
  intended direction for this fix (fail closed by default). The single-token
  `auth_token=` constructor shorthand keeps full admin authority unchanged,
  since it represents the one trusted local-operator credential, not a
  per-caller-scoped token.

New tests (`tests/test_service.py`): a label-only token can `ping`/`evaluate`
but gets `unauthorized` on all four admin/delegation ops; a token bound to
one `agent_id` can delegate as that agent but not impersonate another, and
still can't reach admin ops; an explicit admin `CallerIdentity` retains full
access; the single-token shorthand keeps its existing full-trust behaviour.

### Fixed — quorum ran after execution, not before it (independent audit, P0 #1)

`ChainmailGovernor.evaluate()` called `execution_boundary.execute()` (step 15)
*before* collecting and aggregating quorum votes (step 16). A peer governor's
`HUMAN` veto still produced a `HUMAN` final decision, but only after the real
side effect had already run through the execution boundary — the veto arrived
too late to prevent anything. Reordered: quorum is now collected and
aggregated first; the execution boundary only runs once quorum (when
configured) has also agreed to `CONTINUE`. New tests in `tests/test_quorum.py`
assert the execution boundary is never invoked when a peer vetoes, and that
execution strictly follows quorum in the CONTINUE case too (not just by
coincidence of the same final decision).

Response to the independent technical assessment's Priority 0 finding
("Secure Behaviour Should Be the Default"): the permissive defaults needed
for local development and testing were silent about the protections they
were skipping.

### New

- `GovernorConfig.production(**overrides)` — a secure-by-default config
  factory. Currently differs from `GovernorConfig()` only in
  `require_signature=True`; other fields still override.
- `ChainmailGovernor.security_report()` — reports which protections are
  actually active on a governor instance (signature enforcement, a real vs.
  permissive execution boundary, quorum configuration) and lists concrete
  weaknesses for anything left permissive. Logged automatically at
  construction: `INFO` when nothing is weak, `WARNING` naming each gap
  otherwise.
- `ChainmailGovernor.__init__` now fails closed at construction time if
  `config.require_signature=True` is paired with a `NullApprovalVerifier`
  (explicit or defaulted) — that combination would enforce signature
  *presence* while accepting any signature *content*, which is a false
  sense of security. A real verifier (e.g. `CompositeVerifier`) must be
  supplied.
- `PermissiveExecutionBoundary` (renamed from `MockArmourBoundary` — see
  below) now logs a construction warning, matching `NullApprovalVerifier` —
  it authorises every `CONTINUE` decision unconditionally and previously did
  so silently.

### Changed — decoupled from Armour naming

Chainmail and Armour are independent sibling projects (see HANDOFF.md §8/§9);
Chainmail must not carry Armour-specific identifiers in its own public API.
`chainmail.armour` never depended on the Armour *project* (it was always a
generic seam), but its naming implied a coupling that didn't exist. Renamed,
with no change in behaviour:

- Module `chainmail.armour` -> `chainmail.execution_boundary`.
- `ArmourBoundary` -> `ExecutionBoundary`.
- `MockArmourBoundary` -> `PermissiveExecutionBoundary`.
- `DenyAllArmourBoundary` -> `DenyAllExecutionBoundary`.
- `ChainmailGovernor(..., armour=...)` constructor kwarg -> `execution_boundary=...`;
  `governor.armour` attribute -> `governor.execution_boundary`.
- `GovernanceResult.armour_output` -> `GovernanceResult.execution_output`;
  same field rename in `AuditSink.record_proposal()` and the hash-chain audit
  record.
- `security_report()` keys `armour` / `armour_wired` -> `execution_boundary` /
  `execution_boundary_wired`.
- `GuardedExecutorAdapter` is unchanged (its name was already generic) but its
  docstring no longer names Armour as the thing it wraps — it wraps any
  compatible `(proposal, authority) -> (ok, message, output)` callable.

### New — durable nonce / proposal-ID replay protection

Response to Priority 1 ("Durable Governance State") from the independent
technical assessment, scoped to nonces and proposal IDs only (restrictions
and budgets are unchanged, tracked separately). Previously, `_seen_nonces`
and `_seen_proposal_ids` lived only in process RAM: a restart silently
dropped replay protection, and nothing prevented two governor processes
sharing one SQLite database from both accepting the same identifier.

- `SQLiteStore` schema at v3: `replay_nonces` (`UNIQUE (deployment_namespace,
  agent_id, nonce)`) and `replay_proposal_ids` (`UNIQUE (deployment_namespace,
  proposal_id)`) — explicit columns, not a constructed `scope` string, so the
  uniqueness boundary is inspectable directly in the schema. `key_id` and
  `envelope_fingerprint` are stored as audit metadata columns only; neither
  is part of either `UNIQUE` constraint (see "Documented scope" below for
  why). An older database (v1, or the short-lived v2 `scope`-column shape)
  is migrated in place the next time it's opened: `proposals`/`delegations`
  rows are always preserved; a pre-v3 `replay_nonces`/`replay_proposal_ids`
  table is dropped and rebuilt in the new shape (that data was only ever
  claim history, not proposal history, and predates the corrected scope).
- `SQLiteStore.claim_nonce()` / `claim_proposal_id()` — a claim is a single
  atomic `INSERT`; there is no separate check-then-insert. A `UNIQUE`
  conflict (`sqlite3.IntegrityError`) *is* the replay signal, so two
  governor processes racing on the same identifier against a shared
  database cannot both win. Any other `sqlite3.Error` propagates to the
  caller as a persistence failure, not a "not a replay" result.
- When a `ChainmailGovernor` is constructed with a `SQLiteStore` wired into
  its `AuditSink`, nonce and proposal-ID claims become durable
  automatically — no extra opt-in. Without one, behaviour is unchanged
  (in-memory only), and `security_report()` now flags that as a weakness.
- `GovernorConfig.production()` now also sets `production_mode=True`, which
  `ChainmailGovernor.__init__` enforces at construction: production mode
  requires *both* a real `ApprovalVerifier` (already enforced) *and* durable
  replay storage (a `SQLiteStore` wired into `AuditSink`) — construction
  raises `ValueError` otherwise rather than silently falling back to
  in-memory-only protection. Development configs (plain `GovernorConfig()`)
  are unaffected and may still use the in-memory fallback.
- Claims happen only *after* a proposal's signature (if any) is verified,
  so an attacker who cannot forge a valid signature can never claim (and so
  can never poison) an identifier a legitimate, correctly-signed proposal
  will need later.
- Consumption is unconditional: a claimed nonce/proposal-ID stays consumed
  even if the proposal's final decision is `RESTRICT`/`RECHECK`/`HUMAN`
  rather than `CONTINUE` — there is no path that returns a claimed
  identifier. Retrying requires a new proposal with a new nonce.
- Fail-closed: if the durable store cannot commit a claim (disk full,
  locked, corrupt, ...), the governor returns `HUMAN` /
  `REPLAY_STORE_UNAVAILABLE` — never `CONTINUE` — and best-effort records
  the failure to the hash-chain log if one is configured.
- An in-memory LRU cache still front-runs the durable store for speed (a
  cache hit is always backed by a prior durable claim, so it's safe to
  trust; a cache miss always falls through to the atomic DB claim — cache
  eviction never weakens the guarantee).
- Documented scope: nonce uniqueness is **per agent** (`deployment_namespace`
  + `agent_id` + `nonce` — not `key_id`, so a nonce stays blocked across that
  agent's key rotation). Proposal-ID uniqueness is **fleet-wide**
  (`deployment_namespace` + `proposal_id`), matching the pre-durability
  in-memory behaviour. Neither includes the envelope/policy fingerprint:
  replay protection identifies whether a *signed request* has already been
  submitted, and a policy/envelope update must never make an earlier signed
  proposal replayable again — an attacker holding one could otherwise retry
  it simply by waiting for (or triggering) a policy change. New
  `ChainmailGovernor(..., deployment_namespace="default")` constructor
  parameter lets multiple deployments share one physical database file.
- The non-durable in-memory nonce cache is now also scoped per agent (it
  previously was not, which was inconsistent with the documented durable
  scope and could over-block two different agents that happened to pick the
  same nonce string).
- New `RiskSignal.REPLAY_STORE_UNAVAILABLE`.
- 14 tests in `tests/test_replay_persistence.py` (+1 in `test_crypto.py` for
  production-mode enforcement): survival across a simulated restart
  (separate `SQLiteStore` instances over the same file), two governors
  racing on one nonce, an invalid signature failing to poison a nonce, a
  forced persistence failure never reaching `CONTINUE`, migration of both a
  hand-built v1 database and a hand-built v2 (`scope`-column) database,
  cache eviction not weakening protection, unconditional consumption on a
  non-`CONTINUE` decision, and the documented scope end to end (per-agent
  nonces, fleet-wide proposal IDs, survival across both key rotation *and* a
  genuine envelope/policy change).

### New — durable restriction state

Continues Priority 1 ("Durable Governance State"), scoped to restrictions
only -- STEP_BUDGET restrictions and general permission/fleet budgets remain
in-memory and are tracked separately. Previously `self.restricted` lived only
in process RAM: a restart silently lifted every active restriction, and
nothing let two governor processes sharing a database observe restrictions
imposed by one another.

- `SQLiteStore` schema at v4: `restrictions` (current-state, one row per
  `restriction_id`, `status` one of `ACTIVE`/`CLEARED`/`EXPIRED`, updated in
  place and never deleted) and `restriction_events` (append-only log of
  every `IMPOSED`/`CLEARED`/`EXPIRED` transition, for investigation after a
  restriction is cleared). `SQLiteStore.impose_restriction()` /
  `active_restrictions()` / `mark_expired()` / `clear_restriction()` /
  `restriction_history()`.
- Scope is `(deployment_namespace, agent_id)` -- deliberately independent of
  `envelope_fingerprint` and any signing key: a restriction is a consequence
  of an agent's behaviour, and a policy update, envelope change, or key
  rotation must not silently lift it. `envelope_fingerprint` is still
  recorded as metadata (the policy version active when imposed / cleared).
- When a `ChainmailGovernor` is constructed with a `SQLiteStore` wired into
  `AuditSink`, restrictions become durable automatically -- same trigger as
  durable replay protection, since both use the same store. Without one,
  behaviour is unchanged (in-memory only, per-process), and
  `security_report()` flags that as a weakness (`durable_restriction_protection`).
- No `__init__`-time load and no in-memory cache for the durable path:
  `evaluate()` asks the store fresh every time via `active_restrictions()`,
  so a restriction imposed or cleared by *any* governor process sharing the
  store is observed on the very next call by every other one -- not just
  after a restart.
- Persist-before-return: imposing a restriction commits to the store (in the
  same transaction as its `IMPOSED` event) *before* `evaluate()` returns.
  If that commit fails, the decision is downgraded to `HUMAN` /
  `RESTRICTION_STORE_UNAVAILABLE` and the in-memory mirror is never touched
  -- a restriction is never reported as imposed when it exists only in
  memory. A failure reading restrictions (not just writing) also fails
  closed the same way, rather than silently proceeding as unrestricted.
- `ChainmailGovernor.clear_restriction(agent_id, restriction_id, *,
  authorised_by, reason="")` -- the only way to lift a durable restriction
  early. Bound to the exact `(agent_id, restriction_id)` pair, so releasing
  one restriction can never affect another, and a stale/replayed release
  naming an old (already-cleared) `restriction_id` cannot clear a different,
  newer restriction imposed since. Idempotent (`"already_cleared"` on a
  repeat). `authorised_by` and `reason` are recorded on the restriction row
  and in `restriction_events`, along with the clearing governor's current
  envelope fingerprint as `cleared_policy_version`.
- `GovernorConfig.production()` / `production_mode` now also cover
  restrictions: since both replay protection and restriction storage are
  backed by the same `SQLiteStore`, the existing construction-time check
  (durable storage required) already enforces this -- the error message now
  says so explicitly.
- Existing expiry semantics only, not extended: `TTL_WALLCLOCK` stores an
  absolute timestamp (durable and restart-safe by construction).
  `TTL_STEPS` stores an absolute step number and is still compared against
  the *evaluating governor's own* `step_count`, exactly as before -- no
  cross-process step synchronisation is invented here. `STEP_BUDGET`
  (`_restrict_budgets`, a decrementing counter) is explicitly out of scope
  for this commit and remains in-memory-only, deferred to a future budget
  durability commit.
- New `RiskSignal.RESTRICTION_STORE_UNAVAILABLE`.
- 13 new tests in `tests/test_restriction_persistence.py`: restart survival,
  survival across both an envelope change and a key rotation, a second
  governor observing a restriction imposed by the first, a forced write
  failure and a forced read failure each failing closed, clearing surviving
  restart, idempotent clearing, a stale release unable to touch a newer
  restriction, clearing rejected for the wrong agent, history surviving
  clearing, v3->v4 schema migration, development-mode behaviour unchanged,
  and production mode requiring durable restriction storage.

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
