"""
Chainmail v5 --- persistence and audit.

Two stores, composed by ``AuditSink``:

* ``HashChainLog``  -- append-only, SHA-256 hash-chained, fsync'd JSONL. The
  tamper-evidence layer. v5 fixes: ``verify()`` is non-destructive, records are
  versioned, the file is re-loaded and re-verified on startup, and ``verify()``
  reports a 0-based ``failed_record``.
* ``SQLiteStore``   -- WAL-mode SQLite with indices, a ``schema_version`` table,
  and a ``prune`` retention hook. The queryable source of truth that feeds
  ``suggest_envelope()``.

``AuditSink.record_*`` writes to both. Any failure raises -- the governor treats
an audit-write failure as fail-closed (escalate to HUMAN, do not execute).
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Set, Tuple

from .redaction import scrub_pii

logger = logging.getLogger(__name__)

RECORD_VERSION = 1
GENESIS_HASH = "0" * 64
LEDGER_GENESIS = "0" * 64


# ============================================================================
# Sanitisation (bounded, cycle-safe)
# ============================================================================

def sanitize(value: Any, *, depth: int = 0, seen: Optional[Set[int]] = None) -> Any:
    if seen is None:
        seen = set()
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return scrub_pii(value[:4096])
    if depth >= 8:
        return "<max-depth>"
    identity = id(value)
    if identity in seen:
        return "<cycle>"
    if isinstance(value, dict):
        seen.add(identity)
        result = {
            str(k)[:256]: sanitize(v, depth=depth + 1, seen=seen)
            for k, v in list(value.items())[:100]
        }
        seen.discard(identity)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        seen.add(identity)
        result = [sanitize(item, depth=depth + 1, seen=seen) for item in list(value)[:100]]
        seen.discard(identity)
        return result
    try:
        rendered = repr(value)
    except Exception:  # noqa: BLE001
        rendered = f"<{type(value).__name__}>"
    return rendered[:4096]


# ============================================================================
# Hash-chained append-only log
# ============================================================================

@dataclass(frozen=True)
class ReceiptVerification:
    valid: bool
    verified_records: int
    failed_record: Optional[int] = None   # 0-based index of the first bad record
    reason: Optional[str] = None
    last_valid_hash: str = GENESIS_HASH

    def __bool__(self) -> bool:
        return self.valid


class ReceiptIntegrityError(ValueError):
    """Raised when an append would extend a damaged receipt chain."""


class SchemaVersionError(ValueError):
    """Raised when a SQLiteStore database's schema_version is newer than this
    code's SQLiteStore.SCHEMA_VERSION -- opening it would risk misreading or
    corrupting a shape this code has no knowledge of."""


class RowIntegrityError(sqlite3.Error):
    """Raised when a durable row's keyed MAC does not match its own
    contents, or a row that must be authenticated has no usable MAC/key_id
    at all (a legacy row from before authentication was enabled, or a
    key_id no ``KeyProvider.get`` can resolve). This is exactly the
    keyed-authentication guarantee described in docs/DURABILITY.md: a row
    edited directly, replaced, or inserted without going through
    ``SQLiteStore``'s own write API fails verification here.

    Deliberately a subclass of ``sqlite3.Error``: every call site in
    ``ChainmailGovernor`` that reads durable authority state already wraps
    the call in ``except sqlite3.Error`` and fails closed (HUMAN,
    AUTHORITY_STORE_UNAVAILABLE) -- a row that fails its MAC is exactly as
    untrustworthy as a store that raised a disk-I/O error, so it is treated
    the same way rather than needing its own exception-handling path
    threaded through the governor.
    """


class KeyProvider(Protocol):
    """The external MAC key used to authenticate durable rows (see
    docs/DURABILITY.md). Never implement this by storing the key inside the
    same SQLite file it protects -- an environment variable, an OS keyring
    entry, or an external KMS are the intended sources.
    """

    def current(self) -> Tuple[str, bytes]:
        """Return ``(key_id, key_bytes)`` to use for new/refreshed MACs."""
        ...

    def get(self, key_id: str) -> Optional[bytes]:
        """Resolve the key bytes previously used under ``key_id`` (so rows
        written before a rotation still verify). Return ``None`` if this
        ``key_id`` is unknown -- the caller must treat that as verification
        failure (fail closed), never as "unauthenticated, trust it"."""
        ...


class InMemoryKeyProvider:
    """A minimal, process-local ``KeyProvider`` -- keys live only in this
    object's memory, never written to the SQLite file. Suitable for tests
    and single-process deployments; a real deployment wanting the key to
    survive a process restart (so rotated-out keys can still verify old
    rows) must supply its own ``KeyProvider`` backed by a keyring, env var,
    or KMS, per docs/DURABILITY.md.
    """

    def __init__(self, key_id: str, key: bytes) -> None:
        self._current_id = key_id
        self._keys: Dict[str, bytes] = {key_id: key}

    def current(self) -> Tuple[str, bytes]:
        return self._current_id, self._keys[self._current_id]

    def get(self, key_id: str) -> Optional[bytes]:
        return self._keys.get(key_id)

    def rotate(self, key_id: str, key: bytes) -> None:
        """Make ``(key_id, key)`` the current signing key. Previously
        registered key_ids remain resolvable via ``get`` -- rotation must
        never make an existing, legitimately-unmodified row fail
        verification (see docs/DURABILITY.md's key-rotation guarantee)."""
        self._keys[key_id] = key
        self._current_id = key_id


class RollbackDetectedError(ValueError):
    """Raised at ``SQLiteStore`` construction when a configured
    ``RollbackCheckpoint``'s recorded high-water mark is ahead of this
    database file's own locally-recorded one -- this file is older than a
    state the external checkpoint already saw committed, exactly what
    restoring an earlier backup (a "rollback") looks like. Construction
    fails closed, like ``SchemaVersionError``, rather than opening a
    database whose own claimed progress cannot be trusted."""


class RollbackCheckpoint(Protocol):
    """A host-provided, externally-trusted monotonic high-water mark for
    rollback detection (see docs/DURABILITY.md). Must be backed by storage
    **outside** the SQLite file it protects -- a TPM/secure-enclave
    monotonic counter, a remote attestation service, another local file
    with its own integrity protection, or an operator-verified out-of-band
    value. A purely local, in-process value cannot bootstrap this
    guarantee on its own (see ``InMemoryRollbackCheckpoint``'s own
    docstring, and docs/DURABILITY.md's explicit callout): if the attacker
    can restore an old database file, they can equally well restore an old
    copy of anything else stored next to it.
    """

    def read(self) -> int:
        """Return the current external high-water mark."""
        ...

    def advance(self, new_value: int) -> None:
        """Durably record ``new_value`` as the current high-water mark.
        ``SQLiteStore`` never calls this with a value lower than what it
        most recently read -- a well-behaved implementation still refuses
        to move backward regardless, since nothing enforces that callers
        are well-behaved."""
        ...


class InMemoryRollbackCheckpoint:
    """A minimal, process-local ``RollbackCheckpoint`` -- state lives only
    in this object's memory, never written anywhere outside this process.

    **This does not provide real rollback protection.** It exists to
    exercise the ``RollbackCheckpoint`` protocol and ``SQLiteStore``'s
    wiring against it in tests, exactly like ``InMemoryKeyProvider`` is not
    a real secret store. A real deployment needs a genuinely external
    mechanism -- see docs/DURABILITY.md.
    """

    def __init__(self, initial: int = 0) -> None:
        self._value = initial

    def read(self) -> int:
        return self._value

    def advance(self, new_value: int) -> None:
        if new_value < self._value:
            raise ValueError(
                f"rollback checkpoint cannot move backward: {new_value} < {self._value}"
            )
        self._value = new_value


def _row_mac(key: bytes, *parts: Any) -> str:
    """HMAC-SHA256 over ``parts`` (each rendered as its own field, joined by
    a separator that cannot appear inside any individual ``str(part)`` for
    the value types this is called with -- ints, floats, and short
    identifier strings). Keyed by an external secret held outside the
    SQLite file (see ``KeyProvider``)."""
    canonical = "\x1f".join("" if p is None else str(p) for p in parts)
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


class HashChainLog:
    def __init__(self, filepath: Optional[str] = None, *, load: bool = True) -> None:
        self.filepath = filepath
        self.entries: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        if filepath and load:
            self.load()

    # -- load / verify -------------------------------------------------
    def load(self) -> ReceiptVerification:
        """Read an existing chain file into memory and verify it. A missing file
        is fine (empty chain)."""
        with self._lock:
            self.entries = []
            if not self.filepath:
                return ReceiptVerification(True, 0)
            path = Path(self.filepath).expanduser()
            if not path.exists():
                return ReceiptVerification(True, 0)
            with path.open("r", encoding="utf-8") as handle:
                for line_no, line in enumerate(handle, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.entries.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise ReceiptIntegrityError(
                            f"chain file {self.filepath} line {line_no}: not valid JSON ({exc})"
                        ) from exc
            result = self.verify()
            if not result.valid:
                raise ReceiptIntegrityError(
                    f"chain file {self.filepath} failed verification at record "
                    f"{result.failed_record}: {result.reason}"
                )
            return result

    def verify(self) -> ReceiptVerification:
        """Non-destructive verification of the in-memory chain."""
        with self._lock:
            previous = GENESIS_HASH
            for index, entry in enumerate(self.entries):
                if not isinstance(entry, dict):
                    return ReceiptVerification(False, index, index, "record is not an object", previous)
                claimed = entry.get("hash", "")
                if entry.get("prev_hash") != previous:
                    return ReceiptVerification(False, index, index, "hash chain is broken", previous)
                canonical = json.dumps(
                    {k: v for k, v in entry.items() if k != "hash"},
                    sort_keys=True, separators=(",", ":"), default=str,
                )
                if hashlib.sha256(canonical.encode()).hexdigest() != claimed:
                    return ReceiptVerification(False, index, index, "record hash does not match", previous)
                previous = claimed
            return ReceiptVerification(True, len(self.entries), last_valid_hash=previous)

    @staticmethod
    def _build_entry(entry_type: str, data: Dict[str, Any], phase: str,
                     execution_id: Optional[str], prev_hash: str) -> Dict[str, Any]:
        entry = {
            "record_version": RECORD_VERSION,
            "type": entry_type,
            "data": sanitize(data),
            "phase": phase,
            "execution_id": execution_id,
            "timestamp": time.time(),
            "prev_hash": prev_hash,
            "nonce": secrets.token_hex(8),
        }
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
        entry["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        return entry

    # -- append -------------------------------------------------------
    def append(self, entry_type: str, data: Dict[str, Any], *, phase: str = "completed",
               execution_id: Optional[str] = None) -> str:
        with self._lock:
            if self.filepath:
                # Multiple processes may share this file (e.g. several
                # governor processes pointed at the same audit log). An
                # in-process lock and this instance's in-memory `entries`
                # only serialise appends within one process; another
                # process's append is invisible to both. An OS-level
                # exclusive lock on the file serialises appends across
                # processes, and reading the file's own last line under
                # that lock -- rather than trusting in-memory state -- is
                # what makes prev_hash correctly chain onto whatever the
                # last writer (this process or another) actually wrote.
                path = Path(self.filepath).expanduser().resolve()
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a+", encoding="utf-8") as handle:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                    try:
                        handle.seek(0)
                        prev_hash = GENESIS_HASH
                        last_line_no = 0
                        for line_no, line in enumerate(handle, start=1):
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                prev_hash = json.loads(line)["hash"]
                            except (json.JSONDecodeError, KeyError) as exc:
                                raise ReceiptIntegrityError(
                                    f"chain file {self.filepath} line {line_no}: "
                                    f"not a valid chain record ({exc})"
                                ) from exc
                            last_line_no = line_no
                        entry = self._build_entry(entry_type, data, phase, execution_id, prev_hash)
                        handle.seek(0, os.SEEK_END)
                        handle.write(json.dumps(entry, default=str) + "\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    finally:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                # Reflect what's now on disk: if another process appended
                # entries this instance never loaded, catch back up so this
                # instance's own view (verify()/entries) stays consistent
                # with the file it just wrote to.
                if last_line_no > len(self.entries):
                    self.load()
                else:
                    self.entries.append(entry)
                return entry["hash"]

            verification = self.verify()
            if not verification.valid:
                raise ReceiptIntegrityError(
                    f"refusing to extend corrupt receipt chain at record "
                    f"{verification.failed_record}: {verification.reason}"
                )
            entry = self._build_entry(entry_type, data, phase, execution_id,
                                      verification.last_valid_hash)
            self.entries.append(entry)
            return entry["hash"]


# ============================================================================
# SQLite store
# ============================================================================

class SQLiteStore:
    # v1: proposals, delegations. v2: + replay_nonces, replay_proposal_ids,
    # scoped by a constructed (namespace, envelope_fingerprint[, agent_id])
    # "scope" string. v3: replay tables rebuilt with explicit columns and the
    # uniqueness boundary narrowed to (namespace, agent_id, nonce) /
    # (namespace, proposal_id) -- envelope_fingerprint is metadata only, no
    # longer part of uniqueness (see claim_nonce / claim_proposal_id: a
    # policy/envelope change must never make an old signed proposal replayable
    # again). A v2 database's replay tables are renamed out of the way, the
    # v3-shaped tables created fresh, and every row migrated forward into
    # the new columns (see _rename_pre_v3_replay_tables /
    # _migrate_replay_data_from_v2) -- claim history is preserved, never
    # dropped, since a claim silently disappearing across a migration would
    # let a previously-consumed signed proposal or nonce become replayable
    # again. proposals/delegations are untouched by any version bump.
    # v4: + restrictions, restriction_events (durable restriction state --
    # see impose_restriction / clear_restriction / active_restrictions).
    # Purely additive over v1-v3; no existing table changes shape.
    # v5: + live_authority, live_authority_agents, step_counters (durable
    # live authority, permission budgets, and fleet/per-agent step budgets --
    # see initialize_agent_authority / replace_live_authority /
    # consume_permission_budget / increment_step_counter). Purely additive
    # over v1-v4; no existing table changes shape, so no data migration is
    # needed for this hop (unlike v2->v3's replay-table rebuild).
    # v6: + live_authority.mac/key_id, live_authority_agents.mac/key_id --
    # keyed-MAC row authentication for the durable live-authority tables
    # (see KeyProvider, RowIntegrityError, docs/DURABILITY.md). Purely
    # additive columns, both nullable: a SQLiteStore opened without a
    # `key_provider` reads/writes these tables exactly as it did at v5 (mac
    # and key_id simply stay NULL). This was the first, narrowest slice of
    # the tamper-detection layer docs/DURABILITY.md describes -- it covered
    # only live_authority/live_authority_agents, not restrictions or the
    # replay tables, and it does not address rollback-to-an-older-database
    # (see docs/DURABILITY.md's "Smallest correct next step" for the
    # deliberately staged remainder).
    # v7: + restrictions.mac/key_id, replay_proposal_ids.mac/key_id,
    # replay_nonces.mac/mac_key_id (named mac_key_id, not key_id --
    # replay_nonces already has a `key_id` column recording the signing key
    # that verified the claimed proposal's signature; that is a different
    # concept from the MAC key authenticating this row, so it gets its own
    # column rather than overloading the existing one), step_counters.mac/
    # key_id. Same opt-in, purely-additive shape as v6: a SQLiteStore
    # without a key_provider is unaffected. See active_restrictions /
    # claim_nonce / claim_proposal_id / peek_step_counter /
    # increment_step_counter for what's verified and, just as importantly,
    # what still is not (a restriction's `status` column is not part of its
    # MAC -- see the comment on impose_restriction/_verify_mac's caller
    # there for why that's a real, documented gap, not an oversight).
    # v8: + initialization_ledger -- a keyed, hash-chained, append-only
    # ledger of every agent-authority-initialization event, closing (most
    # of) the "deleted marker row is indistinguishable from never
    # initialized" gap docs/DURABILITY.md flagged as still open after v6/
    # v7's per-row MAC coverage. A deleted live_authority_agents marker row
    # leaves no trace *by itself* (a MAC only verifies a row that's still
    # present to check) -- but each ledger entry's mac is chained onto the
    # previous entry's mac (see LEDGER_GENESIS, _append_initialization_
    # ledger_entry, _verify_ledger_chain), so deleting entry N breaks the
    # chain at entry N+1 whenever a later agent was ever initialized after
    # it. is_authority_initialized cross-checks marker-row presence against
    # ledger-row presence on every call (cheap: one indexed lookup, not a
    # chain walk) and fails closed on any disagreement; the full O(n) chain
    # walk (_verify_ledger_chain / verify_integrity_ledger) that would also
    # catch both being deleted together runs once at SQLiteStore
    # construction, not on the hot path. Deleting the ledger's current tip
    # entry (the single most-recently-initialized agent, if it and its
    # marker are both removed) is NOT caught by this -- that is the same
    # rollback/truncation gap the design doc already scopes out as needing
    # an external checkpoint. Opt-in like v6/v7: only written to and
    # verified when a key_provider is configured.
    # v9: + restriction_ledger -- the same keyed, hash-chained, append-only
    # ledger mechanism as v8's initialization_ledger, generalized to
    # restrictions: one entry per IMPOSED/EXPIRED/CLEARED transition (see
    # _append_restriction_ledger_entry, _verify_restriction_ledger_chain).
    # Closes (most of) the gap noted in the v7 comment above: active_
    # restrictions filters on status = 'ACTIVE' in SQL before any row mac
    # is checked, so flipping an ACTIVE row's status column directly
    # (rather than editing one of the columns the query still returns)
    # used to make it vanish from the result with no RowIntegrityError
    # raised. active_restrictions now also cross-checks, per call, whether
    # the ledger's latest known transition for each restriction_id it has
    # ever seen for this agent is IMPOSED (i.e. "should still be ACTIVE")
    # against what the ACTIVE query just returned -- a restriction_id the
    # ledger says should still be active but isn't in that result is
    # exactly a status flipped without a matching ledger entry. Same
    # residual limit as v8: deleting the CURRENT TIP of this chain (the
    # single most-recent transition, with nothing chained after it) is not
    # caught -- that is the same rollback/truncation gap needing an
    # external checkpoint. Opt-in like v6-v8: only written to and verified
    # when a key_provider is configured.
    # v10: + rollback_checkpoint_state -- a single-row table recording this
    # database file's own local rollback-checkpoint sequence number (see
    # RollbackCheckpoint, InMemoryRollbackCheckpoint, RollbackDetectedError,
    # advance_checkpoint). Opt-in like v6-v9: only meaningful when a
    # rollback_checkpoint is configured; a fresh row (seq=0) is created
    # unconditionally so the column always has a defined value to compare,
    # but nothing reads or compares it unless rollback_checkpoint is set.
    # This is the first (of two) pieces docs/DURABILITY.md's "host-provided
    # monotonic checkpoint for rollback detection" section describes --
    # see the docstrings on RollbackCheckpoint / advance_checkpoint for
    # what's implemented and what a deployment must still decide for
    # itself (which external mechanism to use, and how often to call
    # advance_checkpoint -- there is no one-size-fits-all answer).
    SCHEMA_VERSION = 10

    def __init__(self, db_path: str = ":memory:", *, synchronous: str = "FULL",
                 key_provider: Optional[KeyProvider] = None,
                 rollback_checkpoint: Optional[RollbackCheckpoint] = None) -> None:
        if synchronous.upper() not in ("FULL", "NORMAL", "OFF"):
            raise ValueError(f"synchronous must be FULL, NORMAL, or OFF, got {synchronous!r}")
        self.db_path = db_path
        # Optional: when set, live_authority/live_authority_agents rows are
        # authenticated with a keyed MAC on every authoritative write and
        # verified on every read that feeds an authorization decision (see
        # KeyProvider, RowIntegrityError). None preserves exactly the
        # unauthenticated schema-v5 behaviour.
        self._key_provider = key_provider
        # Optional: when set, this database's own recorded checkpoint
        # sequence is compared against the external checkpoint's at
        # construction (see _check_rollback_checkpoint), failing closed
        # (RollbackDetectedError) if this file is behind it. None preserves
        # the pre-v10 behaviour: no rollback detection at all (see
        # docs/DURABILITY.md -- this was always explicitly out of scope
        # for the row-level MAC/ledger work alone).
        self._rollback_checkpoint = rollback_checkpoint
        # WAL + synchronous=NORMAL is the common performance-oriented combo,
        # but it can still lose the most recently committed transaction(s)
        # on an OS crash or power loss between the WAL write and its
        # checkpoint (not corruption -- a clean rollback to the last
        # checkpoint). For a store whose entire purpose is durable replay
        # and restriction state ("a previously-consumed proposal cannot
        # become replayable again"), that gap contradicts the guarantee.
        # FULL fsyncs on every commit and is the safe default; pass
        # synchronous="NORMAL" explicitly to trade that for throughput.
        self.synchronous = synchronous.upper()
        # A single shared connection guarded by a lock. threadlocal connections
        # against ``:memory:`` would each get a *separate* database, which is the
        # v4 footgun; one connection avoids it and keeps writes serialised.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            c = self._conn
            c.execute("PRAGMA journal_mode=WAL")
            c.execute(f"PRAGMA synchronous={self.synchronous}")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = c.execute("SELECT version FROM schema_version").fetchone()
            migrating = False
            if row is None:
                c.execute("INSERT INTO schema_version (version) VALUES (?)", (self.SCHEMA_VERSION,))
            elif row[0] > self.SCHEMA_VERSION:
                # A newer schema version than this code understands -- e.g. the
                # database was last written by a newer Chainmail release, then
                # opened by an older one (a downgrade, or two versions pointed
                # at the same file). Proceeding would run this version's
                # CREATE TABLE IF NOT EXISTS / migration logic against tables
                # or columns it has no knowledge of, silently reading or
                # writing an incompatible shape rather than refusing outright.
                raise SchemaVersionError(
                    f"SQLite database {self.db_path!r} has schema_version="
                    f"{row[0]}, newer than this Chainmail's SCHEMA_VERSION="
                    f"{self.SCHEMA_VERSION}; refusing to open it (opening with "
                    f"an older version risks silently misreading or corrupting "
                    f"data written in a newer, unknown shape). Upgrade "
                    f"Chainmail, or point at a different database."
                )
            elif row[0] < self.SCHEMA_VERSION:
                # proposals/delegations are additive-only across every version, so an
                # older database just gains new tables/columns here. The replay
                # tables specifically may need their old (pre-v3) shape replaced --
                # renamed here, out of the way of the CREATE TABLE statements below,
                # then migrated forward by _migrate_replay_data_from_v2 once the
                # v3-shaped tables exist -- never dropped: replay claims are exactly
                # the record that must survive a migration.
                logger.info("migrating SQLiteStore schema %s -> %s", row[0], self.SCHEMA_VERSION)
                self._rename_pre_v3_replay_tables(c)
                if row[0] < 6:
                    self._add_mac_columns(c, "live_authority_agents")
                    self._add_mac_columns(c, "live_authority")
                if row[0] < 7:
                    self._add_mac_columns(c, "restrictions")
                    self._add_mac_columns(c, "replay_proposal_ids")
                    self._add_mac_columns(c, "replay_nonces", key_id_column="mac_key_id")
                    self._add_mac_columns(c, "step_counters")
                c.execute("UPDATE schema_version SET version = ?", (self.SCHEMA_VERSION,))
                migrating = True
            c.execute("""
                CREATE TABLE IF NOT EXISTS proposals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_version INTEGER NOT NULL,
                    proposal_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    signals TEXT,
                    overlap REAL,
                    drift REAL,
                    timestamp REAL NOT NULL,
                    execution_id TEXT,
                    phase TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS delegations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_version INTEGER NOT NULL,
                    from_agent TEXT NOT NULL,
                    to_agent TEXT NOT NULL,
                    reason TEXT,
                    authority TEXT,
                    timestamp REAL NOT NULL
                )
            """)
            # Durable replay protection. The UNIQUE constraint is the whole
            # point -- claims are a single atomic INSERT, never a separate
            # SELECT-then-INSERT, so two governor processes racing on the same
            # identifier cannot both succeed (the loser gets an
            # IntegrityError, which the caller reads as "replay").
            #
            # Deliberately NOT part of the uniqueness boundary:
            # envelope_fingerprint. Replay protection answers "has this
            # signed request already been submitted?" -- a policy/envelope
            # update must not reset that answer, or an attacker holding an
            # earlier signed proposal could replay it simply by waiting for
            # (or triggering) a policy change. envelope_fingerprint and
            # key_id are stored as audit metadata only.
            c.execute("""
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    deployment_namespace TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    key_id TEXT,
                    envelope_fingerprint TEXT,
                    claimed_at REAL NOT NULL,
                    mac TEXT,
                    mac_key_id TEXT,
                    UNIQUE (deployment_namespace, agent_id, nonce)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS replay_proposal_ids (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    deployment_namespace TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    envelope_fingerprint TEXT,
                    claimed_at REAL NOT NULL,
                    mac TEXT,
                    key_id TEXT,
                    UNIQUE (deployment_namespace, proposal_id)
                )
            """)
            # Durable restriction state. ``restrictions`` is the current-state
            # table (one row per restriction_id, updated in place on
            # clear/expire -- never deleted); ``restriction_events`` is the
            # accompanying append-only log of every IMPOSED / CLEARED /
            # EXPIRED transition, for investigation after the fact.
            #
            # Scoped by (deployment_namespace, agent_id) -- see
            # active_restrictions(). Deliberately NOT scoped by
            # envelope_fingerprint or a signing key_id, for the same reason
            # replay protection isn't: a restriction is a consequence of an
            # agent's behaviour, and a policy update, envelope change, or key
            # rotation must not silently lift it. envelope_fingerprint is
            # still recorded as metadata (the policy version active when the
            # restriction was imposed / cleared).
            c.execute("""
                CREATE TABLE IF NOT EXISTS restrictions (
                    restriction_id TEXT PRIMARY KEY,
                    deployment_namespace TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    permission_name TEXT NOT NULL,
                    permission_scope TEXT NOT NULL,
                    permission_max_budget INTEGER,
                    status TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    source_proposal_id TEXT NOT NULL,
                    envelope_fingerprint TEXT,
                    expiry_kind TEXT NOT NULL,
                    expiry_value REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    cleared_by TEXT,
                    cleared_reason TEXT,
                    cleared_policy_version TEXT,
                    mac TEXT,
                    key_id TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS restriction_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    restriction_id TEXT NOT NULL,
                    deployment_namespace TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    permission_name TEXT NOT NULL,
                    permission_scope TEXT NOT NULL,
                    reason_code TEXT,
                    source_proposal_id TEXT,
                    envelope_fingerprint TEXT,
                    actor TEXT,
                    detail TEXT,
                    timestamp REAL NOT NULL
                )
            """)
            # Keyed, hash-chained, append-only ledger of every restriction
            # IMPOSED/EXPIRED/CLEARED transition -- see the v9
            # SCHEMA_VERSION comment above. Only written to / verified when
            # a key_provider is configured. `seq` is the chain order
            # (global, across every namespace/agent/restriction); `prev_mac`
            # is the previous entry's `mac` (or LEDGER_GENESIS for the
            # first entry ever written). Never updated or deleted in place,
            # only appended to -- unlike `restrictions` itself, which is
            # only updated in place, this is the append-only record
            # active_restrictions cross-checks against.
            c.execute("""
                CREATE TABLE IF NOT EXISTS restriction_ledger (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    deployment_namespace TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    restriction_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    permission_name TEXT NOT NULL,
                    permission_scope TEXT NOT NULL,
                    permission_max_budget INTEGER,
                    expiry_kind TEXT NOT NULL,
                    expiry_value REAL,
                    prev_mac TEXT NOT NULL,
                    mac TEXT,
                    key_id TEXT
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS ix_restriction_ledger_agent "
                     "ON restriction_ledger(deployment_namespace, agent_id, restriction_id)")
            # Durable live authority + permission budgets.
            #
            # ``live_authority_agents`` is an explicit initialization marker,
            # separate from whether ``live_authority`` currently holds any
            # rows for that agent. Without it, "no permission rows for this
            # agent" would be ambiguous between "never initialized -- seed
            # from the envelope ceiling" and "legitimately reduced to zero
            # permissions by delegation/consumption" -- collapsing those two
            # would restore authority on every restart the moment an agent's
            # authority reached zero, which is exactly invariant #1
            # ("restarting must never increase an agent's authority") this
            # table exists to prevent. Governor startup seeds this table
            # (and one live_authority row per envelope-ceiling permission)
            # exactly once per (namespace, agent_id) -- see
            # initialize_agent_authority.
            #
            # ``live_authority`` holds the current set of granted
            # permissions, one row per (namespace, agent_id, permission_name,
            # permission_scope). ``remaining`` is NULL iff ``max_budget`` IS
            # NULL (unlimited); otherwise it is the durable budget counter
            # consumed by ``consume_permission_budget``'s single atomic
            # UPDATE. Scoped by (namespace, agent_id) only -- NOT
            # envelope_fingerprint -- for the same reason replay claims and
            # restrictions are not scoped by it: a policy/envelope change
            # must never silently reset consumed budget or restore
            # authority (invariant #8). envelope_fingerprint is recorded per
            # row as audit metadata only (the policy version active at last
            # write), never part of how a row is looked up or matched.
            c.execute("""
                CREATE TABLE IF NOT EXISTS live_authority_agents (
                    deployment_namespace TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    initialized_at REAL NOT NULL,
                    mac TEXT,
                    key_id TEXT,
                    PRIMARY KEY (deployment_namespace, agent_id)
                )
            """)
            # Keyed, hash-chained, append-only ledger of every agent-
            # authority-initialization event -- see the v8 comment on
            # SCHEMA_VERSION above. Only written to / verified when a
            # key_provider is configured (see _append_initialization_
            # ledger_entry, _mark_agent_initialized). `seq` is the chain
            # order; `prev_mac` is the previous entry's `mac` (or
            # LEDGER_GENESIS for the first entry ever written) -- deleting
            # or reordering an entry breaks the next entry's prev_mac
            # linkage, detectable without needing anything outside this
            # table (see _verify_ledger_chain). Never updated or deleted
            # in place, only appended to.
            c.execute("""
                CREATE TABLE IF NOT EXISTS initialization_ledger (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    deployment_namespace TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    initialized_at REAL NOT NULL,
                    prev_mac TEXT NOT NULL,
                    mac TEXT,
                    key_id TEXT,
                    UNIQUE (deployment_namespace, agent_id)
                )
            """)
            # This database file's own locally-recorded rollback-checkpoint
            # sequence number -- see the v10 SCHEMA_VERSION comment above
            # and RollbackCheckpoint / advance_checkpoint. Single row
            # (id=1), created once with seq=0 and never re-created; only
            # advance_checkpoint bumps it, always upward.
            c.execute("""
                CREATE TABLE IF NOT EXISTS rollback_checkpoint_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    seq INTEGER NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS live_authority (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    deployment_namespace TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    permission_name TEXT NOT NULL,
                    permission_scope TEXT NOT NULL,
                    max_budget INTEGER,
                    remaining INTEGER,
                    source TEXT NOT NULL,
                    envelope_fingerprint TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    mac TEXT,
                    key_id TEXT,
                    UNIQUE (deployment_namespace, agent_id, permission_name, permission_scope)
                )
            """)
            # Durable fleet/per-agent step (runtime) budgets. ``scope`` is
            # ``"fleet"`` or ``f"agent:{agent_id}"`` -- a monotonic counter
            # per scope, incremented atomically by increment_step_counter's
            # single UPSERT+read (never a separate check-then-write). Scoped
            # by namespace only, matching the in-memory step_count/
            # _agent_steps this replaces: an evaluation attempt (not just a
            # CONTINUE) consumes step budget, per the existing evaluate()
            # ordering this table must not change the semantics of.
            c.execute("""
                CREATE TABLE IF NOT EXISTS step_counters (
                    deployment_namespace TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL,
                    mac TEXT,
                    key_id TEXT,
                    PRIMARY KEY (deployment_namespace, scope)
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_agent ON proposals(agent_id)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_ts ON proposals(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_pid ON proposals(proposal_id)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_deleg_from ON delegations(from_agent)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_restrictions_active "
                     "ON restrictions(deployment_namespace, agent_id, status)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_restriction_events_rid "
                     "ON restriction_events(restriction_id)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_live_authority_agent "
                     "ON live_authority(deployment_namespace, agent_id)")
            if migrating:
                self._migrate_replay_data_from_v2(c)
            c.commit()
            # One-time, full verification of every append-only ledger's
            # hash chain at open (see the v8/v9 SCHEMA_VERSION comments and
            # _verify_ledger_chain/_verify_restriction_ledger_chain) -- a
            # no-op if no key_provider is configured, or if a ledger is
            # empty (a fresh database, or one that's never had a
            # key_provider attached).
            self._verify_ledger_chain()
            self._verify_restriction_ledger_chain()
            self._check_rollback_checkpoint()

    def _check_rollback_checkpoint(self) -> None:
        """At construction, compare this database file's own locally-
        recorded checkpoint sequence against the configured
        ``RollbackCheckpoint``'s -- a no-op if none is configured (see
        docs/DURABILITY.md: rollback detection is opt-in and requires a
        genuinely external mechanism this repository does not ship).

        Three cases:

        * ``local == external``: consistent, nothing to do.
        * ``local < external``: this file's own recorded progress is
          *behind* what the external, trusted checkpoint has already seen
          committed -- exactly what restoring an earlier (at-the-time
          validly MAC'd) backup looks like. Raises ``RollbackDetectedError``
          -- construction fails closed, like ``SchemaVersionError``.
        * ``local > external``: NOT a rollback signal -- it means a
          previous process committed local state (via
          ``advance_checkpoint``) but crashed or failed before its second
          phase (pushing the same value to the external checkpoint) ran.
          Self-heals: advances the external checkpoint to match what is
          already durably committed locally, rather than leaving the two
          permanently out of sync after an ordinary crash.
        """
        if self._rollback_checkpoint is None:
            return
        row = self._conn.execute(
            "SELECT seq FROM rollback_checkpoint_state WHERE id = 1"
        ).fetchone()
        local_seq = row[0] if row is not None else 0
        external_seq = self._rollback_checkpoint.read()
        if local_seq < external_seq:
            raise RollbackDetectedError(
                f"SQLite database {self.db_path!r} has local rollback-checkpoint "
                f"seq={local_seq}, behind the external checkpoint's seq={external_seq} "
                f"-- this file is older than a state already recorded as committed; "
                f"refusing to open it (this is exactly what restoring an earlier "
                f"backup looks like)"
            )
        if local_seq > external_seq:
            self._rollback_checkpoint.advance(local_seq)

    def _rename_pre_v3_replay_tables(self, c: sqlite3.Connection) -> None:
        """Rename a pre-v3 (``scope``-column) replay table out of the way so
        the v3-shaped table can be created fresh by the ``CREATE TABLE``
        statements that follow; ``_migrate_replay_data_from_v2`` then copies
        its rows forward into the new table and drops it.

        Renaming (not dropping) matters: replay claims are exactly the
        record that must never quietly disappear across a migration -- a
        previously-consumed signed proposal or nonce becoming reusable after
        an upgrade would defeat the whole point of durable replay
        protection. A no-op for a fresh database or one already at v3+
        (nothing to detect: absent or already-correct tables have no
        ``scope`` column).
        """
        for table in ("replay_nonces", "replay_proposal_ids"):
            cols = {row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}
            if "scope" in cols:
                c.execute(f"ALTER TABLE {table} RENAME TO {table}_pre_v3")

    def _add_mac_columns(self, c: sqlite3.Connection, table: str, *,
                        key_id_column: str = "key_id") -> None:
        """Additively add a ``mac`` column and a MAC key-id column (named
        ``key_id_column`` -- ``replay_nonces`` already has an unrelated
        ``key_id`` column, so it uses ``mac_key_id`` instead) to an
        existing pre-authentication table. A no-op for a fresh database
        (created with the columns already present by the ``CREATE TABLE``
        statements below) or one where the columns already exist."""
        if not self._table_exists(c, table):
            return
        cols = {row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}
        if "mac" not in cols:
            c.execute(f"ALTER TABLE {table} ADD COLUMN mac TEXT")
        if key_id_column not in cols:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {key_id_column} TEXT")

    def _migrate_replay_data_from_v2(self, c: sqlite3.Connection) -> None:
        """Copy claim rows forward from a table renamed by
        ``_rename_pre_v3_replay_tables`` into the newly-created v3-shaped
        table, then drop the renamed table. No-op if there is nothing to
        migrate (a fresh database, or one already at v3+).

        v2's ``scope`` was ``f"{namespace}:{envelope_fingerprint}:{agent_id}"``
        for nonces and ``f"{namespace}:{envelope_fingerprint}"`` for proposal
        IDs -- both ``envelope_fingerprint`` and ``agent_id``/``proposal_id``
        were already separate columns even in v2, so ``namespace`` is
        recovered exactly by stripping that known suffix from ``scope``, not
        guessed.

        v3 narrowed uniqueness to no longer include ``envelope_fingerprint``
        (see the table comment above), so multiple v2 rows for the same
        nonce/proposal_id claimed under different envelope fingerprints can
        now collapse onto a single v3 row. ``INSERT OR IGNORE`` keeps
        whichever is inserted first and silently discards the rest -- that's
        correct: they all represent the same already-consumed identifier,
        and the durable point is that it stays consumed, not which specific
        historical claim record wins.
        """
        if self._table_exists(c, "replay_nonces_pre_v3"):
            rows = c.execute(
                "SELECT scope, nonce, agent_id, key_id, envelope_fingerprint, claimed_at "
                "FROM replay_nonces_pre_v3"
            ).fetchall()
            migrated = 0
            for scope, nonce, agent_id, key_id, envelope_fingerprint, claimed_at in rows:
                suffix = f":{envelope_fingerprint}:{agent_id}"
                namespace = scope[: -len(suffix)] if scope.endswith(suffix) else scope
                c.execute(
                    "INSERT OR IGNORE INTO replay_nonces (deployment_namespace, agent_id, "
                    "nonce, key_id, envelope_fingerprint, claimed_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (namespace, agent_id, nonce, key_id, envelope_fingerprint, claimed_at),
                )
                migrated += c.execute("SELECT changes()").fetchone()[0]
            logger.warning(
                "migrated %d/%d nonce claims forward from the pre-v3 schema (%d collapsed "
                "under the v3 uniqueness scope, which no longer includes envelope_fingerprint)",
                migrated, len(rows), len(rows) - migrated,
            )
            c.execute("DROP TABLE replay_nonces_pre_v3")

        if self._table_exists(c, "replay_proposal_ids_pre_v3"):
            rows = c.execute(
                "SELECT scope, proposal_id, agent_id, envelope_fingerprint, claimed_at "
                "FROM replay_proposal_ids_pre_v3"
            ).fetchall()
            migrated = 0
            for scope, proposal_id, agent_id, envelope_fingerprint, claimed_at in rows:
                suffix = f":{envelope_fingerprint}"
                namespace = scope[: -len(suffix)] if scope.endswith(suffix) else scope
                c.execute(
                    "INSERT OR IGNORE INTO replay_proposal_ids (deployment_namespace, "
                    "proposal_id, agent_id, envelope_fingerprint, claimed_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (namespace, proposal_id, agent_id, envelope_fingerprint, claimed_at),
                )
                migrated += c.execute("SELECT changes()").fetchone()[0]
            logger.warning(
                "migrated %d/%d proposal-id claims forward from the pre-v3 schema (%d "
                "collapsed under the v3 uniqueness scope)",
                migrated, len(rows), len(rows) - migrated,
            )
            c.execute("DROP TABLE replay_proposal_ids_pre_v3")

    @staticmethod
    def _table_exists(c: sqlite3.Connection, name: str) -> bool:
        return c.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None

    # -- durable replay protection -------------------------------------
    #
    # Scope:
    #   * Nonces are unique per (deployment_namespace, agent_id, nonce).
    #     Nonce uniqueness is PER AGENT: a nonce is bound to whichever key
    #     signed the proposal that carries it, and keys are themselves
    #     agent-bound (KeyRegistry.resolve), so a nonce collision between two
    #     different agents is not the replay this defends against -- it
    #     would already be caught by signature/key binding. Scoping per
    #     agent also means agent A's nonce space can never be exhausted or
    #     polluted by agent B's traffic.
    #   * Proposal IDs are unique per (deployment_namespace, proposal_id) --
    #     fleet-wide, across all agents. This matches the pre-durability
    #     in-memory behaviour (a single process-wide ``_seen_proposal_ids``
    #     set) and treats proposal_id as a general-purpose idempotency key
    #     for the whole fleet, not a per-agent one.
    #   * ``envelope_fingerprint`` is NOT part of either uniqueness boundary
    #     -- see the table comments in ``_init_db``. Replay protection
    #     identifies whether a *signed request* has already been submitted;
    #     updating policy must not make an old signed proposal fresh again.
    #     It is stored alongside the claim as audit metadata, along with
    #     ``key_id`` for nonces.
    #   * ``deployment_namespace`` (default ``"default"``) lets multiple
    #     independent deployments share one physical database file without
    #     their replay records colliding.
    #
    # Every claim is a single atomic INSERT against real, indexed columns --
    # never a constructed "scope" string, and never a prior SELECT. A UNIQUE
    # violation *is* the replay signal. Callers must not batch these writes
    # -- each call commits immediately, so a claim that returns True is
    # durable before the caller acts on it.
    #
    # Consumption semantics: a claim is unconditional once made -- it is not
    # rolled back if a later policy check on the same proposal returns
    # RESTRICT / RECHECK / HUMAN instead of CONTINUE. An authenticated
    # proposal consumes its nonce and proposal_id the moment they are
    # claimed; retrying requires a new proposal with a new nonce, regardless
    # of how the original proposal was ultimately decided.

    def claim_nonce(self, *, namespace: str, agent_id: str, nonce: str,
                    key_id: Optional[str] = None,
                    envelope_fingerprint: Optional[str] = None) -> bool:
        """Atomically claim ``nonce`` for ``agent_id`` within ``namespace``.

        Uniqueness is ``(namespace, agent_id, nonce)`` only -- see the module
        docs above for why ``envelope_fingerprint`` is metadata, not part of
        the uniqueness boundary. Returns True if this call newly claimed it,
        False if it was already claimed (a replay). Any other
        ``sqlite3.Error`` (disk full, DB locked/corrupt, ...) propagates --
        the caller must treat that as a persistence failure and fail closed,
        not as "not a replay".
        """
        mac_key_id, mac_key = self._signing_key()
        with self._lock:
            claimed_at = time.time()
            mac = (
                _row_mac(mac_key, namespace, agent_id, nonce, claimed_at)
                if mac_key is not None else None
            )
            try:
                self._conn.execute(
                    "INSERT INTO replay_nonces "
                    "(deployment_namespace, agent_id, nonce, key_id, envelope_fingerprint, "
                    "claimed_at, mac, mac_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (namespace, agent_id, nonce, key_id, envelope_fingerprint, claimed_at,
                     mac, mac_key_id),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                # Already claimed -- verify the existing claim itself wasn't
                # forged (inserted without going through this method) before
                # trusting it as a genuine replay signal. A row an attacker
                # planted to pre-emptively block a nonce a legitimate agent
                # hasn't used yet would otherwise look identical to a real
                # replay.
                row = self._conn.execute(
                    "SELECT nonce, claimed_at, mac, mac_key_id FROM replay_nonces WHERE "
                    "deployment_namespace = ? AND agent_id = ? AND nonce = ?",
                    (namespace, agent_id, nonce),
                ).fetchone()
                if row is not None:
                    existing_nonce, existing_claimed_at, existing_mac, existing_key_id = row
                    self._verify_mac(
                        stored_mac=existing_mac, key_id=existing_key_id,
                        parts=(namespace, agent_id, existing_nonce, existing_claimed_at),
                        context=f"replay_nonces({namespace!r}, {agent_id!r}, {nonce!r})",
                    )
                return False

    def claim_proposal_id(self, *, namespace: str, proposal_id: str, agent_id: str,
                          envelope_fingerprint: Optional[str] = None) -> bool:
        """Atomically claim ``proposal_id`` fleet-wide within ``namespace``.

        Uniqueness is ``(namespace, proposal_id)`` only. Same return/exception
        contract as ``claim_nonce``.
        """
        key_id, key = self._signing_key()
        with self._lock:
            claimed_at = time.time()
            mac = (
                _row_mac(key, namespace, proposal_id, agent_id, claimed_at)
                if key is not None else None
            )
            try:
                self._conn.execute(
                    "INSERT INTO replay_proposal_ids "
                    "(deployment_namespace, proposal_id, agent_id, envelope_fingerprint, "
                    "claimed_at, mac, key_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (namespace, proposal_id, agent_id, envelope_fingerprint, claimed_at,
                     mac, key_id),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                # Same rationale as claim_nonce: verify the existing claim
                # wasn't forged before trusting it as a genuine replay.
                row = self._conn.execute(
                    "SELECT proposal_id, agent_id, claimed_at, mac, key_id FROM "
                    "replay_proposal_ids WHERE deployment_namespace = ? AND proposal_id = ?",
                    (namespace, proposal_id),
                ).fetchone()
                if row is not None:
                    existing_pid, existing_agent, existing_claimed_at, existing_mac, existing_key_id = row
                    self._verify_mac(
                        stored_mac=existing_mac, key_id=existing_key_id,
                        parts=(namespace, existing_pid, existing_agent, existing_claimed_at),
                        context=f"replay_proposal_ids({namespace!r}, {proposal_id!r})",
                    )
                return False

    # -- durable restriction state --------------------------------------
    #
    # ``restrictions`` holds current state (never deleted, only transitioned:
    # ACTIVE -> CLEARED or ACTIVE -> EXPIRED); ``restriction_events`` is an
    # append-only log of every transition, for investigation after a
    # restriction is cleared. Both are written in the same commit as the
    # state change they record.
    #
    # Scope: (deployment_namespace, agent_id) -- NOT envelope_fingerprint or
    # a key_id. A restriction is a consequence of behaviour; a policy
    # update, envelope change, or key rotation must not silently lift it.
    # envelope_fingerprint is recorded as metadata (the policy version in
    # effect when imposed / cleared), never part of how a restriction is
    # looked up.

    @staticmethod
    def _restriction_mac_parts(*, namespace: str, agent_id: str, restriction_id: str,
                              permission_name: str, permission_scope: str,
                              permission_max_budget: Optional[int], expiry_kind: str,
                              expiry_value: Optional[float], status: str) -> Tuple[Any, ...]:
        """The MAC content for one ``restrictions`` row. Includes ``status``
        so a legitimate ACTIVE -> EXPIRED/CLEARED transition (which changes
        it) always carries a mac matching its *current* status -- but by
        itself, this row-level MAC has the same limit as v6/v7 everywhere
        else: ``active_restrictions`` filters on ``status = 'ACTIVE'`` in
        SQL before any mac is checked, so an attacker who flips an ACTIVE
        row's status column directly makes it vanish from the result set
        entirely, never reaching this verification at all. ``restriction_
        ledger`` (schema v9, see ``_append_restriction_ledger_entry`` /
        ``_cross_check_restriction_ledger``) closes most of that instead --
        this MAC alone still detects a forged *new* ACTIVE restriction, or
        edits to an ACTIVE row's other fields.
        """
        return (namespace, agent_id, restriction_id, permission_name, permission_scope,
                permission_max_budget, expiry_kind, expiry_value, status)

    def _restriction_mac(self, key: Optional[bytes], **kwargs: Any) -> Optional[str]:
        if key is None:
            return None
        return _row_mac(key, *self._restriction_mac_parts(**kwargs))

    def _append_restriction_ledger_entry(self, *, namespace: str, agent_id: str,
                                        restriction_id: str, event_type: str,
                                        permission_name: str, permission_scope: str,
                                        permission_max_budget: Optional[int], expiry_kind: str,
                                        expiry_value: Optional[float], key_id: str,
                                        key: bytes) -> None:
        """Append one IMPOSED/EXPIRED/CLEARED entry to ``restriction_ledger``,
        chained onto whatever the current (global) tip's ``mac`` is (or
        ``LEDGER_GENESIS`` for the very first entry ever written across any
        namespace/agent/restriction). Must be called inside the same
        transaction as the ``restrictions`` row write it accompanies."""
        prev = self._conn.execute(
            "SELECT mac FROM restriction_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_mac = prev[0] if prev is not None else LEDGER_GENESIS
        mac = _row_mac(key, prev_mac, namespace, agent_id, restriction_id, event_type,
                      permission_name, permission_scope, permission_max_budget, expiry_kind,
                      expiry_value)
        self._conn.execute(
            "INSERT INTO restriction_ledger (deployment_namespace, agent_id, restriction_id, "
            "event_type, permission_name, permission_scope, permission_max_budget, "
            "expiry_kind, expiry_value, prev_mac, mac, key_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (namespace, agent_id, restriction_id, event_type, permission_name, permission_scope,
             permission_max_budget, expiry_kind, expiry_value, prev_mac, mac, key_id),
        )

    def _cross_check_restriction_ledger(self, *, namespace: str, agent_id: str,
                                       active_ids: Set[str]) -> None:
        """Cheap, per-call cross-check used by ``active_restrictions``: for
        every ``restriction_id`` this agent's ``restriction_ledger`` has
        ever recorded a transition for, look at only its *latest* entry (one
        indexed lookup per restriction_id this agent has ever had, not a
        full chain walk) and verify that entry's own mac. If the latest
        recorded transition is IMPOSED (i.e. the ledger's last word is
        "this should still be ACTIVE") but ``restriction_id`` is not in
        ``active_ids`` (what the ACTIVE query in ``active_restrictions`` just
        returned), that disagreement is exactly a status column flipped
        directly, without a corresponding ledger entry -- fail closed.
        """
        rows = self._conn.execute(
            "SELECT rl.restriction_id, rl.event_type, rl.permission_name, "
            "rl.permission_scope, rl.permission_max_budget, rl.expiry_kind, "
            "rl.expiry_value, rl.prev_mac, rl.mac, rl.key_id FROM restriction_ledger rl "
            "JOIN (SELECT restriction_id, MAX(seq) AS max_seq FROM restriction_ledger "
            "WHERE deployment_namespace = ? AND agent_id = ? GROUP BY restriction_id) latest "
            "ON rl.restriction_id = latest.restriction_id AND rl.seq = latest.max_seq "
            "WHERE rl.deployment_namespace = ? AND rl.agent_id = ?",
            (namespace, agent_id, namespace, agent_id),
        ).fetchall()
        for (restriction_id, event_type, permission_name, permission_scope,
             permission_max_budget, expiry_kind, expiry_value, prev_mac, mac, key_id) in rows:
            self._verify_mac(
                stored_mac=mac, key_id=key_id,
                parts=(prev_mac, namespace, agent_id, restriction_id, event_type,
                       permission_name, permission_scope, permission_max_budget,
                       expiry_kind, expiry_value),
                context=f"restriction_ledger({namespace!r}, {agent_id!r}, {restriction_id!r})",
            )
            if event_type == "IMPOSED" and restriction_id not in active_ids:
                raise RowIntegrityError(
                    f"restriction_ledger says restriction {restriction_id!r} for "
                    f"({namespace!r}, {agent_id!r}) should still be ACTIVE (its latest "
                    f"recorded transition is IMPOSED with nothing after it), but it is "
                    f"not in the ACTIVE rows restrictions currently returns -- its "
                    f"status was changed without a corresponding restriction_ledger "
                    f"entry, i.e. outside SQLiteStore's own write API"
                )

    def impose_restriction(self, *, namespace: str, agent_id: str, permission_name: str,
                           permission_scope: str, permission_max_budget: Optional[int],
                           reason_code: str, source_proposal_id: str,
                           envelope_fingerprint: Optional[str], expiry_kind: str,
                           expiry_value: Optional[float]) -> str:
        """Durably impose a new ACTIVE restriction. Returns the new
        ``restriction_id``. Raises ``sqlite3.Error`` on failure -- the caller
        must fail closed (HUMAN, never CONTINUE/RESTRICT reported as applied)
        rather than treat the restriction as imposed.
        """
        restriction_id = secrets.token_hex(16)
        now = time.time()
        key_id, key = self._signing_key()
        mac = self._restriction_mac(
            key, namespace=namespace, agent_id=agent_id, restriction_id=restriction_id,
            permission_name=permission_name, permission_scope=permission_scope,
            permission_max_budget=permission_max_budget, expiry_kind=expiry_kind,
            expiry_value=expiry_value, status="ACTIVE",
        )
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO restrictions (restriction_id, deployment_namespace, agent_id, "
                    "permission_name, permission_scope, permission_max_budget, status, "
                    "reason_code, source_proposal_id, envelope_fingerprint, expiry_kind, "
                    "expiry_value, created_at, updated_at, mac, key_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (restriction_id, namespace, agent_id, permission_name, permission_scope,
                     permission_max_budget, reason_code, source_proposal_id, envelope_fingerprint,
                     expiry_kind, expiry_value, now, now, mac, key_id),
                )
                self._conn.execute(
                    "INSERT INTO restriction_events (restriction_id, deployment_namespace, "
                    "agent_id, event_type, permission_name, permission_scope, reason_code, "
                    "source_proposal_id, envelope_fingerprint, actor, detail, timestamp) "
                    "VALUES (?, ?, ?, 'IMPOSED', ?, ?, ?, ?, ?, ?, ?, ?)",
                    (restriction_id, namespace, agent_id, permission_name, permission_scope,
                     reason_code, source_proposal_id, envelope_fingerprint, None, None, now),
                )
                if key is not None:
                    self._append_restriction_ledger_entry(
                        namespace=namespace, agent_id=agent_id, restriction_id=restriction_id,
                        event_type="IMPOSED", permission_name=permission_name,
                        permission_scope=permission_scope,
                        permission_max_budget=permission_max_budget, expiry_kind=expiry_kind,
                        expiry_value=expiry_value, key_id=key_id, key=key,
                    )
                self._conn.commit()
                return restriction_id
            except sqlite3.Error:
                self._conn.rollback()
                raise

    def active_restrictions(self, *, namespace: str, agent_id: str) -> List[Dict[str, Any]]:
        """All ACTIVE restriction rows for ``(namespace, agent_id)``.

        The caller (``ChainmailGovernor``) applies liveness (steps/wall/human)
        itself and calls ``mark_expired`` for anything found expired -- this
        method does not interpret expiry, it only returns what's currently
        marked ACTIVE.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT restriction_id, permission_name, permission_scope, "
                "permission_max_budget, expiry_kind, expiry_value, mac, key_id FROM "
                "restrictions WHERE deployment_namespace = ? AND agent_id = ? "
                "AND status = 'ACTIVE'",
                (namespace, agent_id),
            )
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
            for row in rows:
                self._verify_mac(
                    stored_mac=row["mac"], key_id=row["key_id"],
                    parts=self._restriction_mac_parts(
                        namespace=namespace, agent_id=agent_id,
                        restriction_id=row["restriction_id"],
                        permission_name=row["permission_name"],
                        permission_scope=row["permission_scope"],
                        permission_max_budget=row["permission_max_budget"],
                        expiry_kind=row["expiry_kind"], expiry_value=row["expiry_value"],
                        status="ACTIVE",
                    ),
                    context=f"restrictions({namespace!r}, {agent_id!r}, {row['restriction_id']!r})",
                )
                del row["mac"], row["key_id"]
            if self._key_provider is not None:
                self._cross_check_restriction_ledger(
                    namespace=namespace, agent_id=agent_id,
                    active_ids={row["restriction_id"] for row in rows},
                )
            return rows

    def mark_expired(self, *, namespace: str, agent_id: str, restriction_id: str) -> bool:
        """Atomically transition one restriction ACTIVE -> EXPIRED.

        Returns True if this call performed the transition, False if it was
        already non-ACTIVE (idempotent no-op) -- never raises on a
        already-cleared/expired restriction, only on a genuine store error.
        """
        now = time.time()
        key_id, key = self._signing_key()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE restrictions SET status = 'EXPIRED', updated_at = ? "
                "WHERE restriction_id = ? AND deployment_namespace = ? AND agent_id = ? "
                "AND status = 'ACTIVE'",
                (now, restriction_id, namespace, agent_id),
            )
            if cur.rowcount:
                row = self._conn.execute(
                    "SELECT permission_name, permission_scope, permission_max_budget, "
                    "expiry_kind, expiry_value FROM restrictions WHERE restriction_id = ?",
                    (restriction_id,),
                ).fetchone()
                perm_name, perm_scope, perm_max_budget, expiry_kind, expiry_value = row
                new_mac = self._restriction_mac(
                    key, namespace=namespace, agent_id=agent_id, restriction_id=restriction_id,
                    permission_name=perm_name, permission_scope=perm_scope,
                    permission_max_budget=perm_max_budget, expiry_kind=expiry_kind,
                    expiry_value=expiry_value, status="EXPIRED",
                )
                self._conn.execute(
                    "UPDATE restrictions SET mac = ?, key_id = ? WHERE restriction_id = ?",
                    (new_mac, key_id, restriction_id),
                )
                self._conn.execute(
                    "INSERT INTO restriction_events (restriction_id, deployment_namespace, "
                    "agent_id, event_type, permission_name, permission_scope, timestamp) "
                    "VALUES (?, ?, ?, 'EXPIRED', ?, ?, ?)",
                    (restriction_id, namespace, agent_id, perm_name, perm_scope, now),
                )
                if key is not None:
                    self._append_restriction_ledger_entry(
                        namespace=namespace, agent_id=agent_id, restriction_id=restriction_id,
                        event_type="EXPIRED", permission_name=perm_name,
                        permission_scope=perm_scope, permission_max_budget=perm_max_budget,
                        expiry_kind=expiry_kind, expiry_value=expiry_value, key_id=key_id,
                        key=key,
                    )
            self._conn.commit()
            return bool(cur.rowcount)

    def clear_restriction(self, *, namespace: str, agent_id: str, restriction_id: str,
                          authorised_by: str, reason: str,
                          policy_version: Optional[str]) -> str:
        """Explicitly clear one restriction, bound to a specific
        ``(agent_id, restriction_id)`` pair -- clearing restriction A can
        never affect restriction B, however similar, and a stale release
        naming an old restriction_id cannot clear a newer one imposed since.

        Returns one of:
          * ``"cleared"``          -- this call performed the transition
          * ``"already_cleared"``  -- idempotent no-op, it was already CLEARED
          * ``"not_found"``        -- no such restriction_id in this namespace
                                      (or it is EXPIRED, not ACTIVE/CLEARED --
                                      an expired restriction cannot be cleared)
          * ``"wrong_agent"``      -- the restriction_id exists but belongs to
                                      a different agent_id
        """
        now = time.time()
        key_id, key = self._signing_key()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE restrictions SET status = 'CLEARED', updated_at = ?, cleared_by = ?, "
                "cleared_reason = ?, cleared_policy_version = ? WHERE restriction_id = ? AND "
                "deployment_namespace = ? AND agent_id = ? AND status = 'ACTIVE'",
                (now, authorised_by, reason, policy_version, restriction_id, namespace, agent_id),
            )
            if cur.rowcount:
                row = self._conn.execute(
                    "SELECT permission_name, permission_scope, permission_max_budget, "
                    "expiry_kind, expiry_value FROM restrictions WHERE restriction_id = ?",
                    (restriction_id,),
                ).fetchone()
                perm_name, perm_scope, perm_max_budget, expiry_kind, expiry_value = row
                new_mac = self._restriction_mac(
                    key, namespace=namespace, agent_id=agent_id, restriction_id=restriction_id,
                    permission_name=perm_name, permission_scope=perm_scope,
                    permission_max_budget=perm_max_budget, expiry_kind=expiry_kind,
                    expiry_value=expiry_value, status="CLEARED",
                )
                self._conn.execute(
                    "UPDATE restrictions SET mac = ?, key_id = ? WHERE restriction_id = ?",
                    (new_mac, key_id, restriction_id),
                )
                self._conn.execute(
                    "INSERT INTO restriction_events (restriction_id, deployment_namespace, "
                    "agent_id, event_type, permission_name, permission_scope, actor, detail, "
                    "timestamp) VALUES (?, ?, ?, 'CLEARED', ?, ?, ?, ?, ?)",
                    (restriction_id, namespace, agent_id, perm_name, perm_scope, authorised_by,
                     reason, now),
                )
                if key is not None:
                    self._append_restriction_ledger_entry(
                        namespace=namespace, agent_id=agent_id, restriction_id=restriction_id,
                        event_type="CLEARED", permission_name=perm_name,
                        permission_scope=perm_scope, permission_max_budget=perm_max_budget,
                        expiry_kind=expiry_kind, expiry_value=expiry_value, key_id=key_id,
                        key=key,
                    )
                self._conn.commit()
                return "cleared"
            # not newly cleared: figure out why, without assuming anything changed
            row = self._conn.execute(
                "SELECT status, agent_id FROM restrictions WHERE restriction_id = ? "
                "AND deployment_namespace = ?", (restriction_id, namespace),
            ).fetchone()
            self._conn.commit()
            if row is None:
                return "not_found"
            status, existing_agent = row
            if existing_agent != agent_id:
                return "wrong_agent"
            if status == "CLEARED":
                return "already_cleared"
            return "not_found"  # EXPIRED (or any other non-ACTIVE state) -- can't clear it

    def restriction_history(self, *, namespace: str, agent_id: str,
                            restriction_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Every recorded event (IMPOSED/CLEARED/EXPIRED) for an agent, or for
        one specific restriction_id -- the append-only audit trail."""
        with self._lock:
            if restriction_id is not None:
                cur = self._conn.execute(
                    "SELECT * FROM restriction_events WHERE deployment_namespace = ? "
                    "AND agent_id = ? AND restriction_id = ? ORDER BY id",
                    (namespace, agent_id, restriction_id),
                )
            else:
                cur = self._conn.execute(
                    "SELECT * FROM restriction_events WHERE deployment_namespace = ? "
                    "AND agent_id = ? ORDER BY id", (namespace, agent_id),
                )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    # -- durable live authority + permission budgets ---------------------
    #
    # See the live_authority_agents / live_authority table comments in
    # _init_db for the initialization-marker rationale and the scoping
    # rationale (namespace + agent_id, deliberately not envelope_fingerprint).
    #
    # Permission sets are passed as (name, scope, max_budget) tuples --
    # this module has no dependency on chainmail.core.Permission, keeping
    # the storage layer's own API narrow: a proposal (agent-controlled) never
    # reaches these methods directly, only ChainmailGovernor's own resolved
    # (namespace, agent_id, name, scope) keys do.

    def _signing_key(self) -> Tuple[Optional[str], Optional[bytes]]:
        """The current ``(key_id, key)`` to MAC new/updated rows with, or
        ``(None, None)`` when no ``KeyProvider`` is configured (unauthenticated
        mode -- rows are written with ``mac``/``key_id`` left NULL, exactly
        the schema-v5 behaviour)."""
        if self._key_provider is None:
            return None, None
        return self._key_provider.current()

    def _verify_mac(self, *, stored_mac: Optional[str], key_id: Optional[str],
                    parts: Tuple[Any, ...], context: str) -> None:
        """Recompute the MAC over ``parts`` and compare to ``stored_mac``,
        raising ``RowIntegrityError`` on any mismatch. No-op if no
        ``KeyProvider`` is configured -- authentication is opt-in, and an
        unconfigured store must keep reading rows exactly as schema v5 did.
        """
        if self._key_provider is None:
            return
        if key_id is None or stored_mac is None:
            raise RowIntegrityError(
                f"{context}: keyed authentication is enabled but this row has no "
                f"mac/key_id (a legacy row from before authentication was enabled, "
                f"or a row inserted without going through SQLiteStore's write API) "
                f"-- refusing to trust it"
            )
        key = self._key_provider.get(key_id)
        if key is None:
            raise RowIntegrityError(
                f"{context}: no key registered for key_id={key_id!r} -- cannot "
                f"verify this row's mac; refusing to trust it"
            )
        expected = _row_mac(key, *parts)
        if not hmac.compare_digest(expected, stored_mac):
            raise RowIntegrityError(
                f"{context}: mac does not match row contents -- the row was "
                f"modified outside SQLiteStore's write API"
            )

    def _append_initialization_ledger_entry(self, *, namespace: str, agent_id: str,
                                            initialized_at: float, key_id: str,
                                            key: bytes) -> None:
        """Append one entry to ``initialization_ledger``, chained onto
        whatever the current tip's ``mac`` is (or ``LEDGER_GENESIS`` for the
        very first entry ever written). Must be called inside the same
        transaction as the ``live_authority_agents`` marker insert it
        accompanies -- see ``_mark_agent_initialized``.
        """
        prev = self._conn.execute(
            "SELECT mac FROM initialization_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_mac = prev[0] if prev is not None else LEDGER_GENESIS
        mac = _row_mac(key, prev_mac, namespace, agent_id, initialized_at)
        self._conn.execute(
            "INSERT INTO initialization_ledger (deployment_namespace, agent_id, "
            "initialized_at, prev_mac, mac, key_id) VALUES (?, ?, ?, ?, ?, ?)",
            (namespace, agent_id, initialized_at, prev_mac, mac, key_id),
        )

    def _verify_hash_chain(self, *, chain_name: str,
                          rows: Iterable[Tuple[str, str, Optional[str], Optional[str],
                                              Tuple[Any, ...]]]) -> None:
        """Generic O(n) hash-chain verification shared by every append-only
        ledger table (``initialization_ledger``, ``restriction_ledger``,
        ...). Each item in ``rows`` is ``(identity_label, prev_mac, mac,
        key_id, content_parts)``, ordered oldest-to-newest. Raises
        ``RowIntegrityError`` on the first break -- an entry deleted,
        reordered, or inserted without going through ``SQLiteStore``'s own
        write API. Does **not** catch the chain's current tip being
        deleted (nothing chained after it yet leaves everything before it
        self-consistent) -- see the callers' own docstrings for that
        residual, documented limit, which is the same rollback/truncation
        gap docs/DURABILITY.md tracks as needing an external checkpoint.
        """
        expected_prev = LEDGER_GENESIS
        for identity, prev_mac, mac, key_id, content_parts in rows:
            if prev_mac != expected_prev:
                raise RowIntegrityError(
                    f"{chain_name}({identity}): prev_mac does not match the preceding "
                    f"entry's mac -- an entry was deleted, reordered, or inserted "
                    f"without going through SQLiteStore's write API"
                )
            self._verify_mac(
                stored_mac=mac, key_id=key_id, parts=(prev_mac,) + content_parts,
                context=f"{chain_name}({identity})",
            )
            expected_prev = mac

    def _verify_ledger_chain(self) -> None:
        """Full verification of ``initialization_ledger``'s hash chain, from
        genesis to the current tip -- O(n) in the number of agents ever
        initialized. Run once at construction (see ``_init_db``), not on
        the per-request hot path (``is_authority_initialized`` does a
        cheaper single-row cross-check instead, see its docstring). Also
        exposed as ``verify_integrity_ledger`` for on-demand use.
        """
        if self._key_provider is None:
            return
        rows = self._conn.execute(
            "SELECT seq, deployment_namespace, agent_id, initialized_at, prev_mac, mac, "
            "key_id FROM initialization_ledger ORDER BY seq"
        ).fetchall()
        self._verify_hash_chain(
            chain_name="initialization_ledger",
            rows=(
                (f"seq={seq}", prev_mac, mac, key_id, (namespace, agent_id, initialized_at))
                for seq, namespace, agent_id, initialized_at, prev_mac, mac, key_id in rows
            ),
        )

    def _verify_restriction_ledger_chain(self) -> None:
        """Full verification of ``restriction_ledger``'s hash chain -- the
        same mechanism as ``_verify_ledger_chain``, generalized to
        restriction IMPOSED/EXPIRED/CLEARED transitions (see
        ``active_restrictions``'s cheaper, per-call cross-check and this
        method's shared caller ``verify_integrity_ledger``)."""
        if self._key_provider is None:
            return
        rows = self._conn.execute(
            "SELECT seq, deployment_namespace, agent_id, restriction_id, event_type, "
            "permission_name, permission_scope, permission_max_budget, expiry_kind, "
            "expiry_value, prev_mac, mac, key_id FROM restriction_ledger ORDER BY seq"
        ).fetchall()
        self._verify_hash_chain(
            chain_name="restriction_ledger",
            rows=(
                (f"seq={seq}", prev_mac, mac, key_id,
                 (namespace, agent_id, restriction_id, event_type, permission_name,
                  permission_scope, permission_max_budget, expiry_kind, expiry_value))
                for seq, namespace, agent_id, restriction_id, event_type, permission_name,
                    permission_scope, permission_max_budget, expiry_kind, expiry_value,
                    prev_mac, mac, key_id in rows
            ),
        )

    def verify_integrity_ledger(self) -> None:
        """Public, on-demand full verification of every append-only ledger's
        hash chain (``initialization_ledger`` and ``restriction_ledger`` --
        see ``_verify_ledger_chain``/``_verify_restriction_ledger_chain``
        for what each does and does not catch). Intended for operator/
        health-check use -- SQLiteStore already runs both once at
        construction; nothing on the per-request path re-runs the full O(n)
        walk. Raises ``RowIntegrityError`` on any break; a no-op if no
        ``key_provider`` is configured."""
        with self._lock:
            self._verify_ledger_chain()
            self._verify_restriction_ledger_chain()

    @property
    def rollback_protected(self) -> bool:
        """Whether a ``RollbackCheckpoint`` is configured (see
        docs/DURABILITY.md). False means this store's row-level MAC/ledger
        coverage (schema v6-v9) still detects tampering with individual
        rows or their deletion, but a whole-database rollback to an
        earlier, internally-valid backup is NOT detected -- see
        ``ChainmailGovernor.security_report()``, which surfaces this."""
        return self._rollback_checkpoint is not None

    @property
    def row_authentication_configured(self) -> bool:
        """Whether a ``KeyProvider`` is configured (see docs/DURABILITY.md).
        False means every durable row is read/written exactly as
        unauthenticated schema-v5 ``SQLiteStore`` was -- no MAC is checked
        or written, so a row edited, replaced, or inserted outside this
        class's own write API is silently trusted."""
        return self._key_provider is not None

    def advance_checkpoint(self) -> int:
        """Atomically bump this store's local rollback-checkpoint sequence,
        then push the same new value to the external ``RollbackCheckpoint``.
        Returns the new sequence number. Raises ``ValueError`` if no
        ``rollback_checkpoint`` is configured -- there is nothing to
        protect against rollback, so calling this is a caller bug.

        Two-phase, in this order: the local bump commits first (a real,
        atomic SQLite transaction); only then is the external checkpoint's
        ``advance`` called with that exact value. If the external call then
        fails or raises, the local sequence is already ahead of the
        external checkpoint -- exactly the "crashed between phases" window
        ``_check_rollback_checkpoint`` self-heals from on the next open
        (advancing the external checkpoint to match, since local-ahead is
        not itself a rollback signal), never a silent gap that looks like a
        validated advance. This deliberately never advances the checkpoint
        as a separate, unsynchronised write disconnected from what it
        protects -- the pushed value is always exactly the value this call
        just durably committed locally.

        Callers decide how often to call this and after which writes --
        there is no one-size-fits-all policy (a TPM counter increment may
        be expensive or rate-limited; a remote attestation call may be
        cheap and worth doing after every proposal). This method provides
        the mechanism, not a policy for when to invoke it.
        """
        if self._rollback_checkpoint is None:
            raise ValueError(
                "advance_checkpoint() called without a rollback_checkpoint configured"
            )
        with self._lock:
            row = self._conn.execute(
                "SELECT seq FROM rollback_checkpoint_state WHERE id = 1"
            ).fetchone()
            new_seq = (row[0] if row is not None else 0) + 1
            self._conn.execute(
                "INSERT INTO rollback_checkpoint_state (id, seq) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET seq = excluded.seq",
                (new_seq,),
            )
            self._conn.commit()
        self._rollback_checkpoint.advance(new_seq)
        return new_seq

    def _mark_agent_initialized(self, *, namespace: str, agent_id: str, now: float,
                               key_id: Optional[str], key: Optional[bytes]) -> bool:
        """Attempt the ``live_authority_agents`` marker INSERT; on success,
        atomically append the chained ``initialization_ledger`` entry too
        (when authenticated) in the same transaction, so the two can never
        disagree about whether *this* call actually performed the
        initialization. Returns True if this call performed it, False if
        the agent was already initialized (a no-op, caller decides what
        that means -- see ``initialize_agent_authority`` /
        ``replace_live_authority``).
        """
        marker_mac = _row_mac(key, namespace, agent_id, now) if key is not None else None
        try:
            self._conn.execute(
                "INSERT INTO live_authority_agents (deployment_namespace, agent_id, "
                "initialized_at, mac, key_id) VALUES (?, ?, ?, ?, ?)",
                (namespace, agent_id, now, marker_mac, key_id),
            )
        except sqlite3.IntegrityError:
            return False
        if key is not None:
            self._append_initialization_ledger_entry(
                namespace=namespace, agent_id=agent_id, initialized_at=now,
                key_id=key_id, key=key,
            )
        return True

    def is_authority_initialized(self, *, namespace: str, agent_id: str) -> bool:
        """Whether ``(namespace, agent_id)`` has ever been initialized.

        When a ``key_provider`` is configured, this also cross-checks the
        ``live_authority_agents`` marker row's presence against the
        ``initialization_ledger`` entry's presence for the same
        ``(namespace, agent_id)`` -- a single indexed lookup, not a chain
        walk. A marker row deleted directly (bypassing ``SQLiteStore``'s
        write API) while its ledger entry survives is caught here,
        immediately, on the very next call: the two disagreeing about
        whether this agent was ever initialized is itself the tamper
        signal, raised as ``RowIntegrityError`` (fail closed) rather than
        silently trusting whichever one says "not initialized" (which
        would let a deleted marker re-seed authority at the envelope
        ceiling -- exactly invariant #1's "restart must never increase
        authority", laundered via direct file tampering instead of a
        restart). Deleting *both* together isn't caught by this cheap
        check -- see ``_verify_ledger_chain`` for what closes (most of)
        that instead, and its own documented limit.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT initialized_at, mac, key_id FROM live_authority_agents "
                "WHERE deployment_namespace = ? AND agent_id = ?", (namespace, agent_id),
            ).fetchone()
            marker_exists = row is not None
            if marker_exists:
                initialized_at, mac, key_id = row
                self._verify_mac(
                    stored_mac=mac, key_id=key_id, parts=(namespace, agent_id, initialized_at),
                    context=f"live_authority_agents({namespace!r}, {agent_id!r})",
                )
            if self._key_provider is not None:
                ledger_row = self._conn.execute(
                    "SELECT initialized_at, prev_mac, mac, key_id FROM initialization_ledger "
                    "WHERE deployment_namespace = ? AND agent_id = ?", (namespace, agent_id),
                ).fetchone()
                ledger_exists = ledger_row is not None
                if ledger_exists:
                    l_initialized_at, prev_mac, l_mac, l_key_id = ledger_row
                    self._verify_mac(
                        stored_mac=l_mac, key_id=l_key_id,
                        parts=(prev_mac, namespace, agent_id, l_initialized_at),
                        context=f"initialization_ledger({namespace!r}, {agent_id!r})",
                    )
                if marker_exists != ledger_exists:
                    raise RowIntegrityError(
                        f"live_authority_agents/initialization_ledger disagree about "
                        f"whether ({namespace!r}, {agent_id!r}) was ever initialized "
                        f"-- marker {'exists' if marker_exists else 'is absent'} but "
                        f"ledger entry {'exists' if ledger_exists else 'is absent'}; a "
                        f"row was deleted without going through SQLiteStore's write API"
                    )
            return marker_exists

    def initialize_agent_authority(self, *, namespace: str, agent_id: str,
                                   permissions: Iterable[Tuple[str, str, Optional[int]]],
                                   envelope_fingerprint: Optional[str]) -> bool:
        """Seed ``agent_id``'s durable live authority from ``permissions``
        -- but only the first time this is ever called for this
        ``(namespace, agent_id)``. Returns True if this call performed the
        seeding, False if the agent was already initialized (a no-op -- the
        existing durable state, however it got there, is authoritative and
        must never be silently overwritten by envelope-ceiling values on a
        later restart; that would restore previously delegated-away or
        consumed authority, which invariant #1 forbids).

        Atomic: the initialization marker and every permission row are
        written in one transaction, so a crash partway through can never
        leave a marked-initialized agent with a partial permission set.
        """
        now = time.time()
        key_id, key = self._signing_key()
        with self._lock:
            if not self._mark_agent_initialized(
                    namespace=namespace, agent_id=agent_id, now=now, key_id=key_id, key=key):
                self._conn.rollback()
                return False
            for name, scope, max_budget in permissions:
                row_mac = (
                    _row_mac(key, namespace, agent_id, name, scope, max_budget, max_budget)
                    if key is not None else None
                )
                self._conn.execute(
                    "INSERT INTO live_authority (deployment_namespace, agent_id, "
                    "permission_name, permission_scope, max_budget, remaining, source, "
                    "envelope_fingerprint, created_at, updated_at, mac, key_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'envelope_ceiling', ?, ?, ?, ?, ?)",
                    (namespace, agent_id, name, scope, max_budget, max_budget,
                     envelope_fingerprint, now, now, row_mac, key_id),
                )
            self._conn.commit()
            return True

    def get_live_authority_rows(self, *, namespace: str, agent_id: str) -> List[Dict[str, Any]]:
        """Every current permission row for ``(namespace, agent_id)``. An
        empty list is a valid, meaningful answer once the agent is
        initialized (zero permissions is a legitimate state, e.g. fully
        delegated away) -- callers that need to distinguish "not yet
        initialized" from "legitimately zero permissions" must check
        ``is_authority_initialized`` separately.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT permission_name, permission_scope, max_budget, remaining, mac, key_id "
                "FROM live_authority WHERE deployment_namespace = ? AND agent_id = ?",
                (namespace, agent_id),
            )
            cols = [d[0] for d in cur.description]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
            for row in rows:
                self._verify_mac(
                    stored_mac=row["mac"], key_id=row["key_id"],
                    parts=(namespace, agent_id, row["permission_name"], row["permission_scope"],
                           row["max_budget"], row["remaining"]),
                    context=(
                        f"live_authority({namespace!r}, {agent_id!r}, "
                        f"{row['permission_name']!r}, {row['permission_scope']!r})"
                    ),
                )
                del row["mac"], row["key_id"]
            return rows

    def replace_live_authority(self, *, namespace: str, agent_id: str,
                               permissions: Iterable[Tuple[str, str, Optional[int]]],
                               source: str, envelope_fingerprint: Optional[str]) -> None:
        """Atomically replace ``agent_id``'s entire durable permission set
        with ``permissions``. Used by delegation and revocation -- the old
        rows are deleted and the new ones inserted in one transaction, so a
        reader can never observe a mix of old and new permissions, and a
        crash partway through leaves the pre-transaction state intact
        (SQLite rolls back an uncommitted transaction automatically). Also
        marks the agent initialized (idempotent) so a later restart never
        re-seeds from the envelope ceiling over this.
        """
        now = time.time()
        key_id, key = self._signing_key()
        with self._lock:
            # Already initialized -- this call still replaces the rows
            # below; no rollback here (unlike initialize_agent_authority's
            # own use of this helper), the transaction continues.
            self._mark_agent_initialized(
                namespace=namespace, agent_id=agent_id, now=now, key_id=key_id, key=key)
            self._conn.execute(
                "DELETE FROM live_authority WHERE deployment_namespace = ? AND agent_id = ?",
                (namespace, agent_id),
            )
            for name, scope, max_budget in permissions:
                row_mac = (
                    _row_mac(key, namespace, agent_id, name, scope, max_budget, max_budget)
                    if key is not None else None
                )
                self._conn.execute(
                    "INSERT INTO live_authority (deployment_namespace, agent_id, "
                    "permission_name, permission_scope, max_budget, remaining, source, "
                    "envelope_fingerprint, created_at, updated_at, mac, key_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (namespace, agent_id, name, scope, max_budget, max_budget,
                     source, envelope_fingerprint, now, now, row_mac, key_id),
                )
            self._conn.commit()

    def consume_permission_budget(self, *, namespace: str, agent_id: str, permission_name: str,
                                  permission_scope: str, amount: int = 1) -> bool:
        """Atomically consume ``amount`` from the durable budget for one
        specific permission -- a single UPDATE, never a SELECT followed by
        a separate UPDATE, so two governor processes racing to spend the
        last unit of a budget cannot both succeed: whichever UPDATE commits
        first leaves too little for the second, whose WHERE clause then
        matches zero rows.

        A permission with ``max_budget IS NULL`` (unlimited) always
        succeeds without decrementing anything. Returns True if consumption
        succeeded (or the permission is unlimited), False if the row does
        not exist or has insufficient remaining budget -- the caller must
        treat False as "do not proceed" (fail closed), never retry with the
        same amount expecting a different outcome.
        """
        key_id, key = self._signing_key()
        with self._lock:
            # RETURNING keeps the mac refresh (below) inside the same
            # transaction as the consume itself -- both happen under the
            # single write lock this connection already holds for the
            # whole call, so no concurrent consumer can observe a row whose
            # `remaining` was decremented but whose `mac` still reflects
            # the pre-consume value (which would itself look like tampering
            # to the next verifying read).
            cur = self._conn.execute(
                "UPDATE live_authority SET "
                "remaining = CASE WHEN max_budget IS NULL THEN remaining ELSE remaining - ? END, "
                "updated_at = ? "
                "WHERE deployment_namespace = ? AND agent_id = ? AND permission_name = ? "
                "AND permission_scope = ? AND (max_budget IS NULL OR remaining >= ?) "
                "RETURNING id, max_budget, remaining",
                (amount, time.time(), namespace, agent_id, permission_name, permission_scope, amount),
            )
            row = cur.fetchone()
            if row is None:
                self._conn.commit()
                return False
            if key is not None:
                row_id, max_budget, remaining = row
                new_mac = _row_mac(key, namespace, agent_id, permission_name, permission_scope,
                                   max_budget, remaining)
                self._conn.execute(
                    "UPDATE live_authority SET mac = ?, key_id = ? WHERE id = ?",
                    (new_mac, key_id, row_id),
                )
            self._conn.commit()
            return True

    # -- durable step (runtime) budgets -----------------------------------

    def increment_step_counter(self, *, namespace: str, scope: str,
                               max_allowed: Optional[int]) -> Tuple[int, bool]:
        """Atomically increment the durable counter for ``scope`` (e.g.
        ``"fleet"`` or ``f"agent:{agent_id}"``) within ``namespace`` and
        return ``(new_count, within_budget)``. ``within_budget`` is True
        when ``max_allowed`` is None (no cap) or ``new_count <= max_allowed``.

        The increment (UPSERT) and the read of the resulting value happen
        inside one transaction on this connection -- SQLite holds the write
        lock for the whole transaction, so no other writer's increment can
        land between them; the count this call observes is exactly the
        count its own increment produced, making concurrent increments
        from multiple processes safely serialised rather than lost.
        """
        now = time.time()
        key_id, key = self._signing_key()
        with self._lock:
            if key is not None:
                # Verify the pre-increment row (if any) before building on
                # top of it -- a tampered count (e.g. reset to 0 to renew a
                # step budget) must be caught here, not silently
                # incremented from the forged value. This SELECT doesn't
                # reintroduce a check-then-write race for the counter
                # itself: the increment below remains a single atomic
                # UPSERT, this only decides whether to trust what it's
                # incrementing from.
                existing = self._conn.execute(
                    "SELECT count, mac, key_id FROM step_counters WHERE "
                    "deployment_namespace = ? AND scope = ?", (namespace, scope),
                ).fetchone()
                if existing is not None:
                    existing_count, existing_mac, existing_key_id = existing
                    self._verify_mac(
                        stored_mac=existing_mac, key_id=existing_key_id,
                        parts=(namespace, scope, existing_count),
                        context=f"step_counters({namespace!r}, {scope!r})",
                    )
            self._conn.execute(
                "INSERT INTO step_counters (deployment_namespace, scope, count, updated_at) "
                "VALUES (?, ?, 1, ?) "
                "ON CONFLICT(deployment_namespace, scope) DO UPDATE SET "
                "count = count + 1, updated_at = excluded.updated_at",
                (namespace, scope, now),
            )
            row = self._conn.execute(
                "SELECT count FROM step_counters WHERE deployment_namespace = ? AND scope = ?",
                (namespace, scope),
            ).fetchone()
            new_count = row[0]
            if key is not None:
                new_mac = _row_mac(key, namespace, scope, new_count)
                self._conn.execute(
                    "UPDATE step_counters SET mac = ?, key_id = ? WHERE deployment_namespace = ? "
                    "AND scope = ?", (new_mac, key_id, namespace, scope),
                )
            self._conn.commit()
            within = max_allowed is None or new_count <= max_allowed
            return new_count, within

    def peek_step_counter(self, *, namespace: str, scope: str) -> int:
        """Read the current count for ``scope`` without incrementing it --
        for startup, to sync an in-memory mirror (``step_count``,
        ``_agent_steps``) to the durable value instead of resetting it to
        zero. Returns 0 if the scope has no row yet (never incremented)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT count, mac, key_id FROM step_counters WHERE deployment_namespace = ? "
                "AND scope = ?", (namespace, scope),
            ).fetchone()
            if row is None:
                return 0
            count, mac, key_id = row
            self._verify_mac(
                stored_mac=mac, key_id=key_id, parts=(namespace, scope, count),
                context=f"step_counters({namespace!r}, {scope!r})",
            )
            return count

    def log_proposal(self, *, proposal_id: str, agent_id: str, action: str, decision: str,
                     signals: List[str], overlap: float, drift: float, phase: str,
                     execution_id: Optional[str] = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO proposals (record_version, proposal_id, agent_id, action, decision, "
                "signals, overlap, drift, timestamp, execution_id, phase) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (RECORD_VERSION, proposal_id, agent_id, action, decision,
                 json.dumps(signals), overlap, drift, time.time(), execution_id, phase),
            )
            self._conn.commit()

    def log_delegation(self, *, from_agent: str, to_agent: str, reason: str, authority: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO delegations (record_version, from_agent, to_agent, reason, authority, "
                "timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (RECORD_VERSION, from_agent, to_agent, reason, authority, time.time()),
            )
            self._conn.commit()

    def get_proposal_history(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if agent_id:
                cur = self._conn.execute(
                    "SELECT * FROM proposals WHERE agent_id = ? ORDER BY timestamp, id", (agent_id,)
                )
            else:
                cur = self._conn.execute("SELECT * FROM proposals ORDER BY timestamp, id")
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def prune(self, *, before_timestamp: Optional[float] = None, keep_last: Optional[int] = None) -> int:
        """Delete old ``proposals`` rows. Returns the number removed."""
        with self._lock:
            removed = 0
            if before_timestamp is not None:
                cur = self._conn.execute(
                    "DELETE FROM proposals WHERE timestamp < ?", (before_timestamp,)
                )
                removed += cur.rowcount
            if keep_last is not None:
                cur = self._conn.execute(
                    "DELETE FROM proposals WHERE id NOT IN "
                    "(SELECT id FROM proposals ORDER BY id DESC LIMIT ?)", (keep_last,)
                )
                removed += cur.rowcount
            self._conn.commit()
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return removed

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ============================================================================
# Composed audit sink
# ============================================================================

class AuditSink:
    """Writes each governance event to the hash-chain and/or SQLite. Either may
    be ``None``. A raised exception is the caller's signal to fail closed."""

    def __init__(self, hash_chain: Optional[HashChainLog] = None,
                 sqlite_store: Optional[SQLiteStore] = None) -> None:
        self.hash_chain = hash_chain
        self.sqlite = sqlite_store

    @property
    def active(self) -> bool:
        return self.hash_chain is not None or self.sqlite is not None

    def record_proposal(self, *, proposal_id: str, agent_id: str, action: str, decision: str,
                        signals: List[str], overlap: float, drift: float, phase: str,
                        execution_id: Optional[str], execution_output: Any = None,
                        objective_fragment: Optional[str] = None,
                        trace_id: Optional[str] = None) -> None:
        if self.hash_chain is not None:
            self.hash_chain.append("proposal", {
                "proposal_id": proposal_id, "agent_id": agent_id, "action": action,
                "decision": decision, "signals": signals,
                "objective_fragment": scrub_pii(objective_fragment) if objective_fragment else None,
                "overlap": round(overlap, 4), "drift": round(drift, 4),
                "execution_output": execution_output, "trace_id": trace_id,
            }, phase=phase, execution_id=execution_id)
        if self.sqlite is not None:
            self.sqlite.log_proposal(
                proposal_id=proposal_id, agent_id=agent_id, action=action, decision=decision,
                signals=signals, overlap=round(overlap, 4), drift=round(drift, 4),
                phase=phase, execution_id=execution_id,
            )

    def record_delegation(self, *, from_agent: str, to_agent: str, reason: str,
                          authority_repr: str) -> None:
        reason = scrub_pii(reason)
        if self.hash_chain is not None:
            self.hash_chain.append("delegation", {
                "from": from_agent, "to": to_agent, "reason": reason, "authority": authority_repr,
            })
        if self.sqlite is not None:
            self.sqlite.log_delegation(
                from_agent=from_agent, to_agent=to_agent, reason=reason, authority=authority_repr,
            )
