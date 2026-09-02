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
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .redaction import scrub_pii

logger = logging.getLogger(__name__)

RECORD_VERSION = 1
GENESIS_HASH = "0" * 64


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
    SCHEMA_VERSION = 4

    def __init__(self, db_path: str = ":memory:", *, synchronous: str = "FULL") -> None:
        if synchronous.upper() not in ("FULL", "NORMAL", "OFF"):
            raise ValueError(f"synchronous must be FULL, NORMAL, or OFF, got {synchronous!r}")
        self.db_path = db_path
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
                    cleared_policy_version TEXT
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
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_agent ON proposals(agent_id)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_ts ON proposals(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_pid ON proposals(proposal_id)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_deleg_from ON delegations(from_agent)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_restrictions_active "
                     "ON restrictions(deployment_namespace, agent_id, status)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_restriction_events_rid "
                     "ON restriction_events(restriction_id)")
            if migrating:
                self._migrate_replay_data_from_v2(c)
            c.commit()

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
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO replay_nonces "
                    "(deployment_namespace, agent_id, nonce, key_id, envelope_fingerprint, "
                    "claimed_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (namespace, agent_id, nonce, key_id, envelope_fingerprint, time.time()),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

    def claim_proposal_id(self, *, namespace: str, proposal_id: str, agent_id: str,
                          envelope_fingerprint: Optional[str] = None) -> bool:
        """Atomically claim ``proposal_id`` fleet-wide within ``namespace``.

        Uniqueness is ``(namespace, proposal_id)`` only. Same return/exception
        contract as ``claim_nonce``.
        """
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO replay_proposal_ids "
                    "(deployment_namespace, proposal_id, agent_id, envelope_fingerprint, "
                    "claimed_at) VALUES (?, ?, ?, ?, ?)",
                    (namespace, proposal_id, agent_id, envelope_fingerprint, time.time()),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
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
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO restrictions (restriction_id, deployment_namespace, agent_id, "
                    "permission_name, permission_scope, permission_max_budget, status, "
                    "reason_code, source_proposal_id, envelope_fingerprint, expiry_kind, "
                    "expiry_value, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?)",
                    (restriction_id, namespace, agent_id, permission_name, permission_scope,
                     permission_max_budget, reason_code, source_proposal_id, envelope_fingerprint,
                     expiry_kind, expiry_value, now, now),
                )
                self._conn.execute(
                    "INSERT INTO restriction_events (restriction_id, deployment_namespace, "
                    "agent_id, event_type, permission_name, permission_scope, reason_code, "
                    "source_proposal_id, envelope_fingerprint, actor, detail, timestamp) "
                    "VALUES (?, ?, ?, 'IMPOSED', ?, ?, ?, ?, ?, ?, ?, ?)",
                    (restriction_id, namespace, agent_id, permission_name, permission_scope,
                     reason_code, source_proposal_id, envelope_fingerprint, None, None, now),
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
                "permission_max_budget, expiry_kind, expiry_value FROM restrictions "
                "WHERE deployment_namespace = ? AND agent_id = ? AND status = 'ACTIVE'",
                (namespace, agent_id),
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def mark_expired(self, *, namespace: str, agent_id: str, restriction_id: str) -> bool:
        """Atomically transition one restriction ACTIVE -> EXPIRED.

        Returns True if this call performed the transition, False if it was
        already non-ACTIVE (idempotent no-op) -- never raises on a
        already-cleared/expired restriction, only on a genuine store error.
        """
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE restrictions SET status = 'EXPIRED', updated_at = ? "
                "WHERE restriction_id = ? AND deployment_namespace = ? AND agent_id = ? "
                "AND status = 'ACTIVE'",
                (now, restriction_id, namespace, agent_id),
            )
            if cur.rowcount:
                row = self._conn.execute(
                    "SELECT permission_name, permission_scope FROM restrictions "
                    "WHERE restriction_id = ?", (restriction_id,),
                ).fetchone()
                self._conn.execute(
                    "INSERT INTO restriction_events (restriction_id, deployment_namespace, "
                    "agent_id, event_type, permission_name, permission_scope, timestamp) "
                    "VALUES (?, ?, ?, 'EXPIRED', ?, ?, ?)",
                    (restriction_id, namespace, agent_id, row[0], row[1], now),
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
        with self._lock:
            cur = self._conn.execute(
                "UPDATE restrictions SET status = 'CLEARED', updated_at = ?, cleared_by = ?, "
                "cleared_reason = ?, cleared_policy_version = ? WHERE restriction_id = ? AND "
                "deployment_namespace = ? AND agent_id = ? AND status = 'ACTIVE'",
                (now, authorised_by, reason, policy_version, restriction_id, namespace, agent_id),
            )
            if cur.rowcount:
                row = self._conn.execute(
                    "SELECT permission_name, permission_scope FROM restrictions "
                    "WHERE restriction_id = ?", (restriction_id,),
                ).fetchone()
                self._conn.execute(
                    "INSERT INTO restriction_events (restriction_id, deployment_namespace, "
                    "agent_id, event_type, permission_name, permission_scope, actor, detail, "
                    "timestamp) VALUES (?, ?, ?, 'CLEARED', ?, ?, ?, ?, ?)",
                    (restriction_id, namespace, agent_id, row[0], row[1], authorised_by, reason, now),
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
