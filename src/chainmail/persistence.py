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

    # -- append -------------------------------------------------------
    def append(self, entry_type: str, data: Dict[str, Any], *, phase: str = "completed",
               execution_id: Optional[str] = None) -> str:
        with self._lock:
            verification = self.verify()
            if not verification.valid:
                raise ReceiptIntegrityError(
                    f"refusing to extend corrupt receipt chain at record "
                    f"{verification.failed_record}: {verification.reason}"
                )
            entry = {
                "record_version": RECORD_VERSION,
                "type": entry_type,
                "data": sanitize(data),
                "phase": phase,
                "execution_id": execution_id,
                "timestamp": time.time(),
                "prev_hash": verification.last_valid_hash,
                "nonce": secrets.token_hex(8),
            }
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
            entry["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
            self.entries.append(entry)
            if self.filepath:
                path = Path(self.filepath).expanduser().resolve()
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, default=str) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            return entry["hash"]


# ============================================================================
# SQLite store
# ============================================================================

class SQLiteStore:
    # v1: proposals, delegations. v2: + replay_nonces, replay_proposal_ids
    # (durable replay protection -- see claim_nonce / claim_proposal_id).
    SCHEMA_VERSION = 2

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
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
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = c.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                c.execute("INSERT INTO schema_version (version) VALUES (?)", (self.SCHEMA_VERSION,))
            elif row[0] < self.SCHEMA_VERSION:
                # Table creation below is idempotent (CREATE TABLE IF NOT EXISTS) and
                # additive-only, so an older database just gains the new tables here.
                logger.info("migrating SQLiteStore schema %s -> %s", row[0], self.SCHEMA_VERSION)
                c.execute("UPDATE schema_version SET version = ?", (self.SCHEMA_VERSION,))
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
            # Durable replay protection. ``scope`` encodes the binding described in
            # claim_nonce()/claim_proposal_id(): deployment namespace + envelope
            # (policy) fingerprint, plus agent_id for nonces. The UNIQUE constraint
            # is the whole point -- claims are a single atomic INSERT, never a
            # separate SELECT-then-INSERT, so two governor processes racing on the
            # same identifier cannot both succeed (the loser gets an
            # IntegrityError, which the caller reads as "replay").
            c.execute("""
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    key_id TEXT,
                    envelope_fingerprint TEXT NOT NULL,
                    claimed_at REAL NOT NULL,
                    UNIQUE (scope, nonce)
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS replay_proposal_ids (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    envelope_fingerprint TEXT NOT NULL,
                    claimed_at REAL NOT NULL,
                    UNIQUE (scope, proposal_id)
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_agent ON proposals(agent_id)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_ts ON proposals(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_proposals_pid ON proposals(proposal_id)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_deleg_from ON delegations(from_agent)")
            c.commit()

    # -- durable replay protection -------------------------------------
    #
    # Scope (see the table comments above for the schema):
    #   * Nonces are unique per (deployment namespace, envelope/policy
    #     fingerprint, agent_id). Nonce uniqueness is PER AGENT: a nonce is
    #     bound to whichever key signed the proposal that carries it, and
    #     keys are themselves agent-bound (KeyRegistry.resolve), so a nonce
    #     collision between two different agents is not the replay this
    #     defends against -- it would already be caught by signature/key
    #     binding. Scoping per agent also means agent A's nonce space can
    #     never be exhausted or polluted by agent B's traffic.
    #   * Proposal IDs are unique per (deployment namespace, envelope/policy
    #     fingerprint) -- fleet-wide, across all agents. This matches the
    #     pre-durability in-memory behaviour (a single process-wide
    #     ``_seen_proposal_ids`` set) and treats proposal_id as a
    #     general-purpose idempotency key for the whole fleet, not a
    #     per-agent one.
    #   * Both are scoped to the envelope's construction fingerprint, so a
    #     legitimate policy/envelope update starts a fresh replay namespace
    #     rather than being blocked by (or silently sharing) identifiers
    #     claimed under a previous policy version.
    #   * ``deployment_namespace`` (default ``"default"``) lets multiple
    #     independent deployments share one physical database file without
    #     their replay records colliding.
    #
    # Every claim is a single atomic INSERT; a UNIQUE violation *is* the
    # replay signal, never a prior SELECT. Callers must not batch these
    # writes -- each call commits immediately, so a claim that returns True
    # is durable before the caller acts on it.

    def claim_nonce(self, *, namespace: str, envelope_fingerprint: str, agent_id: str,
                    nonce: str, key_id: Optional[str] = None) -> bool:
        """Atomically claim ``nonce`` for ``agent_id`` in this scope.

        Returns True if this call newly claimed it, False if it was already
        claimed (a replay). Any other ``sqlite3.Error`` (disk full, DB
        locked/corrupt, ...) propagates -- the caller must treat that as a
        persistence failure and fail closed, not as "not a replay".
        """
        scope = f"{namespace}:{envelope_fingerprint}:{agent_id}"
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO replay_nonces "
                    "(scope, nonce, agent_id, key_id, envelope_fingerprint, claimed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (scope, nonce, agent_id, key_id, envelope_fingerprint, time.time()),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

    def claim_proposal_id(self, *, namespace: str, envelope_fingerprint: str,
                          proposal_id: str, agent_id: str) -> bool:
        """Atomically claim ``proposal_id`` fleet-wide in this scope.

        Same return/exception contract as ``claim_nonce``.
        """
        scope = f"{namespace}:{envelope_fingerprint}"
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO replay_proposal_ids "
                    "(scope, proposal_id, agent_id, envelope_fingerprint, claimed_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (scope, proposal_id, agent_id, envelope_fingerprint, time.time()),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

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
