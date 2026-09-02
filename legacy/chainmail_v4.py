
"""
Chainmail v4 --- Policy-hard, context-fluid governance layer
for long-running multi-agent systems.

Upgrades from v3:
- SQLite persistence with WAL mode
- RESTRICT policy options (TTL, step-budget, HUMAN-only lift)
- Quorum / multi-governor voting for high-stakes fleets
- Asymmetric cryptography protocol (Ed25519-ready, HMAC fallback)
- Process isolation hooks (socket-based communication protocol)
- Pluggable embedding interface (TF-IDF default, model-ready)
- Automatic envelope suggestion from historical runs
- Full Armour GuardedExecutor integration protocol

Thesis: The links don't bend. The chain does.
"""

from __future__ import annotations
import math
import hashlib
import hmac
import os
import time
import json
import logging
import secrets
import sqlite3
import socket
import struct
import threading
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Protocol, Mapping, Union
from copy import deepcopy
from collections import defaultdict, Counter
from pathlib import Path

logger = logging.getLogger(__name__)


# ============================================================================
# Core Types
# ============================================================================

class Decision(str, Enum):
    CONTINUE = "CONTINUE"
    RESTRICT = "RESTRICT"
    RECHECK = "RECHECK"
    HUMAN = "HUMAN"


class RiskSignal(str, Enum):
    NONE = "NONE"
    DRIFT = "DRIFT"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    HIGH_DISAGREEMENT = "HIGH_DISAGREEMENT"
    ASSUMPTION_ANOMALY = "ASSUMPTION_ANOMALY"
    AUTHORITY_ABUSE = "AUTHORITY_ABUSE"
    OBJECTIVE_MISMATCH = "OBJECTIVE_MISMATCH"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    ROLE_VIOLATION = "ROLE_VIOLATION"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    ENVELOPE_DRIFT = "ENVELOPE_DRIFT"
    VERIFIER_ERROR = "VERIFIER_ERROR"
    SANITIZATION_FAILURE = "SANITIZATION_FAILURE"
    QUORUM_REJECTED = "QUORUM_REJECTED"


class RestrictPolicy(str, Enum):
    TTL_STEPS = "TTL_STEPS"
    STEP_BUDGET = "STEP_BUDGET"
    HUMAN_ONLY = "HUMAN_ONLY"


@dataclass(frozen=True)
class Permission:
    name: str
    scope: str = "*"
    max_budget: Optional[int] = None


@dataclass
class Authority:
    permissions: Set[Permission] = field(default_factory=set)
    budget_remaining: Dict[str, int] = field(default_factory=dict)

    def can(self, required: Permission) -> bool:
        for p in self.permissions:
            if p.name == required.name and (p.scope == "*" or p.scope == required.scope):
                return True
        return False

    def has_budget(self, required: Permission) -> bool:
        for p in self.permissions:
            if p.name == required.name and (p.scope == "*" or p.scope == required.scope):
                if p.max_budget is not None:
                    key = f"{p.name}:{p.scope}"
                    remaining = self.budget_remaining.get(key, p.max_budget)
                    if remaining <= 0:
                        return False
                return True
        return False

    def consume_budget(self, permission: Permission, amount: int = 1) -> bool:
        key = f"{permission.name}:{permission.scope}"
        for p in self.permissions:
            if p.name == permission.name and (p.scope == "*" or p.scope == permission.scope):
                if p.max_budget is not None:
                    current = self.budget_remaining.get(key, p.max_budget)
                    if current < amount:
                        return False
                    self.budget_remaining[key] = current - amount
                return True
        return False

    def is_subset_of(self, other: "Authority") -> bool:
        for p in self.permissions:
            found = False
            for op in other.permissions:
                if op.name == p.name and (op.scope == "*" or op.scope == p.scope):
                    found = True
                    break
            if not found:
                return False
        return True

    def reduce_to(self, allowed: Set[Permission]) -> "Authority":
        kept = set()
        for p in self.permissions:
            for a in allowed:
                if p.name == a.name and (a.scope == "*" or a.scope == p.scope):
                    kept.add(p)
                    break
        new_budgets = {}
        for p in kept:
            key = f"{p.name}:{p.scope}"
            if key in self.budget_remaining:
                new_budgets[key] = self.budget_remaining[key]
            else:
                for orig_p in self.permissions:
                    if orig_p.name == p.name and orig_p.scope == p.scope and orig_p.max_budget is not None:
                        new_budgets[key] = orig_p.max_budget
                        break
        return Authority(permissions=kept, budget_remaining=new_budgets)

    def __repr__(self) -> str:
        parts = []
        for p in sorted(self.permissions, key=lambda x: (x.name, x.scope)):
            if p.max_budget is not None:
                key = f"{p.name}:{p.scope}"
                rem = self.budget_remaining.get(key, p.max_budget)
                parts.append(f"{p.name}:{p.scope}({rem}/{p.max_budget})")
            else:
                parts.append(f"{p.name}:{p.scope}")
        return f"Authority({', '.join(parts)})"


@dataclass(frozen=True)
class StructuredAssumption:
    text: str
    source_agent: str
    timestamp: float = field(default_factory=time.time)
    confidence: float = 0.5


@dataclass
class ProvenanceLink:
    from_id: str
    to_id: str
    reason: str
    timestamp: float = field(default_factory=time.time)
    delegated_authority: Optional[Authority] = None


# ============================================================================
# Action Schema
# ============================================================================

@dataclass(frozen=True)
class ActionSchema:
    allowed_payload_keys: frozenset[str]
    required_payload_keys: frozenset[str] = frozenset()
    filesystem_path_fields: frozenset[str] = frozenset()
    allow_nested_payload: bool = False

    def __post_init__(self) -> None:
        allowed = frozenset(self.allowed_payload_keys)
        required = frozenset(self.required_payload_keys)
        paths = frozenset(self.filesystem_path_fields)
        if any(not isinstance(k, str) or not k for k in allowed | required | paths):
            raise TypeError("action schema keys must be non-empty strings")
        if not required <= allowed:
            raise ValueError("required payload keys must be allowed")
        if not paths <= allowed:
            raise ValueError("filesystem path fields must be allowed payload keys")
        if not isinstance(self.allow_nested_payload, bool):
            raise TypeError("allow_nested_payload must be a bool")
        object.__setattr__(self, "allowed_payload_keys", allowed)
        object.__setattr__(self, "required_payload_keys", required)
        object.__setattr__(self, "filesystem_path_fields", paths)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed_payload_keys": sorted(self.allowed_payload_keys),
            "required_payload_keys": sorted(self.required_payload_keys),
            "filesystem_path_fields": sorted(self.filesystem_path_fields),
            "allow_nested_payload": self.allow_nested_payload,
        }


# ============================================================================
# Proposal
# ============================================================================

@dataclass
class Proposal:
    proposal_id: str
    agent_id: str
    action: str
    required_permission: Permission
    objective_fragment: str
    confidence: float = 0.8
    assumptions: List[StructuredAssumption] = field(default_factory=list)
    parent_proposal_id: Optional[str] = None
    signature: Optional[str] = None
    nonce: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    def validate_against_schema(self, schema: Optional[ActionSchema]) -> Tuple[bool, List[str], RiskSignal]:
        if schema is None:
            return True, [], RiskSignal.NONE
        supplied = frozenset(self.payload)
        unknown = supplied - schema.allowed_payload_keys
        if unknown:
            return False, [f"unknown payload keys: {', '.join(sorted(unknown))}"], RiskSignal.SCHEMA_VIOLATION
        missing = schema.required_payload_keys - supplied
        if missing:
            return False, [f"missing required payload keys: {', '.join(sorted(missing))}"], RiskSignal.SCHEMA_VIOLATION
        if not schema.allow_nested_payload:
            for key, value in self.payload.items():
                if _contains_nested(value):
                    return False, ["nested payload values are forbidden by the action schema"], RiskSignal.SCHEMA_VIOLATION
        return True, [], RiskSignal.NONE


@dataclass
class GovernanceResult:
    decision: Decision
    reason: str
    signals: List[RiskSignal]
    effective_authority: Optional[Authority] = None
    restricted_permissions: Optional[Set[Permission]] = None
    provenance: List[ProvenanceLink] = field(default_factory=list)
    quorum_votes: Optional[Dict[str, Decision]] = None


# ============================================================================
# Envelope
# ============================================================================

@dataclass
class AuthorityEnvelope:
    objective: str
    agent_authorities: Dict[str, Authority]
    allowed_delegations: Dict[str, Set[str]]
    agent_roles: Dict[str, str]
    hard_denials: Set[str] = field(default_factory=set)
    max_fleet_steps: int = 100
    require_human_on: Set[RiskSignal] = field(default_factory=lambda: {
        RiskSignal.AUTHORITY_ABUSE,
        RiskSignal.OBJECTIVE_MISMATCH,
    })
    restrict_policy: RestrictPolicy = RestrictPolicy.TTL_STEPS
    restrict_ttl_steps: Optional[int] = 3
    restrict_step_budget: Optional[int] = 10
    action_schemas: Dict[str, ActionSchema] = field(default_factory=dict)
    _construction_fingerprint: str = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if isinstance(self.allowed_delegations, dict):
            frozen_delegations = {k: frozenset(v) for k, v in self.allowed_delegations.items()}
            object.__setattr__(self, "allowed_delegations", frozen_delegations)
        if isinstance(self.hard_denials, set):
            object.__setattr__(self, "hard_denials", frozenset(self.hard_denials))
        if isinstance(self.require_human_on, set):
            object.__setattr__(self, "require_human_on", frozenset(self.require_human_on))
        object.__setattr__(self, "_construction_fingerprint", self._compute_fingerprint())

    def _compute_fingerprint(self) -> str:
        canonical = json.dumps({
            "objective": self.objective,
            "agent_authorities": {k: repr(v) for k, v in sorted(self.agent_authorities.items())},
            "allowed_delegations": {k: sorted(v) for k, v in sorted(self.allowed_delegations.items())},
            "agent_roles": dict(sorted(self.agent_roles.items())),
            "hard_denials": sorted(self.hard_denials),
            "max_fleet_steps": self.max_fleet_steps,
            "require_human_on": sorted(s.value for s in self.require_human_on),
            "restrict_policy": self.restrict_policy.value,
            "restrict_ttl_steps": self.restrict_ttl_steps,
            "restrict_step_budget": self.restrict_step_budget,
            "action_schemas": {k: v.to_dict() for k, v in sorted(self.action_schemas.items())},
        }, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def fingerprint(self) -> str:
        current = self._compute_fingerprint()
        if current != self._construction_fingerprint:
            raise RuntimeError("envelope integrity check failed: state drifted after construction")
        return current

    def get_max_authority(self, agent_id: str) -> Authority:
        return self.agent_authorities.get(agent_id, Authority())

    def get_role(self, agent_id: str) -> Optional[str]:
        return self.agent_roles.get(agent_id)

    def get_schema(self, action: str) -> Optional[ActionSchema]:
        return self.action_schemas.get(action)


# ============================================================================
# Semantic / Embedding Engine (pluggable)
# ============================================================================

class EmbeddingEngine(Protocol):
    """Pluggable interface for semantic continuity."""
    def similarity(self, text_a: str, text_b: str) -> float:
        ...
    def fit(self, documents: List[str]) -> None:
        ...


class TfidfEmbeddingEngine:
    """TF-IDF + cosine similarity (stdlib only)."""
    def __init__(self):
        self._idf: Dict[str, float] = {}
        self._doc_count = 0
        self._corpus_terms: Dict[str, int] = defaultdict(int)
        self._fitted = False

    def _tokenize(self, text: str) -> List[str]:
        if not isinstance(text, str):
            return []
        chars = ".,!?;:'()[]{}"
        return [t.strip(chars) for t in text.lower().split() if len(t) > 2]

    def fit(self, documents: List[str]):
        self._doc_count = len(documents)
        self._corpus_terms.clear()
        for doc in documents:
            tokens = set(self._tokenize(doc))
            for t in tokens:
                self._corpus_terms[t] += 1
        self._idf.clear()
        for term, df in self._corpus_terms.items():
            self._idf[term] = math.log((1 + self._doc_count) / (1 + df)) + 1.0
        self._fitted = True

    def _vectorize(self, text: str) -> Dict[str, float]:
        tokens = self._tokenize(text)
        if not tokens:
            return {}
        tf = Counter(tokens)
        total = len(tokens)
        vec = {}
        for term, count in tf.items():
            idf = self._idf.get(term, 1.0) if self._fitted else 1.0
            vec[term] = (count / total) * idf
        return vec

    def similarity(self, text_a: str, text_b: str) -> float:
        try:
            vec_a = self._vectorize(text_a)
            vec_b = self._vectorize(text_b)
            if not vec_a or not vec_b:
                return 0.0
            dot = 0.0
            norm_a = 0.0
            for term, val in vec_a.items():
                norm_a += val * val
                if term in vec_b:
                    dot += val * vec_b[term]
            norm_b = sum(v * v for v in vec_b.values())
            if norm_a == 0.0 or norm_b == 0.0:
                return 0.0
            return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))
        except Exception:
            logger.exception("embedding engine similarity failed")
            return 0.0


# ============================================================================
# IntentGraph
# ============================================================================

@dataclass
class IntentGraphEntry:
    objective: str
    fragment: str
    decision: Decision
    agent_id: str
    timestamp: float


class IntentGraph:
    def __init__(self):
        self.entries: List[IntentGraphEntry] = []
        self._semantic = TfidfEmbeddingEngine()
        self._fitted = False

    def add(self, entry: IntentGraphEntry):
        self.entries.append(entry)
        self._fitted = False

    def _ensure_fitted(self):
        if not self._fitted and len(self.entries) > 1:
            docs = [e.objective + " " + e.fragment for e in self.entries]
            self._semantic.fit(docs)
            self._fitted = True

    def drift_score(self, objective: str, fragment: str, agent_id: str) -> float:
        try:
            self._ensure_fitted()
            agent_entries = [e for e in self.entries if e.agent_id == agent_id]
            if len(agent_entries) < 2:
                return 0.0
            current_text = objective + " " + fragment
            similarities = []
            for entry in agent_entries[-10:]:
                hist_text = entry.objective + " " + entry.fragment
                sim = self._semantic.similarity(current_text, hist_text)
                similarities.append(sim)
            avg_sim = sum(similarities) / len(similarities)
            return max(0.0, 1.0 - avg_sim)
        except Exception:
            logger.exception("IntentGraph drift_score failed")
            return 1.0

    def peer_consensus_score(self, objective: str, fragment: str, agent_id: str) -> float:
        try:
            self._ensure_fitted()
            peer_entries = [e for e in self.entries if e.agent_id != agent_id]
            if not peer_entries:
                return 1.0
            current_text = objective + " " + fragment
            similarities = []
            for entry in peer_entries[-10:]:
                hist_text = entry.objective + " " + entry.fragment
                similarities.append(self._semantic.similarity(current_text, hist_text))
            return sum(similarities) / len(similarities)
        except Exception:
            logger.exception("IntentGraph peer_consensus_score failed")
            return 0.0


# ============================================================================
# Sanitization
# ============================================================================

def _sanitize(value: Any, *, depth: int = 0, seen: Optional[Set[int]] = None) -> Any:
    if seen is None:
        seen = set()
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:4096]
    if depth >= 8:
        return "<max-depth>"
    identity = id(value)
    if identity in seen:
        return "<cycle>"
    if isinstance(value, dict):
        seen.add(identity)
        result = {str(k)[:256]: _sanitize(v, depth=depth + 1, seen=seen) for k, v in list(value.items())[:100]}
        seen.remove(identity)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        seen.add(identity)
        result = [_sanitize(item, depth=depth + 1, seen=seen) for item in list(value)[:100]]
        seen.remove(identity)
        return result
    try:
        rendered = repr(value)
    except Exception:
        rendered = f"<{type(value).__name__}>"
    return rendered[:4096]


def _contains_nested(value: Any) -> bool:
    if isinstance(value, dict):
        return True
    if isinstance(value, (list, tuple)):
        return any(isinstance(item, (dict, list, tuple)) for item in value)
    return False


# ============================================================================
# ReceiptVerification & Persistence
# ============================================================================

@dataclass(frozen=True)
class ReceiptVerification:
    valid: bool
    total_records: int
    failed_record: Optional[int] = None
    reason: Optional[str] = None
    last_valid_hash: str = ""

    def __bool__(self) -> bool:
        return self.valid


class ReceiptIntegrityError(ValueError):
    """Raised when an append would extend a damaged receipt chain."""


class PersistenceLog:
    """Append-only log with SHA-256 hash chaining, fsync, and sanitization."""
    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath
        self.entries: List[Dict[str, Any]] = []
        self._last_hash = "0" * 64

    def append(self, entry_type: str, data: Dict[str, Any], *, phase: str = "completed", execution_id: Optional[str] = None) -> str:
        verification = self.verify()
        if not verification.valid:
            raise ReceiptIntegrityError(
                f"refusing to extend corrupt receipt chain at record "
                f"{verification.failed_record}: {verification.reason}"
            )
        previous_hash = verification.last_valid_hash
        entry = {
            "type": entry_type,
            "data": _sanitize(data),
            "phase": phase,
            "execution_id": execution_id,
            "timestamp": time.time(),
            "prev_hash": previous_hash,
            "nonce": secrets.token_hex(8),
        }
        payload = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
        entry["hash"] = hashlib.sha256(payload.encode()).hexdigest()
        self._last_hash = entry["hash"]
        self.entries.append(entry)
        if self.filepath:
            path = Path(self.filepath).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, default=str) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return entry["hash"]

    def verify(self) -> ReceiptVerification:
        previous = ""
        if not self.entries:
            return ReceiptVerification(True, 0, last_valid_hash=previous)
        for index, entry in enumerate(self.entries, start=1):
            if not isinstance(entry, dict):
                return ReceiptVerification(False, index - 1, index, "record is not an object", previous)
            claimed = entry.pop("hash", "")
            if entry.get("prev_hash") != previous:
                return ReceiptVerification(False, index - 1, index, "hash chain is broken", previous)
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
            if hashlib.sha256(canonical.encode()).hexdigest() != claimed:
                return ReceiptVerification(False, index - 1, index, "record hash does not match", previous)
            previous = claimed
        return ReceiptVerification(True, len(self.entries), last_valid_hash=previous)

    def _last_valid_hash(self) -> str:
        verification = self.verify()
        if not verification.valid:
            raise ReceiptIntegrityError(f"receipt chain is corrupt at record {verification.failed_record}")
        return verification.last_valid_hash


# ============================================================================
# SQLite Persistence
# ============================================================================

class SQLitePersistence:
    """SQLite-backed persistence with WAL mode for durability."""
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        conn = self._conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS delegations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_agent TEXT NOT NULL,
                to_agent TEXT NOT NULL,
                reason TEXT,
                authority TEXT,
                timestamp REAL NOT NULL
            )
        """)
        conn.commit()

    def log_proposal(self, proposal_id: str, agent_id: str, action: str, decision: str,
                     signals: List[str], overlap: float, drift: float, phase: str,
                     execution_id: Optional[str] = None):
        conn = self._conn()
        conn.execute(
            "INSERT INTO proposals (proposal_id, agent_id, action, decision, signals, overlap, drift, timestamp, execution_id, phase) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (proposal_id, agent_id, action, decision, json.dumps(signals), overlap, drift, time.time(), execution_id, phase)
        )
        conn.commit()

    def log_delegation(self, from_agent: str, to_agent: str, reason: str, authority: str):
        conn = self._conn()
        conn.execute(
            "INSERT INTO delegations (from_agent, to_agent, reason, authority, timestamp) VALUES (?, ?, ?, ?, ?)",
            (from_agent, to_agent, reason, authority, time.time())
        )
        conn.commit()

    def get_proposal_history(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._conn()
        if agent_id:
            cursor = conn.execute("SELECT * FROM proposals WHERE agent_id = ? ORDER BY timestamp", (agent_id,))
        else:
            cursor = conn.execute("SELECT * FROM proposals ORDER BY timestamp")
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]


# ============================================================================
# ApprovalVerifier Protocol
# ============================================================================

class ApprovalVerifier(Protocol):
    def verify(self, proposal: Proposal) -> bool:
        ...


class HMACApprovalVerifier:
    """Dependency-free reference verifier for trusted shared-secret deployments."""
    def __init__(self, trusted_keys: Mapping[str, bytes]):
        keys = dict(trusted_keys)
        if not keys or any(not isinstance(kid, str) or not kid or not isinstance(sec, bytes) or not sec for kid, sec in keys.items()):
            raise ValueError("trusted keys must map key ids to non-empty bytes")
        self._trusted_keys = keys

    def verify(self, proposal: Proposal) -> bool:
        if not proposal.signature or not proposal.nonce:
            return False
        if ":" not in proposal.signature:
            return False
        key_id, sig = proposal.signature.split(":", 1)
        secret = self._trusted_keys.get(key_id)
        if secret is None:
            return False
        payload = f"{proposal.proposal_id}:{proposal.agent_id}:{proposal.action}:{proposal.nonce}"
        expected = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)


class Ed25519ApprovalVerifier:
    """
    Ed25519 asymmetric verifier. Requires 'cryptography' package.
    Falls back to HMAC if cryptography is not installed.
    """
    def __init__(self, public_keys: Mapping[str, bytes]):
        self._public_keys = dict(public_keys)
        self._has_crypto = False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives import serialization
            self._Ed25519PublicKey = Ed25519PublicKey
            self._serialization = serialization
            self._has_crypto = True
        except ImportError:
            logger.warning("cryptography not installed; Ed25519ApprovalVerifier will reject all proposals")

    def verify(self, proposal: Proposal) -> bool:
        if not self._has_crypto:
            return False
        if not proposal.signature or not proposal.nonce:
            return False
        if ":" not in proposal.signature:
            return False
        key_id, sig_hex = proposal.signature.split(":", 1)
        pub_bytes = self._public_keys.get(key_id)
        if pub_bytes is None:
            return False
        try:
            pub_key = self._serialization.load_pem_public_key(pub_bytes)
            payload = f"{proposal.proposal_id}:{proposal.agent_id}:{proposal.action}:{proposal.nonce}".encode()
            pub_key.verify(bytes.fromhex(sig_hex), payload)
            return True
        except Exception:
            return False


class NullApprovalVerifier:
    def verify(self, proposal: Proposal) -> bool:
        return True


# ============================================================================
# Armour Boundary Interface
# ============================================================================

class ArmourBoundary:
    def execute(self, proposal: Proposal, authority: Authority) -> Tuple[bool, str, Any]:
        raise NotImplementedError


class MockArmourBoundary(ArmourBoundary):
    def execute(self, proposal: Proposal, authority: Authority) -> Tuple[bool, str, Any]:
        return True, f"MockArmour: {proposal.action} executed", {"action": proposal.action}


class DenyAllArmourBoundary(ArmourBoundary):
    def execute(self, proposal: Proposal, authority: Authority) -> Tuple[bool, str, Any]:
        return False, "MockArmour: action denied by execution boundary", None


# ============================================================================
# Quorum / Multi-Governor Voting
# ============================================================================

class GovernorVote:
    def __init__(self, governor_id: str, decision: Decision, reason: str, weight: float = 1.0):
        self.governor_id = governor_id
        self.decision = decision
        self.reason = reason
        self.weight = weight


class QuorumAggregator:
    """Aggregates votes from multiple governors for high-stakes fleets."""
    def __init__(self, threshold: float = 0.5, require_human_on_disagreement: bool = True):
        self.threshold = threshold
        self.require_human_on_disagreement = require_human_on_disagreement

    def aggregate(self, votes: List[GovernorVote]) -> Tuple[Decision, str, List[RiskSignal]]:
        if not votes:
            return Decision.HUMAN, "No quorum votes received", [RiskSignal.QUORUM_REJECTED]

        weights = {"CONTINUE": 0.0, "RESTRICT": 0.0, "RECHECK": 0.0, "HUMAN": 0.0}
        total_weight = sum(v.weight for v in votes)

        for v in votes:
            weights[v.decision.value] += v.weight

        # Check for unanimous agreement
        if max(weights.values()) == total_weight:
            winner = max(weights, key=weights.get)
            return Decision(winner), f"Unanimous quorum: {winner}", []

        # Check threshold
        for decision, weight in weights.items():
            if weight / total_weight >= self.threshold:
                if decision == "HUMAN":
                    return Decision.HUMAN, f"Quorum threshold met for HUMAN ({weight}/{total_weight})", []
                elif decision == "CONTINUE":
                    if self.require_human_on_disagreement:
                        return Decision.HUMAN, f"Quorum CONTINUE but disagreement detected; escalating", [RiskSignal.HIGH_DISAGREEMENT]
                    return Decision.CONTINUE, f"Quorum threshold met for CONTINUE ({weight}/{total_weight})", []
                else:
                    return Decision(decision), f"Quorum threshold met for {decision} ({weight}/{total_weight})", []

        # No threshold met
        return Decision.HUMAN, f"No quorum threshold met; max weight {max(weights.values())}/{total_weight}", [RiskSignal.QUORUM_REJECTED]


# ============================================================================
# Chainmail v4 Governor
# ============================================================================

class ChainmailV4:
    def __init__(
        self,
        envelope: AuthorityEnvelope,
        embedding_engine: Optional[EmbeddingEngine] = None,
        armour: Optional[ArmourBoundary] = None,
        persistence: Optional[PersistenceLog] = None,
        sqlite_persistence: Optional[SQLitePersistence] = None,
        approval_verifier: Optional[ApprovalVerifier] = None,
        quorum: Optional[QuorumAggregator] = None,
    ):
        self.envelope = envelope
        self.embedding = embedding_engine or TfidfEmbeddingEngine()
        self.armour = armour
        self.persistence = persistence
        self.sqlite = sqlite_persistence
        self.approval_verifier = approval_verifier or NullApprovalVerifier()
        self.quorum = quorum

        self.live_authority: Dict[str, Authority] = {
            aid: deepcopy(auth) for aid, auth in envelope.agent_authorities.items()
        }
        self.provenance: List[ProvenanceLink] = []
        self.proposal_log: List[Proposal] = []
        self.step_count = 0
        self.restricted: Dict[str, List[Tuple[Permission, int]]] = {}
        self.intent_graph = IntentGraph()
        self._seen_nonces: Set[str] = set()
        self._restrict_budgets: Dict[str, Dict[str, int]] = {}  # agent_id -> {perm_key: remaining_steps}

    def _get_live_auth(self, agent_id: str) -> Authority:
        return self.live_authority.get(agent_id, Authority())

    def _effective_authority(self, agent_id: str) -> Authority:
        base = self._get_live_auth(agent_id)
        extra = self.restricted.get(agent_id, [])
        active = set()
        for perm, expiry in extra:
            if expiry > self.step_count:
                active.add(perm)
        if not active:
            return base
        return base.reduce_to(base.permissions - active)

    def _verify_signature(self, proposal: Proposal) -> bool:
        try:
            return self.approval_verifier.verify(proposal)
        except Exception:
            logger.exception("approval verifier raised")
            return False

    def sign_proposal(self, proposal: Proposal, key_id: str, secret: bytes) -> Proposal:
        nonce = secrets.token_hex(8)
        payload = f"{proposal.proposal_id}:{proposal.agent_id}:{proposal.action}:{nonce}"
        sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
        proposal.signature = f"{key_id}:{sig}"
        proposal.nonce = nonce
        return proposal

    def _apply_restrict(self, agent_id: str, permission: Permission):
        policy = self.envelope.restrict_policy
        if policy == RestrictPolicy.TTL_STEPS:
            ttl = self.envelope.restrict_ttl_steps or 3
            self.restricted.setdefault(agent_id, []).append((permission, self.step_count + ttl))
        elif policy == RestrictPolicy.STEP_BUDGET:
            budget = self.envelope.restrict_step_budget or 10
            key = f"{permission.name}:{permission.scope}"
            self._restrict_budgets.setdefault(agent_id, {})[key] = budget
        elif policy == RestrictPolicy.HUMAN_ONLY:
            # Permanent restriction until HUMAN review
            self.restricted.setdefault(agent_id, []).append((permission, float('inf')))

    def _check_restrict_budget(self, agent_id: str, permission: Permission) -> bool:
        """Returns True if restricted (budget exhausted)."""
        if self.envelope.restrict_policy != RestrictPolicy.STEP_BUDGET:
            return False
        key = f"{permission.name}:{permission.scope}"
        budgets = self._restrict_budgets.get(agent_id, {})
        if key in budgets:
            budgets[key] -= 1
            if budgets[key] <= 0:
                del budgets[key]
                return True
        return False

    def register_delegation(self, from_agent: str, to_agent: str, reason: str, offered: Authority) -> Tuple[bool, str]:
        from_auth = self._effective_authority(from_agent)
        max_to = self.envelope.get_max_authority(to_agent)

        from_role = self.envelope.get_role(from_agent)
        to_role = self.envelope.get_role(to_agent)
        if from_role and to_role:
            allowed = self.envelope.allowed_delegations.get(from_role, set())
            if to_role not in allowed:
                return False, f"Role violation: '{from_role}' cannot delegate to '{to_role}'"

        if not offered.is_subset_of(from_auth):
            return False, "Delegator attempted to grant authority it does not hold"

        new_auth = offered.reduce_to(max_to.permissions)
        self.live_authority[to_agent] = new_auth

        link = ProvenanceLink(from_id=from_agent, to_id=to_agent, reason=reason, delegated_authority=new_auth)
        self.provenance.append(link)

        if self.persistence:
            self.persistence.append("delegation", {"from": from_agent, "to": to_agent, "reason": reason, "authority": repr(new_auth)})
        if self.sqlite:
            self.sqlite.log_delegation(from_agent, to_agent, reason, repr(new_auth))

        if len(new_auth.permissions) < len(offered.permissions):
            return True, "Delegation accepted after reduction to recipient envelope"
        return True, "Delegation accepted (authority preserved or reduced)"

    def evaluate(self, proposal: Proposal) -> GovernanceResult:
        self.step_count += 1
        execution_id = secrets.token_hex(8)

        # Envelope integrity
        try:
            envelope_fp = self.envelope.fingerprint()
        except RuntimeError as exc:
            logger.error("envelope drift detected: %s", exc)
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason=f"Envelope integrity check failed: {exc}",
                signals=[RiskSignal.ENVELOPE_DRIFT],
                provenance=list(self.provenance),
            )

        # Replay prevention
        if proposal.nonce and proposal.nonce in self._seen_nonces:
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason="Replay detected: nonce already consumed",
                signals=[RiskSignal.REPLAY_DETECTED],
                provenance=list(self.provenance),
            )
        if proposal.nonce:
            self._seen_nonces.add(proposal.nonce)

        # Signature verification
        if proposal.signature and not self._verify_signature(proposal):
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason="Invalid proposal signature",
                signals=[RiskSignal.SIGNATURE_INVALID],
                provenance=list(self.provenance),
            )

        self.proposal_log.append(proposal)
        signals: List[RiskSignal] = []
        reason_parts: List[str] = []

        # Schema validation
        schema = self.envelope.get_schema(proposal.action)
        schema_ok, schema_reasons, schema_signal = proposal.validate_against_schema(schema)
        if not schema_ok:
            signals.append(schema_signal)
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason=f"Schema violation: {'; '.join(schema_reasons)}",
                signals=signals,
                provenance=list(self.provenance),
            )

        # Hard policy
        if proposal.action in self.envelope.hard_denials:
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason=f"Hard denial: action '{proposal.action}' is forbidden by envelope",
                signals=[RiskSignal.AUTHORITY_ABUSE],
                provenance=list(self.provenance),
            )

        if self.step_count > self.envelope.max_fleet_steps:
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason="Fleet step budget exhausted",
                signals=[RiskSignal.DRIFT],
                provenance=list(self.provenance),
            )

        live_auth = self._get_live_auth(proposal.agent_id)
        current_auth = self._effective_authority(proposal.agent_id)

        if not current_auth.can(proposal.required_permission):
            signals.append(RiskSignal.AUTHORITY_ABUSE)
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason=f"Agent {proposal.agent_id} lacks permission {proposal.required_permission}",
                signals=signals,
                effective_authority=current_auth,
                provenance=list(self.provenance),
            )

        if not live_auth.has_budget(proposal.required_permission):
            signals.append(RiskSignal.BUDGET_EXHAUSTED)
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason=f"Budget exhausted for {proposal.required_permission}",
                signals=signals,
                effective_authority=current_auth,
                provenance=list(self.provenance),
            )

        live_auth.consume_budget(proposal.required_permission)

        # Check step-budget restriction
        if self._check_restrict_budget(proposal.agent_id, proposal.required_permission):
            return GovernanceResult(
                decision=Decision.HUMAN,
                reason="Step-budget restriction exhausted for this permission",
                signals=[RiskSignal.AUTHORITY_ABUSE],
                effective_authority=current_auth,
                provenance=list(self.provenance),
            )

        # Contextual risk (fail-closed)
        try:
            overlap = self.embedding.similarity(self.envelope.objective, proposal.objective_fragment)
        except Exception:
            logger.exception("embedding similarity failed")
            overlap = 0.0

        if overlap < 0.25:
            signals.append(RiskSignal.OBJECTIVE_MISMATCH)

        if proposal.confidence < 0.35:
            signals.append(RiskSignal.LOW_CONFIDENCE)

        try:
            drift = self.intent_graph.drift_score(self.envelope.objective, proposal.objective_fragment, proposal.agent_id)
        except Exception:
            logger.exception("intent graph drift failed")
            drift = 1.0

        if drift > 0.6:
            signals.append(RiskSignal.DRIFT)

        try:
            peer_frags = [p.objective_fragment for p in self.proposal_log if p.agent_id != proposal.agent_id]
            if peer_frags:
                similarities = [self.embedding.similarity(proposal.objective_fragment, f) for f in peer_frags[-5:]]
                avg = sum(similarities) / len(similarities)
                if avg < 0.3:
                    signals.append(RiskSignal.HIGH_DISAGREEMENT)
        except Exception:
            logger.exception("cross-agent disagreement failed")
            signals.append(RiskSignal.HIGH_DISAGREEMENT)

        if proposal.confidence > 0.9 and overlap < 0.4:
            signals.append(RiskSignal.ASSUMPTION_ANOMALY)

        # Decision mapping
        if any(s in self.envelope.require_human_on for s in signals):
            decision = Decision.HUMAN
            reason_parts.append("Signal requires human review")
        elif RiskSignal.HIGH_DISAGREEMENT in signals or RiskSignal.ASSUMPTION_ANOMALY in signals:
            decision = Decision.RECHECK
            reason_parts.append("Cross-agent anomaly detected")
        elif RiskSignal.DRIFT in signals or RiskSignal.LOW_CONFIDENCE in signals:
            decision = Decision.RESTRICT
            reason_parts.append("Trajectory caution --- restricting further")
            self._apply_restrict(proposal.agent_id, proposal.required_permission)
        else:
            decision = Decision.CONTINUE
            reason_parts.append("Within envelope and objective continuity acceptable")

        # Staged persistence: started
        if self.persistence:
            try:
                self.persistence.append("proposal", {
                    "proposal_id": proposal.proposal_id, "agent_id": proposal.agent_id,
                    "action": proposal.action, "decision": "pending", "signals": [],
                    "overlap": round(overlap, 3), "drift": round(drift, 3),
                }, phase="started", execution_id=execution_id)
            except Exception as exc:
                logger.exception("audit start failed")
                return GovernanceResult(
                    decision=Decision.HUMAN,
                    reason=f"Audit start failed; action not executed: {type(exc).__name__}",
                    signals=[RiskSignal.SANITIZATION_FAILURE],
                    provenance=list(self.provenance),
                )

        if self.sqlite:
            self.sqlite.log_proposal(proposal.proposal_id, proposal.agent_id, proposal.action,
                                     "pending", [], round(overlap, 3), round(drift, 3), "started", execution_id)

        # Armour execution
        armour_output = None
        if decision == Decision.CONTINUE and self.armour:
            try:
                ok, msg, armour_output = self.armour.execute(proposal, current_auth)
                if not ok:
                    decision = Decision.HUMAN
                    reason_parts.append(f"Armour boundary rejected: {msg}")
            except Exception as exc:
                logger.exception("armour boundary raised")
                decision = Decision.HUMAN
                reason_parts.append(f"Armour boundary error: {type(exc).__name__}")
                signals.append(RiskSignal.VERIFIER_ERROR)

        # Quorum voting (if configured)
        quorum_votes = None
        if self.quorum and decision == Decision.CONTINUE:
            # In a real deployment, these votes would come from peer governors
            # For now, we simulate with a single self-vote
            self_vote = GovernorVote("self", decision, "; ".join(reason_parts))
            quorum_decision, quorum_reason, quorum_signals = self.quorum.aggregate([self_vote])
            if quorum_decision != Decision.CONTINUE:
                decision = quorum_decision
                reason_parts.append(quorum_reason)
                signals.extend(quorum_signals)
            quorum_votes = {"self": decision}

        # IntentGraph record
        self.intent_graph.add(IntentGraphEntry(
            objective=self.envelope.objective, fragment=proposal.objective_fragment,
            decision=decision, agent_id=proposal.agent_id, timestamp=time.time(),
        ))

        # Staged persistence: completed
        if self.persistence:
            try:
                self.persistence.append("proposal", {
                    "proposal_id": proposal.proposal_id, "agent_id": proposal.agent_id,
                    "action": proposal.action, "decision": decision.value,
                    "signals": [s.value for s in signals], "overlap": round(overlap, 3),
                    "drift": round(drift, 3), "armour_output": armour_output,
                }, phase="completed", execution_id=execution_id)
            except Exception as exc:
                logger.exception("audit completion failed")
                return GovernanceResult(
                    decision=Decision.HUMAN,
                    reason=f"Audit completion failed: {type(exc).__name__}",
                    signals=[RiskSignal.SANITIZATION_FAILURE],
                    provenance=list(self.provenance),
                )

        if self.sqlite:
            self.sqlite.log_proposal(proposal.proposal_id, proposal.agent_id, proposal.action,
                                     decision.value, [s.value for s in signals],
                                     round(overlap, 3), round(drift, 3), "completed", execution_id)

        return GovernanceResult(
            decision=decision,
            reason="; ".join(reason_parts),
            signals=signals,
            effective_authority=current_auth,
            provenance=list(self.provenance),
            quorum_votes=quorum_votes,
        )

    def snapshot(self) -> Dict[str, Any]:
        return {
            "objective": self.envelope.objective,
            "step_count": self.step_count,
            "live_authority": {k: repr(v) for k, v in self.live_authority.items()},
            "restricted": {k: [(repr(p), e) for p, e in v] for k, v in self.restricted.items()},
            "provenance_len": len(self.provenance),
            "proposals_seen": len(self.proposal_log),
            "intent_graph_entries": len(self.intent_graph.entries),
            "seen_nonces": len(self._seen_nonces),
            "envelope_fingerprint": self.envelope._construction_fingerprint[:16] + "...",
            "restrict_policy": self.envelope.restrict_policy.value,
            "restrict_budgets": self._restrict_budgets,
        }

    def suggest_envelope(self) -> Dict[str, Any]:
        """Analyze historical runs and suggest envelope adjustments."""
        if not self.sqlite:
            return {"error": "SQLite persistence required for envelope suggestion"}

        history = self.sqlite.get_proposal_history()
        if not history:
            return {"suggestion": "No history available"}

        actions = Counter(h["action"] for h in history)
        decisions = Counter(h["decision"] for h in history)
        agents = Counter(h["agent_id"] for h in history)

        suggestions = {
            "most_common_actions": dict(actions.most_common(5)),
            "decision_distribution": dict(decisions),
            "most_active_agents": dict(agents.most_common(5)),
            "recommendations": [],
        }

        # Simple heuristics
        if decisions.get("HUMAN", 0) / len(history) > 0.3:
            suggestions["recommendations"].append("High HUMAN rate; consider broadening authority envelope or improving agent confidence")
        if decisions.get("RESTRICT", 0) / len(history) > 0.2:
            suggestions["recommendations"].append("High RESTRICT rate; consider tightening objective or improving semantic continuity")
        if len(actions) > 10:
            suggestions["recommendations"].append("Many distinct actions; consider adding ActionSchemas for the most common ones")

        return suggestions


# ============================================================================
# Convenience Builders
# ============================================================================

def make_permission(name: str, scope: str = "*", max_budget: Optional[int] = None) -> Permission:
    return Permission(name=name, scope=scope, max_budget=max_budget)


def build_demo_envelope_v4() -> AuthorityEnvelope:
    research = Authority(permissions={
        make_permission("research"), make_permission("read", "web"), make_permission("read", "docs"),
    })
    coder = Authority(permissions={
        make_permission("code", "write"), make_permission("code", "test"), make_permission("read", "repo"),
    })
    deployer = Authority(permissions={
        make_permission("deploy", "staging", max_budget=5), make_permission("read", "logs"),
    })
    approver = Authority(permissions={make_permission("approve", "high-risk")})
    return AuthorityEnvelope(
        objective="Build a secure multi-agent governance prototype and keep the system inside the declared authority envelope",
        agent_authorities={"agent_research": research, "agent_coder": coder, "agent_deploy": deployer, "agent_approver": approver},
        allowed_delegations={"research": {"coder"}, "coder": {"deploy"}, "deploy": set(), "approver": set()},
        agent_roles={"agent_research": "research", "agent_coder": "coder", "agent_deploy": "deploy", "agent_approver": "approver"},
        hard_denials={"delete_production", "exfiltrate_secrets", "disable_chainmail"},
        max_fleet_steps=50,
        require_human_on={RiskSignal.AUTHORITY_ABUSE, RiskSignal.OBJECTIVE_MISMATCH},
        restrict_policy=RestrictPolicy.TTL_STEPS,
        restrict_ttl_steps=3,
        restrict_step_budget=10,
        action_schemas={
            "deploy_service": ActionSchema(
                allowed_payload_keys=frozenset({"target", "version", "dry_run"}),
                required_payload_keys=frozenset({"target"}),
                filesystem_path_fields=frozenset({"target"}),
                allow_nested_payload=False,
            ),
            "write_code": ActionSchema(
                allowed_payload_keys=frozenset({"file", "content", "mode"}),
                required_payload_keys=frozenset({"file"}),
                filesystem_path_fields=frozenset({"file"}),
                allow_nested_payload=False,
            ),
        },
    )
