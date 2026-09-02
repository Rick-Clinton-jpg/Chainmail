"""
Chainmail v5 --- core types.

Value objects shared across the governance layer: decisions, risk signals,
permissions, authority sets, proposals, and the structured result of an
evaluation. Nothing here reaches for I/O, crypto, or embeddings; those live in
sibling modules.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# ============================================================================
# Enumerations
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
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    ROLE_VIOLATION = "ROLE_VIOLATION"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    ENVELOPE_DRIFT = "ENVELOPE_DRIFT"
    OBJECTIVE_REENTRY = "OBJECTIVE_REENTRY"
    VERIFIER_ERROR = "VERIFIER_ERROR"
    SANITIZATION_FAILURE = "SANITIZATION_FAILURE"
    QUORUM_REJECTED = "QUORUM_REJECTED"
    FLEET_BUDGET_EXHAUSTED = "FLEET_BUDGET_EXHAUSTED"
    AGENT_BUDGET_EXHAUSTED = "AGENT_BUDGET_EXHAUSTED"
    PROPOSAL_DUPLICATE = "PROPOSAL_DUPLICATE"
    INVALID_PROPOSAL = "INVALID_PROPOSAL"
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    REPLAY_STORE_UNAVAILABLE = "REPLAY_STORE_UNAVAILABLE"
    RESTRICTION_STORE_UNAVAILABLE = "RESTRICTION_STORE_UNAVAILABLE"


class RestrictPolicy(str, Enum):
    TTL_STEPS = "TTL_STEPS"
    TTL_WALLCLOCK = "TTL_WALLCLOCK"
    STEP_BUDGET = "STEP_BUDGET"
    HUMAN_ONLY = "HUMAN_ONLY"


# ============================================================================
# Permission / Authority
# ============================================================================

@dataclass(frozen=True)
class Permission:
    name: str
    scope: str = "*"
    max_budget: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("permission name must be a non-empty string")
        if not isinstance(self.scope, str) or not self.scope:
            raise ValueError("permission scope must be a non-empty string")
        if self.max_budget is not None:
            if not isinstance(self.max_budget, int) or isinstance(self.max_budget, bool):
                raise TypeError("permission max_budget must be an int or None")
            if self.max_budget < 0:
                raise ValueError("permission max_budget must be non-negative")

    def covers(self, required: "Permission") -> bool:
        """True if this permission authorises ``required`` (name match, scope
        wildcard or exact)."""
        return self.name == required.name and (self.scope == "*" or self.scope == required.scope)

    def key(self) -> str:
        return f"{self.name}:{self.scope}"


@dataclass
class Authority:
    permissions: Set[Permission] = field(default_factory=set)
    budget_remaining: Dict[str, int] = field(default_factory=dict)

    # -- queries -----------------------------------------------------------
    def can(self, required: Permission) -> bool:
        return any(p.covers(required) for p in self.permissions)

    def _match(self, required: Permission) -> Optional[Permission]:
        for p in self.permissions:
            if p.covers(required):
                return p
        return None

    def has_budget(self, required: Permission) -> bool:
        p = self._match(required)
        if p is None:
            return False
        if p.max_budget is None:
            return True
        remaining = self.budget_remaining.get(p.key(), p.max_budget)
        return remaining > 0

    def is_subset_of(self, other: "Authority") -> bool:
        return all(any(op.covers(p) for op in other.permissions) for p in self.permissions)

    # -- mutations -------------------------------------------------------
    def consume_budget(self, required: Permission, amount: int = 1) -> bool:
        """Decrement the budget for the permission that authorises ``required``.

        Returns True when the permission exists and (if metered) had enough
        budget; False otherwise. A non-metered permission always returns True
        without recording anything.
        """
        p = self._match(required)
        if p is None:
            return False
        if p.max_budget is None:
            return True
        key = p.key()
        current = self.budget_remaining.get(key, p.max_budget)
        if current < amount:
            return False
        self.budget_remaining[key] = current - amount
        return True

    def reduce_to(self, allowed: Set[Permission]) -> "Authority":
        """Return a new Authority keeping only permissions also authorised by
        ``allowed``. Budget counters are carried across for kept permissions."""
        kept: Set[Permission] = set()
        for p in self.permissions:
            if any(a.covers(p) for a in allowed):
                kept.add(p)
        new_budgets: Dict[str, int] = {}
        for p in kept:
            key = p.key()
            if key in self.budget_remaining:
                new_budgets[key] = self.budget_remaining[key]
            elif p.max_budget is not None:
                new_budgets[key] = p.max_budget
        return Authority(permissions=set(kept), budget_remaining=new_budgets)

    def copy(self) -> "Authority":
        return Authority(permissions=set(self.permissions), budget_remaining=dict(self.budget_remaining))

    def __repr__(self) -> str:
        parts = []
        for p in sorted(self.permissions, key=lambda x: (x.name, x.scope)):
            if p.max_budget is not None:
                rem = self.budget_remaining.get(p.key(), p.max_budget)
                parts.append(f"{p.name}:{p.scope}({rem}/{p.max_budget})")
            else:
                parts.append(f"{p.name}:{p.scope}")
        return f"Authority({', '.join(parts)})"


# ============================================================================
# Assumptions / provenance
# ============================================================================

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
# Action schema (payload shape + filesystem-path safety)
# ============================================================================

_CONTROL_CHARS = frozenset(chr(c) for c in range(0x20)) | {chr(0x7F)}


def _contains_nested(value: Any) -> bool:
    if isinstance(value, dict):
        return True
    if isinstance(value, (list, tuple)):
        return any(isinstance(item, (dict, list, tuple)) for item in value)
    return False


@dataclass(frozen=True)
class ActionSchema:
    """Declares the payload contract for one action name.

    ``filesystem_path_fields`` are validated for traversal safety: no NUL or
    control bytes, no ``..`` segments, and -- when ``allowed_path_roots`` is set
    -- the resolved path must sit inside one of the declared roots.
    """
    allowed_payload_keys: FrozenSet[str]
    required_payload_keys: FrozenSet[str] = frozenset()
    filesystem_path_fields: FrozenSet[str] = frozenset()
    allow_nested_payload: bool = False
    allowed_path_roots: Tuple[str, ...] = ()

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
        roots = tuple(self.allowed_path_roots or ())
        if any(not isinstance(r, str) or not r for r in roots):
            raise TypeError("allowed_path_roots entries must be non-empty strings")
        object.__setattr__(self, "allowed_payload_keys", allowed)
        object.__setattr__(self, "required_payload_keys", required)
        object.__setattr__(self, "filesystem_path_fields", paths)
        object.__setattr__(self, "allowed_path_roots", roots)

    # -- validation -----------------------------------------------------
    def validate(self, payload: Dict[str, Any]) -> Tuple[bool, List[str], RiskSignal]:
        supplied = frozenset(payload)
        unknown = supplied - self.allowed_payload_keys
        if unknown:
            return False, [f"unknown payload keys: {', '.join(sorted(unknown))}"], RiskSignal.SCHEMA_VIOLATION
        missing = self.required_payload_keys - supplied
        if missing:
            return False, [f"missing required payload keys: {', '.join(sorted(missing))}"], RiskSignal.SCHEMA_VIOLATION
        if not self.allow_nested_payload:
            for value in payload.values():
                if _contains_nested(value):
                    return False, ["nested payload values are forbidden by the action schema"], RiskSignal.SCHEMA_VIOLATION

        for pfield in self.filesystem_path_fields:
            if pfield not in payload:
                continue
            ok, why = self._validate_path(payload[pfield])
            if not ok:
                return False, [f"path field '{pfield}': {why}"], RiskSignal.PATH_TRAVERSAL
        return True, [], RiskSignal.NONE

    def _validate_path(self, raw: Any) -> Tuple[bool, str]:
        import os
        import posixpath

        if not isinstance(raw, str) or not raw:
            return False, "must be a non-empty string"
        if "\x00" in raw:
            return False, "contains NUL byte"
        if any(ch in _CONTROL_CHARS for ch in raw):
            return False, "contains control characters"
        # Reject Windows-style drive/UNC and backslash separators outright.
        if "\\" in raw or (len(raw) >= 2 and raw[1] == ":"):
            return False, "backslash or drive-letter paths are not allowed"
        segments = raw.split("/")
        if any(seg == ".." for seg in segments):
            return False, "contains a '..' traversal segment"
        normalised = posixpath.normpath(raw)
        if normalised == ".." or normalised.startswith("../"):
            return False, "normalises outside its base"
        if not self.allowed_path_roots:
            return True, ""
        candidate = os.path.realpath(normalised) if posixpath.isabs(normalised) else normalised
        for root in self.allowed_path_roots:
            root_norm = posixpath.normpath(root)
            if candidate == root_norm or candidate.startswith(root_norm.rstrip("/") + "/"):
                return True, ""
        return False, f"resolves outside allowed roots {self.allowed_path_roots}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed_payload_keys": sorted(self.allowed_payload_keys),
            "required_payload_keys": sorted(self.required_payload_keys),
            "filesystem_path_fields": sorted(self.filesystem_path_fields),
            "allow_nested_payload": self.allow_nested_payload,
            "allowed_path_roots": list(self.allowed_path_roots),
        }


# ============================================================================
# Proposal
# ============================================================================

def _finite_unit(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) \
        and not math.isnan(value) and not math.isinf(value) and 0.0 <= value <= 1.0


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

    def __post_init__(self) -> None:
        problems = self.structural_problems()
        if problems:
            raise ValueError(f"invalid proposal: {'; '.join(problems)}")

    def structural_problems(self) -> List[str]:
        """Return a list of structural defects (empty == well-formed).

        Kept as a method so the governor can re-check a proposal that reached it
        over the wire without a constructor call.
        """
        problems: List[str] = []
        if not isinstance(self.proposal_id, str) or not self.proposal_id:
            problems.append("proposal_id must be a non-empty string")
        if not isinstance(self.agent_id, str) or not self.agent_id:
            problems.append("agent_id must be a non-empty string")
        if not isinstance(self.action, str) or not self.action:
            problems.append("action must be a non-empty string")
        if not isinstance(self.required_permission, Permission):
            problems.append("required_permission must be a Permission")
        if not isinstance(self.objective_fragment, str) or not self.objective_fragment:
            problems.append("objective_fragment must be a non-empty string")
        if not _finite_unit(self.confidence):
            problems.append("confidence must be a finite number in [0.0, 1.0]")
        if self.parent_proposal_id is not None and (
            not isinstance(self.parent_proposal_id, str) or not self.parent_proposal_id
        ):
            problems.append("parent_proposal_id must be a non-empty string or None")
        if not isinstance(self.payload, dict):
            problems.append("payload must be a dict")
        elif any(not isinstance(k, str) for k in self.payload):
            problems.append("payload keys must be strings")
        return problems

    def signing_dict(self) -> Dict[str, Any]:
        """The subset of the proposal that a signature must bind. Any field an
        attacker could usefully tamper with is included."""
        return {
            "proposal_id": self.proposal_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "required_permission": {
                "name": self.required_permission.name,
                "scope": self.required_permission.scope,
                "max_budget": self.required_permission.max_budget,
            },
            "objective_fragment": self.objective_fragment,
            "parent_proposal_id": self.parent_proposal_id,
            "payload": self.payload,
            "nonce": self.nonce,
        }


# ============================================================================
# Governance result
# ============================================================================

@dataclass
class GovernanceResult:
    decision: Decision
    reason: str
    signals: List[RiskSignal]
    effective_authority: Optional[Authority] = None
    restricted_permissions: Optional[Set[Permission]] = None
    provenance: List[ProvenanceLink] = field(default_factory=list)
    quorum_votes: Optional[Dict[str, str]] = None
    execution_id: Optional[str] = None
    execution_output: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "signals": [s.value for s in self.signals],
            "effective_authority": repr(self.effective_authority) if self.effective_authority else None,
            "restricted_permissions": (
                sorted(p.key() for p in self.restricted_permissions)
                if self.restricted_permissions else None
            ),
            "provenance": [
                {"from": l.from_id, "to": l.to_id, "reason": l.reason, "timestamp": l.timestamp}
                for l in self.provenance
            ],
            "quorum_votes": self.quorum_votes,
            "execution_id": self.execution_id,
            "execution_output": self.execution_output,
        }
