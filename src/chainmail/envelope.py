"""
Chainmail v5 --- the authority envelope.

The envelope is the human-declared, pre-run contract: the objective, each
agent's ceiling authority, the delegation role-map, hard denials, and the
restriction policy. Once constructed it is tamper-evident: any post-construction
mutation of a governance-relevant field is detected via a SHA-256 fingerprint
and forces every subsequent evaluation to HUMAN.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Set

from .core import ActionSchema, Authority, RestrictPolicy, RiskSignal


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
    restrict_ttl_seconds: Optional[float] = 60.0
    restrict_step_budget: Optional[int] = 10
    action_schemas: Dict[str, ActionSchema] = field(default_factory=dict)
    allowed_actions: Optional[Set[str]] = None
    """When set, any proposal whose ``action`` is not in this set fails closed
    (HUMAN / UNKNOWN_ACTION). ``None`` (default) keeps the permission-centric
    model: the action string is a label and only ``required_permission`` gates."""
    _construction_fingerprint: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.objective, str) or not self.objective.strip():
            raise ValueError("envelope objective must be a non-empty string")
        if not self.agent_authorities:
            raise ValueError("envelope must declare at least one agent authority")

        # Freeze mutable collections so a caller cannot mutate them after the
        # fingerprint is taken.
        if isinstance(self.allowed_delegations, dict):
            object.__setattr__(
                self, "allowed_delegations",
                {k: frozenset(v) for k, v in self.allowed_delegations.items()},
            )
        if isinstance(self.hard_denials, (set, list, tuple)):
            object.__setattr__(self, "hard_denials", frozenset(self.hard_denials))
        if isinstance(self.require_human_on, (set, list, tuple)):
            object.__setattr__(self, "require_human_on", frozenset(self.require_human_on))
        if self.allowed_actions is not None:
            object.__setattr__(self, "allowed_actions", frozenset(self.allowed_actions))

        # Referential integrity: roles must name real agents, delegation keys and
        # values must be roles that some agent actually holds.
        known_roles = set(self.agent_roles.values())
        for agent_id in self.agent_roles:
            if agent_id not in self.agent_authorities:
                raise ValueError(f"agent_roles references unknown agent '{agent_id}'")
        for from_role, to_roles in self.allowed_delegations.items():
            if from_role not in known_roles:
                raise ValueError(f"allowed_delegations key '{from_role}' is not a known role")
            for to_role in to_roles:
                if to_role not in known_roles:
                    raise ValueError(
                        f"allowed_delegations['{from_role}'] references unknown role '{to_role}'"
                    )

        if self.restrict_policy == RestrictPolicy.TTL_WALLCLOCK and not self.restrict_ttl_seconds:
            raise ValueError("restrict_ttl_seconds is required for TTL_WALLCLOCK policy")

        object.__setattr__(self, "_construction_fingerprint", self._compute_fingerprint())

    # -- integrity -----------------------------------------------------
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
            "restrict_ttl_seconds": self.restrict_ttl_seconds,
            "restrict_step_budget": self.restrict_step_budget,
            "action_schemas": {k: v.to_dict() for k, v in sorted(self.action_schemas.items())},
            "allowed_actions": (sorted(self.allowed_actions)
                                if self.allowed_actions is not None else None),
        }, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def fingerprint(self) -> str:
        current = self._compute_fingerprint()
        if current != self._construction_fingerprint:
            raise RuntimeError("envelope integrity check failed: state drifted after construction")
        return current

    # -- lookups -----------------------------------------------------
    def get_max_authority(self, agent_id: str) -> Authority:
        return self.agent_authorities.get(agent_id, Authority())

    def knows_agent(self, agent_id: str) -> bool:
        return agent_id in self.agent_authorities

    def get_role(self, agent_id: str) -> Optional[str]:
        return self.agent_roles.get(agent_id)

    def get_schema(self, action: str) -> Optional[ActionSchema]:
        return self.action_schemas.get(action)
