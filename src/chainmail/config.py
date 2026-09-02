"""
Chainmail v5 --- governor configuration.

Every risk threshold, window size, and bound that used to be a magic number in
``evaluate()`` lives here. Construct a ``GovernorConfig`` once, hand it to the
governor, and it is frozen for the life of that governor instance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class GovernorConfig:
    # -- contextual risk thresholds --------------------------------------
    objective_overlap_min: float = 0.25
    """Below this objective/fragment similarity -> OBJECTIVE_MISMATCH."""

    low_confidence_max: float = 0.35
    """At or below this proposal confidence -> LOW_CONFIDENCE."""

    drift_max: float = 0.6
    """Above this intent-graph drift score -> DRIFT."""

    peer_disagreement_max: float = 0.3
    """Below this mean similarity to recent peer fragments -> HIGH_DISAGREEMENT."""

    anomaly_confidence_min: float = 0.9
    """Confidence at/above this combined with low overlap -> ASSUMPTION_ANOMALY."""

    anomaly_overlap_max: float = 0.4
    """Overlap below this combined with high confidence -> ASSUMPTION_ANOMALY."""

    reentry_high: float = 0.7
    """Confidence-weighted similarity to a prior *refused* objective at/above
    this -> HIGH re-entry risk -> HUMAN. Only ever evaluated when the agent's
    lineage actually contains a prior RESTRICT/HUMAN boundary (hard gate:
    similarity alone, with no real refusal history, never raises risk)."""

    reentry_medium: float = 0.45
    """Same, for MEDIUM re-entry risk -> RESTRICT."""

    # -- history windows ----------------------------------------------------
    peer_window: int = 5
    """How many recent peer fragments feed the disagreement check."""

    drift_history_window: int = 10
    """How many of an agent's own recent fragments feed the drift check."""

    # -- long-running bounds ----------------------------------------------
    max_seen_nonces: int = 200_000
    """LRU cap on the in-memory replay-protection set."""

    proposal_log_max: int = 20_000
    """Ring-buffer cap on retained proposals (peer checks only need the tail)."""

    intent_graph_max: int = 50_000
    """Ring-buffer cap on intent-graph entries."""

    # -- policy knobs ----------------------------------------------------
    require_signature: bool = False
    """When True, an unsigned proposal escalates to HUMAN (SIGNATURE_MISSING)."""

    dedupe_proposal_ids: bool = True
    """When True, a repeated proposal_id escalates to HUMAN (PROPOSAL_DUPLICATE)."""

    per_agent_step_budget: int = 0
    """Per-agent evaluation cap. 0 disables (fleet budget still applies)."""

    embedding_refit_interval: int = 256
    """Refit the TF-IDF fallback engine every N proposals. Ignored by model engines."""

    @classmethod
    def production(cls, **overrides: Any) -> "GovernorConfig":
        """A secure-by-default config for real deployments.

        Differs from ``GovernorConfig()`` only in ``require_signature``, which
        this sets to ``True``. Everything else keeps the same defaults, which
        the caller may still override. Pairing this with a
        :class:`~chainmail.crypto.NullApprovalVerifier` (or no verifier at
        all) is rejected at governor construction time -- see
        ``ChainmailGovernor.__init__`` -- so a real
        :class:`~chainmail.crypto.CompositeVerifier` must be supplied.
        """
        defaults: Dict[str, Any] = {"require_signature": True}
        defaults.update(overrides)
        return cls(**defaults)

    def __post_init__(self) -> None:
        fractions = {
            "objective_overlap_min": self.objective_overlap_min,
            "low_confidence_max": self.low_confidence_max,
            "drift_max": self.drift_max,
            "peer_disagreement_max": self.peer_disagreement_max,
            "anomaly_confidence_min": self.anomaly_confidence_min,
            "anomaly_overlap_max": self.anomaly_overlap_max,
        }
        fractions["reentry_high"] = self.reentry_high
        fractions["reentry_medium"] = self.reentry_medium
        for name, value in fractions.items():
            if not isinstance(value, (int, float)) or not (0.0 <= float(value) <= 1.0):
                raise ValueError(f"{name} must be in [0.0, 1.0]")
        if self.reentry_medium > self.reentry_high:
            raise ValueError("reentry_medium must not exceed reentry_high")
        ints = {
            "peer_window": self.peer_window,
            "drift_history_window": self.drift_history_window,
            "max_seen_nonces": self.max_seen_nonces,
            "proposal_log_max": self.proposal_log_max,
            "intent_graph_max": self.intent_graph_max,
            "per_agent_step_budget": self.per_agent_step_budget,
            "embedding_refit_interval": self.embedding_refit_interval,
        }
        for name, value in ints.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative int")
        if self.peer_window == 0 or self.drift_history_window == 0:
            raise ValueError("peer_window and drift_history_window must be positive")
