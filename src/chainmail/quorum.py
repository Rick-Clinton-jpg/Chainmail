"""
Chainmail v5 --- multi-governor quorum.

For high-stakes fleets no single governor should be able to force CONTINUE.
Votes from peer governors are aggregated here. The v5 rule is strictly
fail-closed:

1. No votes                              -> HUMAN (QUORUM_REJECTED)
2. Any HUMAN vote at all                 -> HUMAN     (HUMAN dominates)
3. Unanimous CONTINUE                    -> CONTINUE
4. CONTINUE meets threshold, no HUMAN,
   and disagreement is tolerated         -> CONTINUE
5. A non-CONTINUE non-HUMAN decision
   (RESTRICT / RECHECK) meets threshold  -> that decision
6. Otherwise                             -> HUMAN (QUORUM_REJECTED)

``VoteTransport`` abstracts *where* peer votes come from. The default
``LocalSingleGovernorTransport`` just echoes this governor's own vote, which
under the rule above still requires unanimity-of-one to pass.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional, Protocol, Tuple

from .core import Decision, RiskSignal

logger = logging.getLogger(__name__)


@dataclass
class GovernorVote:
    governor_id: str
    decision: Decision
    reason: str
    weight: float = 1.0

    def __post_init__(self) -> None:
        if self.weight <= 0:
            raise ValueError("vote weight must be positive")


class QuorumAggregator:
    def __init__(self, threshold: float = 0.5, *, require_human_on_disagreement: bool = True) -> None:
        if not (0.0 < threshold <= 1.0):
            raise ValueError("threshold must be in (0.0, 1.0]")
        self.threshold = threshold
        self.require_human_on_disagreement = require_human_on_disagreement

    def aggregate(self, votes: List[GovernorVote]) -> Tuple[Decision, str, List[RiskSignal]]:
        if not votes:
            return Decision.HUMAN, "no quorum votes received", [RiskSignal.QUORUM_REJECTED]

        total = sum(v.weight for v in votes)
        weights = {d: 0.0 for d in Decision}
        for v in votes:
            weights[v.decision] += v.weight

        # (2) HUMAN dominates -- any HUMAN vote escalates, regardless of threshold.
        if weights[Decision.HUMAN] > 0:
            return (Decision.HUMAN,
                    f"HUMAN vote present ({weights[Decision.HUMAN]}/{total})",
                    [])

        # (3) Unanimous.
        for decision, w in weights.items():
            if w == total:
                return decision, f"unanimous quorum: {decision.value}", []

        # There is disagreement (no HUMAN, not unanimous).
        cont_frac = weights[Decision.CONTINUE] / total
        if cont_frac >= self.threshold:
            if self.require_human_on_disagreement:
                return (Decision.HUMAN,
                        f"quorum leaned CONTINUE ({weights[Decision.CONTINUE]}/{total}) "
                        f"but disagreement present; escalating",
                        [RiskSignal.HIGH_DISAGREEMENT])
            return (Decision.CONTINUE,
                    f"quorum threshold met for CONTINUE ({weights[Decision.CONTINUE]}/{total})",
                    [])

        # (5) A cautious decision (RESTRICT/RECHECK) that clears the threshold.
        for decision in (Decision.RESTRICT, Decision.RECHECK):
            if weights[decision] / total >= self.threshold:
                return (decision,
                        f"quorum threshold met for {decision.value} ({weights[decision]}/{total})",
                        [])

        # (6) No decision commands a quorum.
        return (Decision.HUMAN,
                f"no quorum threshold met (max {max(weights.values())}/{total})",
                [RiskSignal.QUORUM_REJECTED])


# ============================================================================
# Vote transport
# ============================================================================

class VoteTransport(Protocol):
    def collect(self, own_vote: GovernorVote) -> List[GovernorVote]: ...


class LocalSingleGovernorTransport:
    """No peers: the only vote is this governor's own."""

    def collect(self, own_vote: GovernorVote) -> List[GovernorVote]:
        return [own_vote]


class StaticPeerTransport:
    """Test / bootstrap transport with a fixed set of peer votes appended to the
    caller's own vote."""

    def __init__(self, peer_votes: Optional[List[GovernorVote]] = None) -> None:
        self._peer_votes = list(peer_votes or [])

    def collect(self, own_vote: GovernorVote) -> List[GovernorVote]:
        return [own_vote, *self._peer_votes]
