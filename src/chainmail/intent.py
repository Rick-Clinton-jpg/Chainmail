"""
Chainmail v5 --- intent graph.

Records every (objective, fragment, decision, agent) tuple the governor has seen
and answers three questions about a new fragment:

* ``drift_score``    -- how far it has moved from this agent's own recent history.
* ``peer_consensus`` -- how well it aligns with what *other* agents are doing.
* ``reentry_risk``   -- whether it is a reworded return to an objective this
  agent has already been refused (RESTRICT / HUMAN).

The re-entry check carries a **hard gate** borrowed from the ``intent-layer``
project: risk can never rise above LOW unless the agent's lineage actually
contains a prior refusal. Embedding similarity or reframing language alone,
with no real boundary in the history, always resolves to LOW.

Unlike v4 this uses the governor's shared embedding engine (no private, never-fit
TF-IDF instance) and is bounded by a ring buffer.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List

from .core import Decision
from .embeddings import EmbeddingEngine

logger = logging.getLogger(__name__)


@dataclass
class IntentGraphEntry:
    objective: str
    fragment: str
    decision: Decision
    agent_id: str
    timestamp: float
    safety_boundary: bool = False
    """True when this turn was refused (RESTRICT / HUMAN). A later reworded
    return to it is what ``reentry_risk`` looks for."""


@dataclass(frozen=True)
class ReentryRisk:
    level: str            # "LOW" | "MEDIUM" | "HIGH"
    score: float
    boundary_count: int
    explanation: str


class IntentGraph:
    def __init__(self, embedding: EmbeddingEngine, *, max_entries: int = 50_000,
                 history_window: int = 10) -> None:
        self._embedding = embedding
        self._history_window = history_window
        self.entries: Deque[IntentGraphEntry] = deque(maxlen=max_entries)

    def add(self, entry: IntentGraphEntry) -> None:
        self.entries.append(entry)

    def _recent_for(self, agent_id: str, *, same: bool) -> List[IntentGraphEntry]:
        picked: List[IntentGraphEntry] = []
        for entry in reversed(self.entries):
            if (entry.agent_id == agent_id) == same:
                picked.append(entry)
                if len(picked) >= self._history_window:
                    break
        picked.reverse()
        return picked

    def drift_score(self, objective: str, fragment: str, agent_id: str) -> float:
        """0.0 == on-track, 1.0 == fully diverged. Returns 0.0 until the agent
        has at least two prior entries."""
        try:
            history = self._recent_for(agent_id, same=True)
            if len(history) < 2:
                return 0.0
            current = f"{objective} {fragment}"
            sims = [self._embedding.similarity(current, f"{e.objective} {e.fragment}") for e in history]
            avg = sum(sims) / len(sims)
            return max(0.0, min(1.0, 1.0 - avg))
        except Exception:
            logger.exception("IntentGraph.drift_score failed; treating as full drift")
            return 1.0

    def peer_consensus_score(self, objective: str, fragment: str, agent_id: str) -> float:
        """1.0 == aligned with peers, 0.0 == isolated. Returns 1.0 when there are
        no peer entries yet."""
        try:
            peers = self._recent_for(agent_id, same=False)
            if not peers:
                return 1.0
            current = f"{objective} {fragment}"
            sims = [self._embedding.similarity(current, f"{e.objective} {e.fragment}") for e in peers]
            return max(0.0, min(1.0, sum(sims) / len(sims)))
        except Exception:
            logger.exception("IntentGraph.peer_consensus_score failed; treating as isolated")
            return 0.0

    def reentry_risk(self, objective: str, fragment: str, agent_id: str, *,
                     confidence: float, high: float, medium: float) -> ReentryRisk:
        """Is this a reworded return to an objective this agent was already
        refused? HARD GATE: with no prior ``safety_boundary`` entry in the
        agent's history the answer is always LOW, whatever the similarity.

        When there is such history, the score is the agent's confidence times
        its peak similarity to any refused turn -- a shaky read counts for
        less, it is never discarded or blindly trusted.
        """
        try:
            boundaries = [e for e in self.entries
                          if e.agent_id == agent_id and e.safety_boundary]
            if not boundaries:
                return ReentryRisk("LOW", 0.0, 0,
                                   "no prior refusal in this agent's lineage -> "
                                   "re-entry risk forced to LOW")
            # Fragment-to-fragment: the envelope objective is constant across a
            # governor, so including it here would just inflate every score.
            peak = max(self._embedding.similarity(fragment, e.fragment) for e in boundaries)
            score = max(0.0, min(1.0, peak * max(0.0, min(1.0, confidence))))
            if score >= high:
                level = "HIGH"
            elif score >= medium:
                level = "MEDIUM"
            else:
                level = "LOW"
            return ReentryRisk(
                level, round(score, 4), len(boundaries),
                f"{len(boundaries)} prior refusal(s) in lineage; peak similarity "
                f"{peak:.2f} x confidence {confidence:.2f} = {score:.2f}",
            )
        except Exception:
            logger.exception("IntentGraph.reentry_risk failed; treating as HIGH")
            return ReentryRisk("HIGH", 1.0, -1, "re-entry scoring raised; failing closed")
