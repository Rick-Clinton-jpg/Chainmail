"""
Chainmail v5 --- the governor.

``ChainmailGovernor`` is the policy-hard core. It is safe to share across threads:
``evaluate`` and ``register_delegation`` take a re-entrant lock, and all mutable
state (step counters, replay set, live authority, restrictions, intent graph) is
touched only under that lock.

Evaluation order (every failing gate returns HUMAN):

  1. envelope integrity fingerprint
  2. proposal is structurally well-formed
  3. agent is known to the envelope
  4. proposal_id not already seen (optional)
  5. signature present (optional) and valid -- binds the *whole* proposal
  6. nonce not replayed  (checked only after the signature is trusted)
  7. fleet / per-agent step budget
  8. action schema + filesystem-path safety
  9. hard denial
 10. agent holds the required permission (under active restrictions)
 11. permission budget remains
 12. step-budget restriction not exhausted
 13. contextual risk -> signal set -> decision
 14. audit "started"
 15. Armour boundary (only if CONTINUE)
 16. quorum (only if CONTINUE)
 17. consume permission budget  (only if the final decision is CONTINUE)
 18. apply restriction          (only if the final decision is RESTRICT)
 19. audit "completed"
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from collections import Counter, OrderedDict
from collections import deque
from copy import deepcopy
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from .armour import ArmourBoundary
from .config import GovernorConfig
from .core import (
    Authority, Decision, GovernanceResult, Permission, Proposal, ProvenanceLink,
    RestrictPolicy, RiskSignal,
)
from .crypto import ApprovalVerifier, NullApprovalVerifier
from .embeddings import EmbeddingEngine, TfidfEmbeddingEngine, auto_embedding_engine
from .envelope import AuthorityEnvelope
from .intent import IntentGraph, IntentGraphEntry
from .persistence import AuditSink
from .quorum import GovernorVote, LocalSingleGovernorTransport, QuorumAggregator, VoteTransport
from . import tracing

logger = logging.getLogger(__name__)

_INF = float("inf")


class ChainmailGovernor:
    def __init__(
        self,
        envelope: AuthorityEnvelope,
        *,
        config: Optional[GovernorConfig] = None,
        embedding: Optional[EmbeddingEngine] = None,
        armour: Optional[ArmourBoundary] = None,
        audit: Optional[AuditSink] = None,
        verifier: Optional[ApprovalVerifier] = None,
        quorum: Optional[QuorumAggregator] = None,
        quorum_transport: Optional[VoteTransport] = None,
        governor_id: str = "governor-0",
        auto_embedding: bool = True,
    ) -> None:
        self.envelope = envelope
        self.config = config or GovernorConfig()
        self.governor_id = governor_id
        self.armour = armour
        self.audit = audit or AuditSink()
        self.verifier: ApprovalVerifier = verifier or NullApprovalVerifier()
        self.quorum = quorum
        self.quorum_transport = quorum_transport or LocalSingleGovernorTransport()

        if embedding is not None:
            self.embedding = embedding
        elif auto_embedding:
            self.embedding = auto_embedding_engine()
        else:
            self.embedding = TfidfEmbeddingEngine()

        self._lock = threading.RLock()

        self.live_authority: Dict[str, Authority] = {
            aid: auth.copy() for aid, auth in envelope.agent_authorities.items()
        }
        self.provenance: List[ProvenanceLink] = []
        self.proposal_log: Deque[Proposal] = deque(maxlen=self.config.proposal_log_max)
        self.step_count = 0
        self._agent_steps: Counter = Counter()

        # restrictions: agent -> list of (permission, kind, expiry) where kind is
        # "steps" (expiry is a step count), "wall" (expiry is a wall-clock time),
        # or "human" (expiry is +inf; lifted only by human review / revoke).
        self.restricted: Dict[str, List[Tuple[Permission, str, float]]] = {}
        self._restrict_budgets: Dict[str, Dict[str, int]] = {}

        self.intent_graph = IntentGraph(
            self.embedding,
            max_entries=self.config.intent_graph_max,
            history_window=self.config.drift_history_window,
        )

        self._seen_nonces: "OrderedDict[str, bool]" = OrderedDict()
        self._seen_proposal_ids: "OrderedDict[str, bool]" = OrderedDict()

        self._embedding_needs_fit = isinstance(self.embedding, TfidfEmbeddingEngine)
        self._evals_since_fit = 0
        self._fitted_once = False
        self._refit_embedding(force=True)

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------
    def _deny(self, decision: Decision, reason: str, signals: List[RiskSignal], *,
              effective_authority: Optional[Authority] = None,
              execution_id: Optional[str] = None) -> GovernanceResult:
        return GovernanceResult(
            decision=decision,
            reason=reason,
            signals=signals,
            effective_authority=effective_authority.copy() if effective_authority else None,
            provenance=list(self.provenance),
            execution_id=execution_id,
        )

    def _remember(self, table: "OrderedDict[str, bool]", key: str, cap: int) -> None:
        table[key] = True
        table.move_to_end(key)
        while len(table) > cap:
            table.popitem(last=False)

    def _get_live_auth(self, agent_id: str) -> Authority:
        return self.live_authority.get(agent_id, Authority())

    def _active_restrictions(self, agent_id: str) -> Set[Permission]:
        now = time.time()
        active: Set[Permission] = set()
        kept: List[Tuple[Permission, str, float]] = []
        for perm, kind, expiry in self.restricted.get(agent_id, []):
            if kind == "human":
                live = True
            elif kind == "wall":
                live = expiry > now
            else:  # "steps"
                live = expiry > self.step_count
            if live:
                active.add(perm)
                kept.append((perm, kind, expiry))
        if agent_id in self.restricted:
            self.restricted[agent_id] = kept
        return active

    def _effective_authority(self, agent_id: str) -> Authority:
        base = self._get_live_auth(agent_id)
        active = self._active_restrictions(agent_id)
        if not active:
            return base
        return base.reduce_to(base.permissions - active)

    def _apply_restrict(self, agent_id: str, permission: Permission) -> None:
        policy = self.envelope.restrict_policy
        if policy == RestrictPolicy.TTL_STEPS:
            ttl = self.envelope.restrict_ttl_steps or 3
            self.restricted.setdefault(agent_id, []).append(
                (permission, "steps", float(self.step_count + ttl)))
        elif policy == RestrictPolicy.TTL_WALLCLOCK:
            ttl = self.envelope.restrict_ttl_seconds or 60.0
            self.restricted.setdefault(agent_id, []).append(
                (permission, "wall", time.time() + ttl))
        elif policy == RestrictPolicy.STEP_BUDGET:
            budget = self.envelope.restrict_step_budget or 10
            self._restrict_budgets.setdefault(agent_id, {})[permission.key()] = budget
        elif policy == RestrictPolicy.HUMAN_ONLY:
            self.restricted.setdefault(agent_id, []).append((permission, "human", _INF))

    def _check_restrict_budget(self, agent_id: str, permission: Permission) -> bool:
        """STEP_BUDGET policy: consume one unit; return True when it hits zero
        (meaning: escalate)."""
        if self.envelope.restrict_policy != RestrictPolicy.STEP_BUDGET:
            return False
        budgets = self._restrict_budgets.get(agent_id, {})
        key = permission.key()
        if key not in budgets:
            return False
        if budgets[key] <= 0:
            del budgets[key]
            return True
        budgets[key] -= 1
        return False

    def _refit_embedding(self, *, force: bool = False) -> None:
        if not self._embedding_needs_fit:
            return
        self._evals_since_fit += 1
        due = force or not self._fitted_once or (
            self._evals_since_fit >= self.config.embedding_refit_interval
        )
        if not due:
            return
        corpus = [self.envelope.objective]
        corpus.extend(p.objective_fragment for p in list(self.proposal_log)[-256:])
        try:
            self.embedding.fit(corpus)
        except Exception:  # noqa: BLE001
            logger.exception("embedding fit failed")
        self._evals_since_fit = 0
        self._fitted_once = True

    def _similarity(self, a: str, b: str) -> float:
        try:
            return float(self.embedding.similarity(a, b))
        except Exception:  # noqa: BLE001
            logger.exception("embedding similarity failed; treating as no overlap")
            return 0.0

    # ------------------------------------------------------------------
    # delegation
    # ------------------------------------------------------------------
    def register_delegation(self, from_agent: str, to_agent: str, reason: str,
                            offered: Authority) -> Tuple[bool, str]:
        with self._lock:
            if not self.envelope.knows_agent(from_agent):
                return False, f"unknown delegator agent '{from_agent}'"
            if not self.envelope.knows_agent(to_agent):
                return False, f"unknown recipient agent '{to_agent}'"

            from_auth = self._effective_authority(from_agent)
            max_to = self.envelope.get_max_authority(to_agent)

            from_role = self.envelope.get_role(from_agent)
            to_role = self.envelope.get_role(to_agent)
            if from_role and to_role:
                allowed = self.envelope.allowed_delegations.get(from_role, frozenset())
                if to_role not in allowed:
                    return False, f"Role violation: '{from_role}' cannot delegate to '{to_role}'"

            if not offered.is_subset_of(from_auth):
                return False, "Delegator attempted to grant authority it does not hold"

            new_auth = offered.reduce_to(max_to.permissions)
            self.live_authority[to_agent] = new_auth

            link = ProvenanceLink(from_id=from_agent, to_id=to_agent, reason=reason,
                                  delegated_authority=new_auth.copy())
            self.provenance.append(link)

            try:
                if self.audit.active:
                    self.audit.record_delegation(
                        from_agent=from_agent, to_agent=to_agent, reason=reason,
                        authority_repr=repr(new_auth),
                    )
            except Exception:  # noqa: BLE001
                logger.exception("delegation audit write failed")
                return False, "delegation audit write failed; delegation not recorded"

            if len(new_auth.permissions) < len(offered.permissions):
                return True, "Delegation accepted after reduction to recipient envelope"
            return True, "Delegation accepted (authority preserved or reduced)"

    def revoke_delegation(self, to_agent: str) -> bool:
        """Reset an agent's live authority back to its envelope ceiling."""
        with self._lock:
            if not self.envelope.knows_agent(to_agent):
                return False
            self.live_authority[to_agent] = self.envelope.get_max_authority(to_agent).copy()
            self.provenance.append(ProvenanceLink(
                from_id="<governor>", to_id=to_agent, reason="delegation revoked",
            ))
            return True

    # ------------------------------------------------------------------
    # evaluate
    # ------------------------------------------------------------------
    def evaluate(self, proposal: Proposal) -> GovernanceResult:
        agent = proposal.agent_id if isinstance(proposal.agent_id, str) else "<invalid>"
        with tracing.span("chainmail.evaluate", **{"chainmail.agent": agent}) as sp:
            with self._lock:
                result = self._evaluate_locked(proposal)
            sp.set_attribute("chainmail.decision", result.decision.value)
            sp.set_attribute("chainmail.signal_count", len(result.signals))
            if result.execution_id:
                sp.set_attribute("chainmail.execution_id", result.execution_id)
            return result

    def _evaluate_locked(self, proposal: Proposal) -> GovernanceResult:
        execution_id = secrets.token_hex(8)

        # (1) envelope integrity
        try:
            self.envelope.fingerprint()
        except RuntimeError as exc:
            logger.error("envelope drift detected: %s", exc)
            return self._deny(Decision.HUMAN, f"Envelope integrity check failed: {exc}",
                              [RiskSignal.ENVELOPE_DRIFT], execution_id=execution_id)

        # (2) structural validity
        problems = proposal.structural_problems()
        if problems:
            return self._deny(Decision.HUMAN, f"Malformed proposal: {'; '.join(problems)}",
                              [RiskSignal.INVALID_PROPOSAL], execution_id=execution_id)

        # (3) known agent
        if not self.envelope.knows_agent(proposal.agent_id):
            return self._deny(Decision.HUMAN, f"Agent '{proposal.agent_id}' is not in the envelope",
                              [RiskSignal.UNKNOWN_AGENT], execution_id=execution_id)

        # (3b) action allow-list (only when the envelope declares one)
        if (self.envelope.allowed_actions is not None
                and proposal.action not in self.envelope.allowed_actions):
            return self._deny(Decision.HUMAN,
                              f"Action '{proposal.action}' is not on the envelope allow-list",
                              [RiskSignal.UNKNOWN_ACTION], execution_id=execution_id)

        # (4) proposal-id dedupe
        if self.config.dedupe_proposal_ids and proposal.proposal_id in self._seen_proposal_ids:
            return self._deny(Decision.HUMAN,
                              f"Duplicate proposal_id '{proposal.proposal_id}'",
                              [RiskSignal.PROPOSAL_DUPLICATE], execution_id=execution_id)

        # (5) signature
        if proposal.signature:
            result = self._verify_signature(proposal)
            if not result:
                return self._deny(Decision.HUMAN, f"Invalid proposal signature: {result.reason}",
                                  [RiskSignal.SIGNATURE_INVALID], execution_id=execution_id)
        elif self.config.require_signature:
            return self._deny(Decision.HUMAN, "Proposal is unsigned but signatures are required",
                              [RiskSignal.SIGNATURE_MISSING], execution_id=execution_id)

        # (6) replay -- only meaningful once the signature (if any) is trusted
        if proposal.nonce:
            if proposal.nonce in self._seen_nonces:
                return self._deny(Decision.HUMAN, "Replay detected: nonce already consumed",
                                  [RiskSignal.REPLAY_DETECTED], execution_id=execution_id)
            self._remember(self._seen_nonces, proposal.nonce, self.config.max_seen_nonces)

        # commit: this is a real evaluation attempt
        if self.config.dedupe_proposal_ids:
            self._remember(self._seen_proposal_ids, proposal.proposal_id, self.config.proposal_log_max)
        self.step_count += 1
        self._agent_steps[proposal.agent_id] += 1
        self.proposal_log.append(proposal)
        self._refit_embedding()

        signals: List[RiskSignal] = []
        reason_parts: List[str] = []

        # (7) step budgets
        if self.step_count > self.envelope.max_fleet_steps:
            return self._deny(Decision.HUMAN, "Fleet step budget exhausted",
                              [RiskSignal.FLEET_BUDGET_EXHAUSTED], execution_id=execution_id)
        if (self.config.per_agent_step_budget
                and self._agent_steps[proposal.agent_id] > self.config.per_agent_step_budget):
            return self._deny(Decision.HUMAN,
                              f"Per-agent step budget exhausted for {proposal.agent_id}",
                              [RiskSignal.AGENT_BUDGET_EXHAUSTED], execution_id=execution_id)

        # (8) schema + path safety
        schema = self.envelope.get_schema(proposal.action)
        if schema is not None:
            ok, why, sig = schema.validate(proposal.payload)
            if not ok:
                label = "Path validation" if sig == RiskSignal.PATH_TRAVERSAL else "Schema violation"
                return self._deny(Decision.HUMAN, f"{label}: {'; '.join(why)}", [sig],
                                  execution_id=execution_id)

        # (9) hard denial
        if proposal.action in self.envelope.hard_denials:
            return self._deny(Decision.HUMAN,
                              f"Hard denial: action '{proposal.action}' is forbidden by envelope",
                              [RiskSignal.AUTHORITY_ABUSE], execution_id=execution_id)

        # (10) permission
        live_auth = self._get_live_auth(proposal.agent_id)
        current_auth = self._effective_authority(proposal.agent_id)
        if not current_auth.can(proposal.required_permission):
            return self._deny(Decision.HUMAN,
                              f"Agent {proposal.agent_id} lacks permission {proposal.required_permission}",
                              [RiskSignal.AUTHORITY_ABUSE], effective_authority=current_auth,
                              execution_id=execution_id)

        # (11) permission budget (checked now, consumed only on CONTINUE)
        if not live_auth.has_budget(proposal.required_permission):
            return self._deny(Decision.HUMAN,
                              f"Budget exhausted for {proposal.required_permission}",
                              [RiskSignal.BUDGET_EXHAUSTED], effective_authority=current_auth,
                              execution_id=execution_id)

        # (12) step-budget restriction
        if self._check_restrict_budget(proposal.agent_id, proposal.required_permission):
            return self._deny(Decision.HUMAN,
                              "Step-budget restriction exhausted for this permission",
                              [RiskSignal.AUTHORITY_ABUSE], effective_authority=current_auth,
                              execution_id=execution_id)

        # (13) contextual risk
        overlap = self._similarity(self.envelope.objective, proposal.objective_fragment)
        if overlap < self.config.objective_overlap_min:
            signals.append(RiskSignal.OBJECTIVE_MISMATCH)
        if proposal.confidence <= self.config.low_confidence_max:
            signals.append(RiskSignal.LOW_CONFIDENCE)

        try:
            drift = self.intent_graph.drift_score(
                self.envelope.objective, proposal.objective_fragment, proposal.agent_id)
        except Exception:  # noqa: BLE001 -- broken engine must not crash the governor
            logger.exception("intent graph drift failed; treating as full drift")
            drift = 1.0
        if drift > self.config.drift_max:
            signals.append(RiskSignal.DRIFT)

        try:
            peer_consensus = self.intent_graph.peer_consensus_score(
                self.envelope.objective, proposal.objective_fragment, proposal.agent_id)
        except Exception:  # noqa: BLE001
            logger.exception("intent graph peer consensus failed; treating as isolated")
            peer_consensus = 0.0
        if peer_consensus < self.config.peer_disagreement_max:
            signals.append(RiskSignal.HIGH_DISAGREEMENT)

        if (proposal.confidence >= self.config.anomaly_confidence_min
                and overlap < self.config.anomaly_overlap_max):
            signals.append(RiskSignal.ASSUMPTION_ANOMALY)

        # Re-entry: a reworded return to something this agent was already
        # refused. Hard-gated -- LOW unless the lineage holds a real refusal.
        try:
            reentry = self.intent_graph.reentry_risk(
                self.envelope.objective, proposal.objective_fragment, proposal.agent_id,
                confidence=proposal.confidence,
                high=self.config.reentry_high, medium=self.config.reentry_medium,
            )
        except Exception:  # noqa: BLE001
            logger.exception("intent graph re-entry check failed; failing closed")
            from .intent import ReentryRisk
            reentry = ReentryRisk("HIGH", 1.0, -1, "re-entry check raised")
        if reentry.level != "LOW":
            signals.append(RiskSignal.OBJECTIVE_REENTRY)

        # decision mapping
        if any(s in self.envelope.require_human_on for s in signals):
            decision = Decision.HUMAN
            reason_parts.append("Signal requires human review")
        elif reentry.level == "HIGH":
            decision = Decision.HUMAN
            reason_parts.append(f"Re-entry to a refused objective: {reentry.explanation}")
        elif RiskSignal.HIGH_DISAGREEMENT in signals or RiskSignal.ASSUMPTION_ANOMALY in signals:
            decision = Decision.RECHECK
            reason_parts.append("Cross-agent anomaly detected")
        elif reentry.level == "MEDIUM" or RiskSignal.DRIFT in signals or RiskSignal.LOW_CONFIDENCE in signals:
            decision = Decision.RESTRICT
            reason_parts.append("Trajectory caution -- restricting further")
        else:
            decision = Decision.CONTINUE
            reason_parts.append("Within envelope and objective continuity acceptable")

        # (14) audit started
        try:
            if self.audit.active:
                self.audit.record_proposal(
                    proposal_id=proposal.proposal_id, agent_id=proposal.agent_id,
                    action=proposal.action, decision="pending", signals=[],
                    overlap=overlap, drift=drift, phase="started", execution_id=execution_id,
                    objective_fragment=proposal.objective_fragment,
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("audit start failed")
            return self._deny(Decision.HUMAN,
                              f"Audit start failed; action not executed: {type(exc).__name__}",
                              [RiskSignal.SANITIZATION_FAILURE], execution_id=execution_id)

        # (15) Armour
        armour_output: Any = None
        if decision == Decision.CONTINUE and self.armour is not None:
            try:
                ok, msg, armour_output = self.armour.execute(proposal, current_auth.copy())
                if not ok:
                    decision = Decision.HUMAN
                    reason_parts.append(f"Armour boundary rejected: {msg}")
            except Exception as exc:  # noqa: BLE001
                logger.exception("armour boundary raised")
                decision = Decision.HUMAN
                reason_parts.append(f"Armour boundary error: {type(exc).__name__}")
                signals.append(RiskSignal.VERIFIER_ERROR)

        # (16) quorum
        quorum_votes: Optional[Dict[str, str]] = None
        if self.quorum is not None and decision == Decision.CONTINUE:
            own = GovernorVote(self.governor_id, Decision.CONTINUE, "; ".join(reason_parts))
            try:
                votes = self.quorum_transport.collect(own)
            except Exception:  # noqa: BLE001
                logger.exception("quorum transport failed")
                votes = []
            q_decision, q_reason, q_signals = self.quorum.aggregate(votes)
            quorum_votes = {v.governor_id: v.decision.value for v in votes}
            if q_decision != Decision.CONTINUE:
                decision = q_decision
                reason_parts.append(f"quorum: {q_reason}")
                signals.extend(q_signals)

        # (17) consume permission budget -- only on a real CONTINUE
        if decision == Decision.CONTINUE:
            live_auth.consume_budget(proposal.required_permission)

        # (18) apply restriction
        restricted_perms: Optional[Set[Permission]] = None
        if decision == Decision.RESTRICT:
            self._apply_restrict(proposal.agent_id, proposal.required_permission)
            restricted_perms = {proposal.required_permission}

        # intent-graph record. A RESTRICT/HUMAN turn is a refusal boundary: a
        # later reworded return to it is what reentry_risk() keys off.
        self.intent_graph.add(IntentGraphEntry(
            objective=self.envelope.objective, fragment=proposal.objective_fragment,
            decision=decision, agent_id=proposal.agent_id, timestamp=time.time(),
            safety_boundary=decision in (Decision.RESTRICT, Decision.HUMAN),
        ))

        # (19) audit completed
        try:
            if self.audit.active:
                self.audit.record_proposal(
                    proposal_id=proposal.proposal_id, agent_id=proposal.agent_id,
                    action=proposal.action, decision=decision.value,
                    signals=[s.value for s in signals], overlap=overlap, drift=drift,
                    phase="completed", execution_id=execution_id, armour_output=armour_output,
                    objective_fragment=proposal.objective_fragment,
                    trace_id=tracing.current_trace_id(),
                )
        except Exception as exc:  # noqa: BLE001
            logger.exception("audit completion failed")
            return self._deny(Decision.HUMAN, f"Audit completion failed: {type(exc).__name__}",
                              [RiskSignal.SANITIZATION_FAILURE], execution_id=execution_id)

        return GovernanceResult(
            decision=decision,
            reason="; ".join(reason_parts),
            signals=signals,
            effective_authority=current_auth.copy(),
            restricted_permissions=restricted_perms,
            provenance=list(self.provenance),
            quorum_votes=quorum_votes,
            execution_id=execution_id,
            armour_output=armour_output,
        )

    def _verify_signature(self, proposal: Proposal):
        try:
            return self.verifier.verify(proposal)
        except Exception:  # noqa: BLE001
            logger.exception("approval verifier raised")
            from .crypto import VerificationResult
            return VerificationResult(False, "verifier raised an exception")

    # ------------------------------------------------------------------
    # introspection
    # ------------------------------------------------------------------
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            def _exp(v: float) -> Any:
                return "inf" if v == _INF else v
            return {
                "governor_id": self.governor_id,
                "objective": self.envelope.objective,
                "step_count": self.step_count,
                "agent_steps": dict(self._agent_steps),
                "live_authority": {k: repr(v) for k, v in self.live_authority.items()},
                "restricted": {
                    k: [(repr(p), kind, _exp(e)) for p, kind, e in v]
                    for k, v in self.restricted.items()
                },
                "restrict_budgets": deepcopy(self._restrict_budgets),
                "provenance_len": len(self.provenance),
                "proposals_seen": len(self.proposal_log),
                "intent_graph_entries": len(self.intent_graph.entries),
                "seen_nonces": len(self._seen_nonces),
                "envelope_fingerprint": self.envelope._construction_fingerprint[:16] + "...",
                "restrict_policy": self.envelope.restrict_policy.value,
                "embedding_engine": type(self.embedding).__name__,
            }

    def suggest_envelope(self) -> Dict[str, Any]:
        if self.audit.sqlite is None:
            return {"error": "SQLite persistence required for envelope suggestion"}
        history = self.audit.sqlite.get_proposal_history()
        if not history:
            return {"suggestion": "No history available"}

        actions = Counter(h["action"] for h in history)
        decisions = Counter(h["decision"] for h in history)
        agents = Counter(h["agent_id"] for h in history)
        out: Dict[str, Any] = {
            "most_common_actions": dict(actions.most_common(5)),
            "decision_distribution": dict(decisions),
            "most_active_agents": dict(agents.most_common(5)),
            "recommendations": [],
        }
        n = len(history)
        if decisions.get("HUMAN", 0) / n > 0.3:
            out["recommendations"].append(
                "High HUMAN rate; consider broadening authority or improving agent confidence")
        if decisions.get("RESTRICT", 0) / n > 0.2:
            out["recommendations"].append(
                "High RESTRICT rate; consider tightening the objective or the semantic engine")
        if len(actions) > 10:
            out["recommendations"].append(
                "Many distinct actions; add ActionSchemas for the most common ones")
        return out


# Backwards-compatible alias.
ChainmailV5 = ChainmailGovernor
