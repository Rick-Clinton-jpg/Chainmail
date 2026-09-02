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
 15. quorum (only if CONTINUE) -- MUST precede execution; a peer veto is
     meaningless after the side effect has already happened
 16. execution boundary (only if CONTINUE, i.e. quorum also agreed)
 17. consume permission budget  (only if the final decision is CONTINUE)
 18. apply restriction          (only if the final decision is RESTRICT)
 19. audit "completed"
"""

from __future__ import annotations

import logging
import secrets
import sqlite3
import threading
import time
from collections import Counter, OrderedDict
from collections import deque
from copy import deepcopy
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from .execution_boundary import ExecutionBoundary, PermissiveExecutionBoundary
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
        execution_boundary: Optional[ExecutionBoundary] = None,
        audit: Optional[AuditSink] = None,
        verifier: Optional[ApprovalVerifier] = None,
        quorum: Optional[QuorumAggregator] = None,
        quorum_transport: Optional[VoteTransport] = None,
        governor_id: str = "governor-0",
        auto_embedding: bool = True,
        deployment_namespace: str = "default",
    ) -> None:
        self.envelope = envelope
        self.config = config or GovernorConfig()
        self.governor_id = governor_id
        self.deployment_namespace = deployment_namespace
        self.execution_boundary = execution_boundary
        self.audit = audit or AuditSink()
        self.verifier: ApprovalVerifier = verifier or NullApprovalVerifier()
        if self.config.require_signature and isinstance(self.verifier, NullApprovalVerifier):
            raise ValueError(
                "config.require_signature=True but no real ApprovalVerifier was "
                "supplied: NullApprovalVerifier accepts every proposal, which "
                "would make signature enforcement meaningless. Pass an explicit "
                "verifier= (e.g. CompositeVerifier(KeyRegistry(...))) or set "
                "require_signature=False for a development configuration."
            )
        if self.config.production_mode and self.audit.sqlite is None:
            raise ValueError(
                "config.production_mode=True (set by GovernorConfig.production()) "
                "requires durable storage, but no SQLiteStore is wired into audit: "
                "in-memory-only nonce/proposal-ID replay protection and restriction "
                "state do not survive a restart and offer no protection across "
                "multiple governor processes. Pass "
                "audit=AuditSink(sqlite_store=SQLiteStore(...)), or build a "
                "non-production GovernorConfig() for development."
            )
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

        self._log_security_report()

    # ------------------------------------------------------------------
    # security diagnostics
    # ------------------------------------------------------------------
    def security_report(self) -> Dict[str, Any]:
        """Describe which protections are actually active on this governor.

        Intended for startup logging and operational checks -- a user who
        assumes signatures, an execution boundary, or a real quorum are
        enforced should be able to confirm that from this report rather than
        from reading source. See HANDOFF.md / the security assessment for
        the full rationale (each of these is a real config knob, not a
        cosmetic flag).
        """
        signature_enforced = self.config.require_signature and not isinstance(
            self.verifier, NullApprovalVerifier
        )
        boundary_wired = (
            self.execution_boundary is not None
            and not isinstance(self.execution_boundary, PermissiveExecutionBoundary)
        )
        weaknesses: List[str] = []
        if not signature_enforced:
            weaknesses.append(
                "proposal signatures are NOT enforced -- any caller can act as any "
                "agent; use GovernorConfig.production() with a CompositeVerifier"
            )
        if not boundary_wired:
            weaknesses.append(
                "no real execution boundary is wired -- PermissiveExecutionBoundary "
                "(or none at all) authorises every CONTINUE decision unconditionally"
            )
        if self.quorum is None:
            weaknesses.append(
                "no quorum aggregator is configured -- this governor's CONTINUE "
                "decisions are final with no peer-governor review"
            )
        durable_replay = self.audit.sqlite is not None
        if not durable_replay:
            weaknesses.append(
                "nonce and proposal-ID replay protection is in-memory only -- a "
                "restart or crash silently drops it, and it offers no protection "
                "across multiple governor processes; wire a SQLiteStore into "
                "AuditSink for durable, atomic replay protection"
            )
        durable_restrictions = self.audit.sqlite is not None
        if not durable_restrictions:
            weaknesses.append(
                "restriction state is in-memory only -- a restart silently drops "
                "active restrictions, and multiple governor processes cannot "
                "observe restrictions imposed by one another; wire a SQLiteStore "
                "into AuditSink for durable restriction storage"
            )
        return {
            "governor_id": self.governor_id,
            "signature_required": self.config.require_signature,
            "signature_enforced": signature_enforced,
            "verifier": type(self.verifier).__name__,
            "execution_boundary": (
                type(self.execution_boundary).__name__ if self.execution_boundary is not None else None
            ),
            "execution_boundary_wired": boundary_wired,
            "quorum_configured": self.quorum is not None,
            "dedupe_proposal_ids": self.config.dedupe_proposal_ids,
            "durable_replay_protection": durable_replay,
            "durable_restriction_protection": durable_restrictions,
            "production_mode": self.config.production_mode,
            "deployment_namespace": self.deployment_namespace,
            "weaknesses": weaknesses,
        }

    def _log_security_report(self) -> None:
        report = self.security_report()
        if report["weaknesses"]:
            logger.warning(
                "chainmail governor %s starting with reduced protections: %s",
                self.governor_id, "; ".join(report["weaknesses"]),
            )
        else:
            logger.info(
                "chainmail governor %s starting with signatures enforced, a real "
                "execution boundary, and quorum configured", self.governor_id,
            )

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

    def _nonce_cache_key(self, agent_id: str, nonce: str) -> str:
        # Nonce scope is per-agent (see SQLiteStore.claim_nonce); the
        # in-memory cache key must match so a cache hit/miss means the same
        # thing the durable store would say.
        return f"{agent_id}:{nonce}"

    def _claim_replay_identifiers(self, proposal: Proposal, durable: bool,
                                  execution_id: Optional[str]) -> Optional[GovernanceResult]:
        """Claim ``proposal.nonce`` and (if enabled) ``proposal.proposal_id``.

        Returns a denial ``GovernanceResult`` on replay or persistence
        failure, else ``None`` on success (the identifiers are claimed as a
        side effect). See ``SQLiteStore.claim_nonce`` / ``claim_proposal_id``
        for the durable path's scope and atomicity guarantees -- this method
        never does a separate check-then-insert against the store; a claim
        is a single atomic call, and a UNIQUE conflict *is* the replay
        signal. The uniqueness boundary is (namespace, agent_id, nonce) /
        (namespace, proposal_id) -- deliberately independent of the
        envelope/policy fingerprint, so a policy change can never make an
        earlier signed proposal replayable again.

        Consumption is unconditional: once claimed here (which only happens
        after signature verification, above this call in ``evaluate``), the
        identifiers stay consumed even if the contextual-risk checks further
        down ``evaluate`` land on RESTRICT / RECHECK / HUMAN rather than
        CONTINUE. There is no path that "returns" a claimed nonce -- retrying
        requires a new proposal with a new nonce, regardless of how the
        original one was decided.
        """
        if durable:
            envelope_fp = self.envelope._construction_fingerprint
            key_id = proposal.signature.split(":", 1)[0] if proposal.signature and ":" in proposal.signature else None

            if proposal.nonce:
                # A local cache hit is trustworthy -- the cache is only ever
                # populated after a claim durably succeeded -- so it short-
                # circuits repeat replay attempts without a DB round trip. A
                # cache miss is NOT proof the nonce is free (another governor
                # instance sharing this store may hold it), so it always
                # falls through to the authoritative atomic claim below. The
                # cache key includes agent_id to match nonce scope being
                # per-agent (see SQLiteStore.claim_nonce).
                cache_key = self._nonce_cache_key(proposal.agent_id, proposal.nonce)
                if cache_key in self._seen_nonces:
                    return self._deny(Decision.HUMAN, "Replay detected: nonce already consumed",
                                      [RiskSignal.REPLAY_DETECTED], execution_id=execution_id)
                try:
                    claimed = self.audit.sqlite.claim_nonce(
                        namespace=self.deployment_namespace, envelope_fingerprint=envelope_fp,
                        agent_id=proposal.agent_id, nonce=proposal.nonce, key_id=key_id,
                    )
                except sqlite3.Error as exc:
                    return self._replay_store_failure(proposal, exc, execution_id)
                if not claimed:
                    return self._deny(Decision.HUMAN, "Replay detected: nonce already consumed",
                                      [RiskSignal.REPLAY_DETECTED], execution_id=execution_id)
                self._remember(self._seen_nonces, cache_key, self.config.max_seen_nonces)

            if self.config.dedupe_proposal_ids:
                if proposal.proposal_id in self._seen_proposal_ids:
                    return self._deny(Decision.HUMAN,
                                      f"Duplicate proposal_id '{proposal.proposal_id}'",
                                      [RiskSignal.PROPOSAL_DUPLICATE], execution_id=execution_id)
                try:
                    claimed = self.audit.sqlite.claim_proposal_id(
                        namespace=self.deployment_namespace, envelope_fingerprint=envelope_fp,
                        proposal_id=proposal.proposal_id, agent_id=proposal.agent_id,
                    )
                except sqlite3.Error as exc:
                    return self._replay_store_failure(proposal, exc, execution_id)
                if not claimed:
                    return self._deny(Decision.HUMAN,
                                      f"Duplicate proposal_id '{proposal.proposal_id}'",
                                      [RiskSignal.PROPOSAL_DUPLICATE], execution_id=execution_id)
                self._remember(self._seen_proposal_ids, proposal.proposal_id,
                               self.config.proposal_log_max)
            return None

        # non-durable: the in-memory cache is both the check and the record,
        # protected only by this process's lock -- fine single-process, not
        # durable across a restart or meaningful across multiple processes.
        # Same per-agent nonce scope as the durable path, for one consistent
        # meaning of "replay" regardless of whether persistence is wired in.
        if proposal.nonce:
            cache_key = self._nonce_cache_key(proposal.agent_id, proposal.nonce)
            if cache_key in self._seen_nonces:
                return self._deny(Decision.HUMAN, "Replay detected: nonce already consumed",
                                  [RiskSignal.REPLAY_DETECTED], execution_id=execution_id)
            self._remember(self._seen_nonces, cache_key, self.config.max_seen_nonces)
        if self.config.dedupe_proposal_ids:
            self._remember(self._seen_proposal_ids, proposal.proposal_id, self.config.proposal_log_max)
        return None

    def _replay_store_failure(self, proposal: Proposal, exc: Exception,
                              execution_id: Optional[str]) -> GovernanceResult:
        logger.exception("durable replay-protection store is unavailable")
        try:
            if self.audit.hash_chain is not None:
                self.audit.hash_chain.append("replay_store_failure", {
                    "agent_id": proposal.agent_id, "proposal_id": proposal.proposal_id,
                    "error": type(exc).__name__,
                }, phase="failed", execution_id=execution_id)
        except Exception:  # noqa: BLE001
            logger.exception("failed to record replay-store failure to hash chain")
        return self._deny(Decision.HUMAN,
                          f"Durable replay-protection store is unavailable: {type(exc).__name__}",
                          [RiskSignal.REPLAY_STORE_UNAVAILABLE], execution_id=execution_id)

    def _get_live_auth(self, agent_id: str) -> Authority:
        return self.live_authority.get(agent_id, Authority())

    def _is_restriction_live(self, kind: str, expiry: float) -> bool:
        if kind == "human":
            return True
        if kind == "wall":
            return expiry > time.time()
        return expiry > self.step_count  # "steps"

    def _active_restrictions(self, agent_id: str) -> Set[Permission]:
        """The set of currently-restricted permissions for ``agent_id``.

        Durable mode (a SQLiteStore wired into AuditSink) reads the store
        fresh on every call -- never a cached/loaded-at-__init__ snapshot --
        so this reflects restrictions imposed or cleared by *any* governor
        process sharing the store, not just this one. ``sqlite3.Error``
        propagates to the caller (see ``evaluate``), which fails closed
        rather than silently falling back to "no restrictions".
        """
        if self.audit.sqlite is not None:
            return self._active_restrictions_durable(agent_id)
        now = time.time()
        active: Set[Permission] = set()
        kept: List[Tuple[Permission, str, float]] = []
        for perm, kind, expiry in self.restricted.get(agent_id, []):
            if self._is_restriction_live(kind, expiry):
                active.add(perm)
                kept.append((perm, kind, expiry))
        if agent_id in self.restricted:
            self.restricted[agent_id] = kept
        return active

    def _active_restrictions_durable(self, agent_id: str) -> Set[Permission]:
        rows = self.audit.sqlite.active_restrictions(
            namespace=self.deployment_namespace, agent_id=agent_id)
        active: Set[Permission] = set()
        for row in rows:
            live = self._is_restriction_live(row["expiry_kind"], row["expiry_value"])
            if live:
                active.add(Permission(row["permission_name"], row["permission_scope"],
                                      row["permission_max_budget"]))
            else:
                try:
                    self.audit.sqlite.mark_expired(
                        namespace=self.deployment_namespace, agent_id=agent_id,
                        restriction_id=row["restriction_id"],
                    )
                except sqlite3.Error:
                    # Best-effort bookkeeping: the row is already correctly
                    # excluded from `active` above regardless of whether this
                    # write succeeds, so a failure here doesn't need to fail
                    # the whole evaluation -- only imposing/reading a
                    # restriction does.
                    logger.exception("failed to mark restriction %s expired (non-fatal)",
                                     row["restriction_id"])
        return active

    def _effective_authority(self, agent_id: str) -> Authority:
        base = self._get_live_auth(agent_id)
        active = self._active_restrictions(agent_id)
        if not active:
            return base
        # Removal must use the same name/scope *coverage* relation used to
        # grant authority in the first place (Authority.can() / covers()),
        # not exact Permission equality. A restriction is recorded against
        # whatever Permission the restricted proposal declared
        # (required_permission) -- e.g. a specific max_budget or a wildcard
        # scope -- which need not be object-identical to the base
        # permission it was actually authorised by. A plain set difference
        # (base.permissions - active) silently keeps the base permission,
        # and the restriction has no effect, whenever the two differ in any
        # field including max_budget: exact equality is the wrong test for
        # "does this restriction apply to this permission".
        remaining = {p for p in base.permissions if not any(p.covers(r) for r in active)}
        return base.reduce_to(remaining)

    def _compute_restrict_expiry(self) -> Optional[Tuple[str, float]]:
        """The (kind, value) a new restriction would get under the envelope's
        current ``restrict_policy``, or None for STEP_BUDGET -- that policy
        has no expiry row; it consumes ``_restrict_budgets`` instead, which
        is out of scope for durable persistence in this commit (tracked with
        the rest of budget durability)."""
        policy = self.envelope.restrict_policy
        if policy == RestrictPolicy.TTL_STEPS:
            ttl = self.envelope.restrict_ttl_steps or 3
            return ("steps", float(self.step_count + ttl))
        if policy == RestrictPolicy.TTL_WALLCLOCK:
            ttl = self.envelope.restrict_ttl_seconds or 60.0
            return ("wall", time.time() + ttl)
        if policy == RestrictPolicy.HUMAN_ONLY:
            return ("human", _INF)
        return None

    def _apply_restrict(self, agent_id: str, permission: Permission,
                        expiry: Optional[Tuple[str, float]]) -> None:
        """In-memory bookkeeping. ``expiry`` is whatever
        ``_compute_restrict_expiry()`` returned -- None means STEP_BUDGET.

        When durable restriction storage is configured, an expiring
        restriction (expiry is not None) is NOT mirrored here: the durable
        store is the sole source of truth for it (see
        ``_active_restrictions``), and keeping a shadow copy that nothing
        ever prunes would just grow unboundedly and go stale. STEP_BUDGET
        remains in-memory-only regardless of durability (see
        ``_compute_restrict_expiry``).
        """
        if expiry is None:
            budget = self.envelope.restrict_step_budget or 10
            self._restrict_budgets.setdefault(agent_id, {})[permission.key()] = budget
            return
        if self.audit.sqlite is not None:
            return
        kind, value = expiry
        self.restricted.setdefault(agent_id, []).append((permission, kind, value))

    def _restriction_reason_code(self, signals: List[RiskSignal]) -> str:
        return ",".join(s.value for s in signals) if signals else "RESTRICT"

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

            new_auth = offered.clamp_to_ceiling(max_to)
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
        # Snapshot immediately: Proposal is a mutable dataclass (sign_proposal
        # itself mutates .nonce/.signature in place), so the caller retains a
        # live reference to whatever object it passed in. Every check below,
        # the audit log, and -- critically -- the execution boundary must all
        # observe the exact same values that were verified; deep-copying here,
        # before any check runs, and rebinding `proposal` to the copy makes
        # that true structurally. Nothing the caller does to its own
        # reference after this point can reach a check or the executor.
        proposal = deepcopy(proposal)
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

        # (4) proposal-id dedupe -- a cache lookup only (never a claim). With a
        # durable replay store configured this pre-check is skipped: a
        # check-then-later-claim here would be exactly the race a second
        # governor instance sharing the store could win against (see (6)), so
        # the durable path defers to the atomic claim below instead.
        durable_replay = self.audit.sqlite is not None
        if (not durable_replay and self.config.dedupe_proposal_ids
                and proposal.proposal_id in self._seen_proposal_ids):
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

        # (6) replay -- claim the nonce and proposal_id only now that the
        # signature (if any) is trusted; an unauthenticated proposal can
        # never claim (and so can never poison) an identifier a legitimate,
        # signed proposal will need later.
        denial = self._claim_replay_identifiers(proposal, durable_replay, execution_id)
        if denial is not None:
            return denial

        # commit: this is a real evaluation attempt
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
        try:
            current_auth = self._effective_authority(proposal.agent_id)
        except sqlite3.Error as exc:
            logger.exception("durable restriction store is unavailable")
            return self._deny(Decision.HUMAN,
                              f"Durable restriction store is unavailable: {type(exc).__name__}",
                              [RiskSignal.RESTRICTION_STORE_UNAVAILABLE], execution_id=execution_id)
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

        # (15) quorum -- MUST run before the execution boundary. A peer veto
        # is meaningless once the side effect has already happened, so no
        # governor process may execute a proposal before every configured
        # vote is collected and aggregated to CONTINUE.
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

        # (16) execution boundary -- only once quorum (if configured) has
        # also agreed to CONTINUE.
        execution_output: Any = None
        if decision == Decision.CONTINUE and self.execution_boundary is not None:
            try:
                ok, msg, execution_output = self.execution_boundary.execute(proposal, current_auth.copy())
                if not ok:
                    decision = Decision.HUMAN
                    reason_parts.append(f"Execution boundary rejected: {msg}")
            except Exception as exc:  # noqa: BLE001
                logger.exception("execution boundary raised")
                decision = Decision.HUMAN
                reason_parts.append(f"Execution boundary error: {type(exc).__name__}")
                signals.append(RiskSignal.VERIFIER_ERROR)

        # (17) consume permission budget -- only on a real CONTINUE
        if decision == Decision.CONTINUE:
            live_auth.consume_budget(proposal.required_permission)

        # (18) apply restriction. Durable persistence, when configured, is
        # attempted BEFORE any in-memory mutation and before the decision is
        # returned: on failure the decision is downgraded to HUMAN here (fail
        # closed) and _apply_restrict is never called, so this governor never
        # reports a restriction as imposed when it exists only in memory.
        restricted_perms: Optional[Set[Permission]] = None
        if decision == Decision.RESTRICT:
            expiry = self._compute_restrict_expiry()
            persisted = True
            if expiry is not None and self.audit.sqlite is not None:
                kind, value = expiry
                try:
                    self.audit.sqlite.impose_restriction(
                        namespace=self.deployment_namespace, agent_id=proposal.agent_id,
                        permission_name=proposal.required_permission.name,
                        permission_scope=proposal.required_permission.scope,
                        permission_max_budget=proposal.required_permission.max_budget,
                        reason_code=self._restriction_reason_code(signals),
                        source_proposal_id=proposal.proposal_id,
                        envelope_fingerprint=self.envelope._construction_fingerprint,
                        expiry_kind=kind, expiry_value=value,
                    )
                except sqlite3.Error as exc:
                    logger.exception("durable restriction store is unavailable")
                    decision = Decision.HUMAN
                    reason_parts.append(
                        f"Durable restriction store is unavailable: {type(exc).__name__}")
                    signals.append(RiskSignal.RESTRICTION_STORE_UNAVAILABLE)
                    persisted = False
            if persisted:
                self._apply_restrict(proposal.agent_id, proposal.required_permission, expiry)
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
                    phase="completed", execution_id=execution_id, execution_output=execution_output,
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
            execution_output=execution_output,
        )

    def _verify_signature(self, proposal: Proposal):
        try:
            return self.verifier.verify(proposal)
        except Exception:  # noqa: BLE001
            logger.exception("approval verifier raised")
            from .crypto import VerificationResult
            return VerificationResult(False, "verifier raised an exception")

    # ------------------------------------------------------------------
    # restriction release
    # ------------------------------------------------------------------
    def clear_restriction(self, agent_id: str, restriction_id: str, *,
                          authorised_by: str, reason: str = "") -> str:
        """Explicitly clear one durably-imposed restriction.

        Requires durable restriction storage (a SQLiteStore wired into
        AuditSink) -- there is no in-memory equivalent; a non-durable
        governor's TTL/HUMAN_ONLY restrictions clear themselves on expiry or
        aren't meant to be released by anything but that expiry.

        The release is bound to the exact ``(agent_id, restriction_id)``
        pair -- see ``SQLiteStore.clear_restriction`` for why a stale release
        can never clear a different, newer restriction. ``authorised_by``
        (who/what approved this) and ``reason`` are recorded on the
        restriction and in the append-only event history. Idempotent:
        clearing an already-cleared restriction returns ``"already_cleared"``
        rather than raising.

        Returns one of ``"cleared"`` / ``"already_cleared"`` / ``"not_found"``
        / ``"wrong_agent"`` (see ``SQLiteStore.clear_restriction``).
        """
        if self.audit.sqlite is None:
            raise RuntimeError(
                "clear_restriction requires durable restriction storage: no SQLiteStore "
                "is wired into audit. Non-durable restrictions are not individually "
                "releasable -- they clear themselves on TTL expiry."
            )
        if not authorised_by:
            raise ValueError("authorised_by is required: who or what authorised this release "
                             "must be recorded")
        with self._lock:
            return self.audit.sqlite.clear_restriction(
                namespace=self.deployment_namespace, agent_id=agent_id,
                restriction_id=restriction_id, authorised_by=authorised_by, reason=reason,
                policy_version=self.envelope._construction_fingerprint,
            )

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
