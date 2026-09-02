"""
Chainmail v5 --- policy-hard, context-fluid governance for long-running
multi-agent systems.

    The links don't bend. The chain does.
"""

from __future__ import annotations

__version__ = "5.1.0"

from .execution_boundary import (
    DenyAllExecutionBoundary, ExecutionBoundary, GuardedExecutorAdapter,
    PermissiveExecutionBoundary,
)
from .builders import build_demo_envelope, make_permission
from .config import GovernorConfig
from .core import (
    ActionSchema, Authority, Decision, GovernanceResult, Permission, Proposal,
    ProvenanceLink, RestrictPolicy, RiskSignal, StructuredAssumption,
)
from .crypto import (
    ALGO_ED25519, ALGO_HMAC, ApprovalVerifier, CompositeVerifier, KeyRegistry,
    NullApprovalVerifier, VerificationResult, canonical_signing_bytes,
    generate_ed25519_keypair, sign_proposal,
)
from .embeddings import (
    EmbeddingEngine, Model2VecEmbeddingEngine, SentenceTransformerEmbeddingEngine,
    TfidfEmbeddingEngine, auto_embedding_engine,
)
from .envelope import AuthorityEnvelope
from .evaluation import (
    Mutation, MutationReport, MutationRunner, STANDARD_INVARIANTS, standard_mutant_family,
)
from .governor import ChainmailGovernor, ChainmailV5
from .intent import IntentGraph, IntentGraphEntry, ReentryRisk
from .redaction import scrub_pii
from . import tracing
from .persistence import (
    AuditSink, HashChainLog, ReceiptIntegrityError, ReceiptVerification, SQLiteStore,
)
from .quorum import (
    GovernorVote, LocalSingleGovernorTransport, QuorumAggregator, StaticPeerTransport,
    VoteTransport,
)

__all__ = [
    "__version__",
    # core
    "ActionSchema", "Authority", "Decision", "GovernanceResult", "Permission",
    "Proposal", "ProvenanceLink", "RestrictPolicy", "RiskSignal", "StructuredAssumption",
    # config
    "GovernorConfig",
    # envelope + builders
    "AuthorityEnvelope", "build_demo_envelope", "make_permission",
    # governor
    "ChainmailGovernor", "ChainmailV5",
    # embeddings
    "EmbeddingEngine", "TfidfEmbeddingEngine", "Model2VecEmbeddingEngine",
    "SentenceTransformerEmbeddingEngine", "auto_embedding_engine",
    # intent
    "IntentGraph", "IntentGraphEntry", "ReentryRisk",
    # adversarial evaluation
    "MutationRunner", "Mutation", "MutationReport", "standard_mutant_family",
    "STANDARD_INVARIANTS",
    # redaction + tracing
    "scrub_pii", "tracing",
    # crypto
    "ApprovalVerifier", "CompositeVerifier", "NullApprovalVerifier", "VerificationResult",
    "KeyRegistry", "sign_proposal", "canonical_signing_bytes", "generate_ed25519_keypair",
    "ALGO_ED25519", "ALGO_HMAC",
    # persistence
    "AuditSink", "HashChainLog", "SQLiteStore", "ReceiptVerification", "ReceiptIntegrityError",
    # quorum
    "QuorumAggregator", "GovernorVote", "VoteTransport", "LocalSingleGovernorTransport",
    "StaticPeerTransport",
    # execution boundary
    "ExecutionBoundary", "PermissiveExecutionBoundary", "DenyAllExecutionBoundary",
    "GuardedExecutorAdapter",
]
