"""
Chainmail v5 --- Armour execution boundary.

Chainmail governs *trajectory*; Armour governs the *single action*. When the
governor decides CONTINUE it hands the proposal to an ``ArmourBoundary`` for the
final execution check. A boundary that returns ``ok=False`` or raises forces the
governor to HUMAN (fail-closed).

``GuardedExecutorAdapter`` is the integration seam for a real Armour
``GuardedExecutor``: pass any callable with the signature
``(proposal, authority) -> (ok, message, output)``.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Tuple

from .core import Authority, Proposal

logger = logging.getLogger(__name__)

ExecResult = Tuple[bool, str, Any]


class ArmourBoundary:
    def execute(self, proposal: Proposal, authority: Authority) -> ExecResult:
        raise NotImplementedError


class MockArmourBoundary(ArmourBoundary):
    """Authorises every proposal unconditionally. Development only -- logs a
    warning on construction, matching ``NullApprovalVerifier``."""

    def __init__(self) -> None:
        logger.warning(
            "MockArmourBoundary in use: every CONTINUE decision is authorised "
            "unconditionally -- no real execution boundary is enforced"
        )

    def execute(self, proposal: Proposal, authority: Authority) -> ExecResult:
        return True, f"MockArmour: {proposal.action} executed", {"action": proposal.action}


class DenyAllArmourBoundary(ArmourBoundary):
    def execute(self, proposal: Proposal, authority: Authority) -> ExecResult:
        return False, "MockArmour: action denied by execution boundary", None


class GuardedExecutorAdapter(ArmourBoundary):
    """Wrap a real Armour ``GuardedExecutor`` (or any compatible callable)."""

    def __init__(self, executor: Callable[[Proposal, Authority], ExecResult]) -> None:
        self._executor = executor

    def execute(self, proposal: Proposal, authority: Authority) -> ExecResult:
        result = self._executor(proposal, authority)
        if (
            not isinstance(result, tuple)
            or len(result) != 3
            or not isinstance(result[0], bool)
            or not isinstance(result[1], str)
        ):
            raise TypeError(
                "guarded executor must return (ok: bool, message: str, output: Any)"
            )
        return result
