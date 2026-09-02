"""
Chainmail v5 --- execution boundary seam.

Chainmail governs *trajectory* -- authority, delegation, objectives, replay,
budgets over the life of a fleet. It deliberately does not govern the *single
action*: that is a separate concern, with its own threat model (argument
canonicalisation, side-effect containment, capability enforcement at the
syscall/API boundary). When the governor decides ``CONTINUE`` it hands the
proposal to an ``ExecutionBoundary`` for a final, independent execution
check. A boundary that returns ``ok=False`` or raises forces the governor to
``HUMAN`` (fail-closed) -- Chainmail's own decision is never final on its own.

This module has no dependency on any specific execution-boundary project.
``GuardedExecutorAdapter`` is a generic integration seam: pass any callable
with the signature ``(proposal, authority) -> (ok, message, output)`` --
including, but not limited to, a project like Armour's ``GuardedExecutor``.
Chainmail may adopt *lessons* from sibling execution-boundary projects
(canonicalisation, fail-closed adapter behaviour) without depending on or
importing any of them.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Tuple

from .core import Authority, Proposal

logger = logging.getLogger(__name__)

ExecResult = Tuple[bool, str, Any]


class ExecutionBoundary:
    def execute(self, proposal: Proposal, authority: Authority) -> ExecResult:
        raise NotImplementedError


class PermissiveExecutionBoundary(ExecutionBoundary):
    """Authorises every proposal unconditionally. Development only -- logs a
    warning on construction, matching ``NullApprovalVerifier``."""

    def __init__(self) -> None:
        logger.warning(
            "PermissiveExecutionBoundary in use: every CONTINUE decision is "
            "authorised unconditionally -- no real execution boundary is enforced"
        )

    def execute(self, proposal: Proposal, authority: Authority) -> ExecResult:
        return True, f"permissive boundary: {proposal.action} executed", {"action": proposal.action}


class DenyAllExecutionBoundary(ExecutionBoundary):
    def execute(self, proposal: Proposal, authority: Authority) -> ExecResult:
        return False, "action denied by execution boundary", None


class GuardedExecutorAdapter(ExecutionBoundary):
    """Wrap an external execution-boundary handler (or any compatible callable)."""

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
