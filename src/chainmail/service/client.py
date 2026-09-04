"""
Chainmail v5 service --- client library.

    with GovernorClient("/run/chainmail.sock", auth_token=tok) as gov:
        result = gov.evaluate(proposal)
"""

from __future__ import annotations

import itertools
import socket
import threading
from typing import Any, Dict, Optional

from ..core import Authority, GovernanceResult
from .protocol import (
    ProtocolError, authority_to_dict, proposal_to_dict, read_frame, write_frame,
)


class GovernorClientError(Exception):
    pass


class GovernorClient:
    def __init__(self, socket_path: str, *, auth_token: Optional[str] = None,
                 timeout: float = 30.0) -> None:
        self.socket_path = socket_path
        self._auth_token = auth_token
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    # -- lifecycle --------------------------------------------------
    def connect(self) -> "GovernorClient":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        sock.connect(self.socket_path)
        self._sock = sock
        if self._auth_token:
            resp = self._roundtrip({"op": "auth", "token": self._auth_token})
            if not resp.get("ok"):
                self.close()
                raise GovernorClientError(f"authentication failed: {resp.get('error')}")
        return self

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "GovernorClient":
        return self.connect()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- rpc -----------------------------------------------------
    def _roundtrip(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._sock is None:
            raise GovernorClientError("client is not connected")
        with self._lock:
            payload = dict(payload, id=next(self._ids))
            try:
                write_frame(self._sock, payload)
                resp = read_frame(self._sock)
            except (ProtocolError, ConnectionError, OSError) as exc:
                raise GovernorClientError(str(exc)) from exc
        return resp

    def _call(self, payload: Dict[str, Any]) -> Any:
        resp = self._roundtrip(payload)
        if not resp.get("ok"):
            raise GovernorClientError(resp.get("error", "unknown server error"))
        return resp.get("result")

    # -- operations ----------------------------------------------
    def ping(self) -> bool:
        return bool(self._call({"op": "ping"}).get("pong"))

    def evaluate(self, proposal) -> Dict[str, Any]:
        """Return the raw result dict (see ``GovernanceResult.to_dict``)."""
        return self._call({"op": "evaluate", "proposal": proposal_to_dict(proposal)})

    def register_delegation(self, from_agent: str, to_agent: str, reason: str,
                            offered: Authority, *, merge: bool = False) -> Dict[str, Any]:
        """``merge=True`` accumulates ``offered`` onto whatever ``to_agent``
        currently holds instead of replacing it outright -- see
        ``ChainmailGovernor.register_delegation``'s docstring. Refused
        (not merged) if it would collide with a permission ``to_agent``
        already holds."""
        return self._call({
            "op": "register_delegation",
            "from_agent": from_agent, "to_agent": to_agent, "reason": reason,
            "offered": authority_to_dict(offered), "merge": merge,
        })

    def revoke_delegation(self, to_agent: str) -> bool:
        return bool(self._call({"op": "revoke_delegation", "to_agent": to_agent}).get("revoked"))

    def snapshot(self) -> Dict[str, Any]:
        return self._call({"op": "snapshot"})

    def suggest_envelope(self) -> Dict[str, Any]:
        return self._call({"op": "suggest_envelope"})
