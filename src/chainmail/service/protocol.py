"""
Chainmail v5 service --- wire protocol.

Framing: a 4-byte big-endian unsigned length prefix followed by that many bytes
of UTF-8 JSON. One JSON object per frame. Max frame size is capped to bound
memory from a hostile or broken peer.

Request  : {"op": "<name>", "id": <int>, ...op-specific fields...}
Response : {"id": <int>, "ok": true, "result": {...}}
           {"id": <int>, "ok": false, "error": "<message>"}

Ops: "auth", "ping", "evaluate", "register_delegation", "revoke_delegation",
     "snapshot", "suggest_envelope".
"""

from __future__ import annotations

import json
import socket
import struct
from typing import Any, Dict

from ..core import Authority, GovernanceResult, Permission, Proposal, StructuredAssumption

MAX_FRAME_BYTES = 4 * 1024 * 1024
_HEADER = struct.Struct(">I")


class ProtocolError(Exception):
    pass


# ----------------------------------------------------------------------
# framing
# ----------------------------------------------------------------------

def write_frame(sock: socket.socket, obj: Dict[str, Any]) -> None:
    body = json.dumps(obj, separators=(",", ":"), default=str).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise ProtocolError(f"frame too large to send ({len(body)} bytes)")
    sock.sendall(_HEADER.pack(len(body)) + body)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("peer closed the connection mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(sock: socket.socket) -> Dict[str, Any]:
    header = _recv_exact(sock, _HEADER.size)
    (length,) = _HEADER.unpack(header)
    if length > MAX_FRAME_BYTES:
        raise ProtocolError(f"frame too large ({length} bytes)")
    body = _recv_exact(sock, length)
    try:
        obj = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"invalid JSON frame: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("frame must be a JSON object")
    return obj


# ----------------------------------------------------------------------
# (de)serialisation of domain objects
# ----------------------------------------------------------------------

def permission_to_dict(p: Permission) -> Dict[str, Any]:
    return {"name": p.name, "scope": p.scope, "max_budget": p.max_budget}


def permission_from_dict(d: Dict[str, Any]) -> Permission:
    if not isinstance(d, dict):
        raise ProtocolError("permission must be an object")
    try:
        return Permission(
            name=d["name"],
            scope=d.get("scope", "*"),
            max_budget=d.get("max_budget"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError(f"bad permission: {exc}") from exc


def authority_to_dict(a: Authority) -> Dict[str, Any]:
    return {
        "permissions": [permission_to_dict(p) for p in a.permissions],
        "budget_remaining": dict(a.budget_remaining),
    }


def authority_from_dict(d: Dict[str, Any]) -> Authority:
    if not isinstance(d, dict):
        raise ProtocolError("authority must be an object")
    perms = {permission_from_dict(p) for p in d.get("permissions", [])}
    budgets = dict(d.get("budget_remaining", {}))
    return Authority(permissions=perms, budget_remaining=budgets)


def proposal_from_dict(d: Dict[str, Any]) -> Proposal:
    if not isinstance(d, dict):
        raise ProtocolError("proposal must be an object")
    try:
        assumptions = [
            StructuredAssumption(
                text=a["text"], source_agent=a["source_agent"],
                timestamp=a.get("timestamp", 0.0), confidence=a.get("confidence", 0.5),
            )
            for a in d.get("assumptions", [])
        ]
        return Proposal(
            proposal_id=d["proposal_id"],
            agent_id=d["agent_id"],
            action=d["action"],
            required_permission=permission_from_dict(d["required_permission"]),
            objective_fragment=d["objective_fragment"],
            confidence=d.get("confidence", 0.8),
            assumptions=assumptions,
            parent_proposal_id=d.get("parent_proposal_id"),
            signature=d.get("signature"),
            nonce=d.get("nonce"),
            payload=d.get("payload", {}) or {},
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProtocolError(f"bad proposal: {exc}") from exc


def proposal_to_dict(p: Proposal) -> Dict[str, Any]:
    return {
        "proposal_id": p.proposal_id,
        "agent_id": p.agent_id,
        "action": p.action,
        "required_permission": permission_to_dict(p.required_permission),
        "objective_fragment": p.objective_fragment,
        "confidence": p.confidence,
        "assumptions": [
            {"text": a.text, "source_agent": a.source_agent,
             "timestamp": a.timestamp, "confidence": a.confidence}
            for a in p.assumptions
        ],
        "parent_proposal_id": p.parent_proposal_id,
        "signature": p.signature,
        "nonce": p.nonce,
        "payload": p.payload,
    }


def result_to_dict(r: GovernanceResult) -> Dict[str, Any]:
    return r.to_dict()
