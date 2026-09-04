"""
Chainmail v5 service --- Unix-domain-socket governor server.

One ``ChainmailGovernor`` instance, one listening Unix socket, one thread per
connection. The governor already serialises ``evaluate`` / ``register_delegation``
internally, so concurrent clients are safe.

Auth: if ``auth_token`` is set, the first frame on every connection must be
``{"op": "auth", "token": "<token>"}`` with a matching token (compared in
constant time). Without a token the server refuses to start unless
``allow_no_auth=True`` is passed explicitly.

Authentication is not authorization: a valid token identifies the caller
(see ``CallerIdentity``), but by itself grants nothing beyond ``ping`` and
``evaluate``. ``register_delegation`` additionally requires the caller be
bound to the ``from_agent`` it's delegating as (or be an admin credential);
``revoke_delegation``, ``snapshot``, and ``suggest_envelope`` require an
admin credential -- these are fleet-wide administrative operations, not
something any authenticated caller should be able to invoke for an
arbitrary agent just by supplying that agent's id in the request body.

The socket file is created with mode 0600. This is a localhost trust boundary,
not a public endpoint.
"""

from __future__ import annotations

import argparse
import hmac
import logging
import os
import socket
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Union

import dataclasses

from ..builders import build_demo_envelope
from ..config import GovernorConfig
from ..core import RestrictPolicy
from ..crypto import ALGO_ED25519, ALGO_HMAC, CompositeVerifier, KeyRegistry
from ..execution_boundary import DenyAllExecutionBoundary
from ..governor import ChainmailGovernor
from ..persistence import AuditSink, HashChainLog, SQLiteStore
from .protocol import (
    ProtocolError, authority_from_dict, proposal_from_dict, read_frame, result_to_dict,
    write_frame,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CallerIdentity:
    """What one authenticated credential is authorized to do.

    ``label`` is a human-readable name for logging/audit only -- it grants
    nothing by itself. ``agent_id``, when set, is the one agent this
    credential may act as for ``register_delegation``'s ``from_agent``.
    ``admin`` grants the fleet-wide operations (``revoke_delegation``,
    ``snapshot``, ``suggest_envelope``) and bypasses the ``agent_id`` check
    for delegation.
    """
    label: str
    agent_id: Optional[str] = None
    admin: bool = False


def _normalize_tokens(
    auth_tokens: Optional[Dict[str, Union[str, "CallerIdentity"]]],
) -> Dict[str, "CallerIdentity"]:
    normalized: Dict[str, CallerIdentity] = {}
    for token, value in (auth_tokens or {}).items():
        if isinstance(value, CallerIdentity):
            normalized[token] = value
        else:
            # Backward-compatible shorthand: a plain string is a label only
            # -- authenticated, but with no delegation or admin authority.
            # Callers that need those must be granted them explicitly.
            normalized[token] = CallerIdentity(label=str(value))
    return normalized


class UnixSocketGovernorServer:
    def __init__(self, governor: ChainmailGovernor, socket_path: str, *,
                 auth_token: Optional[str] = None,
                 auth_tokens: Optional[Dict[str, Union[str, CallerIdentity]]] = None,
                 allow_no_auth: bool = False,
                 backlog: int = 64,
                 max_connections: int = 128) -> None:
        # ``auth_tokens`` maps token -> CallerIdentity (a plain string value
        # is shorthand for a label-only identity with no delegation/admin
        # authority), so callers can be issued and revoked independently,
        # scoped to exactly what they're authorized to do, and the
        # connecting identity is recorded. ``auth_token`` is the
        # single-token shorthand: full admin authority, matching its use as
        # "the one trusted local operator" credential.
        tokens = _normalize_tokens(auth_tokens)
        if auth_token:
            tokens.setdefault(auth_token, CallerIdentity(label="default", admin=True))
        if not tokens and not allow_no_auth:
            raise ValueError(
                "refusing to start without an auth token; pass allow_no_auth=True to override"
            )
        self.governor = governor
        self.socket_path = socket_path
        self._tokens = tokens
        self._backlog = backlog
        self._sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._conn_threads: "list[threading.Thread]" = []
        # One thread per connection, with no cap, let any client (buggy or
        # malicious) that can reach the socket exhaust server threads/file
        # descriptors just by opening connections and never closing them.
        # This semaphore bounds live connections; accept() keeps polling
        # (never blocks indefinitely) so _stop is still checked promptly
        # while at capacity.
        self._max_connections = max_connections
        self._conn_slots = threading.Semaphore(max_connections)

    # -- lifecycle ---------------------------------------------------
    def start(self) -> None:
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        sock.listen(self._backlog)
        sock.settimeout(0.5)
        self._sock = sock
        self._accept_thread = threading.Thread(target=self._accept_loop, name="chainmail-accept",
                                               daemon=True)
        self._accept_thread.start()
        logger.info("chainmail governor listening on %s", self.socket_path)

    def stop(self) -> None:
        self._stop.set()
        if self._accept_thread:
            self._accept_thread.join(timeout=3)
        if self._sock:
            self._sock.close()
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

    def __enter__(self) -> "UnixSocketGovernorServer":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- accept / serve --------------------------------------------
    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._conn_threads = [t for t in self._conn_threads if t.is_alive()]
            if not self._conn_slots.acquire(blocking=False):
                logger.warning(
                    "chainmail service at max_connections=%d; refusing a new connection",
                    self._max_connections,
                )
                try:
                    conn.close()
                finally:
                    continue
            t = threading.Thread(target=self._serve_conn, args=(conn,),
                                 name="chainmail-conn", daemon=True)
            t.start()
            self._conn_threads.append(t)

    def _authenticate(self, conn: socket.socket) -> Optional[CallerIdentity]:
        """Returns the caller's identity on success, None on failure. When no
        tokens are configured every connection is accepted as a full-trust
        anonymous admin -- that's the existing ``allow_no_auth`` contract
        (loopback/testing only), unchanged here."""
        if not self._tokens:
            return CallerIdentity(label="anonymous", admin=True)
        try:
            frame = read_frame(conn)
        except (ProtocolError, ConnectionError, OSError):
            return None
        if frame.get("op") != "auth":
            write_frame(conn, {"id": frame.get("id"), "ok": False, "error": "auth required"})
            return None
        supplied = str(frame.get("token", ""))
        identity = None
        for token, caller in self._tokens.items():
            if hmac.compare_digest(supplied, token):
                identity = caller
                break
        write_frame(conn, {"id": frame.get("id"), "ok": identity is not None,
                           "error": None if identity else "bad token",
                           "result": {"caller": identity.label} if identity else None})
        return identity

    def _serve_conn(self, conn: socket.socket) -> None:
        conn.settimeout(30)
        try:
            caller = self._authenticate(conn)
            if caller is None:
                return
            logger.info("chainmail connection authenticated as %r (agent_id=%r, admin=%s)",
                       caller.label, caller.agent_id, caller.admin)
            while not self._stop.is_set():
                try:
                    req = read_frame(conn)
                except (ConnectionError, OSError):
                    return
                except ProtocolError as exc:
                    write_frame(conn, {"id": None, "ok": False, "error": str(exc)})
                    continue
                resp = self._dispatch(req, caller)
                write_frame(conn, resp)
        except Exception:  # noqa: BLE001
            logger.exception("connection handler crashed")
        finally:
            conn.close()
            self._conn_slots.release()

    def _dispatch(self, req: dict, caller: CallerIdentity) -> dict:
        rid = req.get("id")
        op = req.get("op")
        try:
            if op == "ping":
                return {"id": rid, "ok": True, "result": {"pong": True}}
            if op == "auth":
                return {"id": rid, "ok": True, "result": {"already_authenticated": True}}
            if op == "evaluate":
                proposal = proposal_from_dict(req.get("proposal", {}))
                result = self.governor.evaluate(proposal)
                return {"id": rid, "ok": True, "result": result_to_dict(result)}
            if op == "register_delegation":
                from_agent = req.get("from_agent")
                if not caller.admin and caller.agent_id != from_agent:
                    return {"id": rid, "ok": False,
                           "error": f"unauthorized: caller {caller.label!r} may not delegate "
                                     f"as agent {from_agent!r}"}
                offered = authority_from_dict(req.get("offered", {}))
                ok, msg = self.governor.register_delegation(
                    req["from_agent"], req["to_agent"], req.get("reason", ""), offered,
                )
                return {"id": rid, "ok": True, "result": {"accepted": ok, "message": msg}}
            if op == "revoke_delegation":
                if not caller.admin:
                    return {"id": rid, "ok": False,
                           "error": f"unauthorized: {caller.label!r} requires admin authority "
                                     "for revoke_delegation"}
                ok = self.governor.revoke_delegation(req["to_agent"])
                return {"id": rid, "ok": True, "result": {"revoked": ok}}
            if op == "snapshot":
                if not caller.admin:
                    return {"id": rid, "ok": False,
                           "error": f"unauthorized: {caller.label!r} requires admin authority "
                                     "for snapshot"}
                return {"id": rid, "ok": True, "result": self.governor.snapshot()}
            if op == "suggest_envelope":
                if not caller.admin:
                    return {"id": rid, "ok": False,
                           "error": f"unauthorized: {caller.label!r} requires admin authority "
                                     "for suggest_envelope"}
                return {"id": rid, "ok": True, "result": self.governor.suggest_envelope()}
            return {"id": rid, "ok": False, "error": f"unknown op {op!r}"}
        except (ProtocolError, KeyError, TypeError, ValueError) as exc:
            return {"id": rid, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
        except Exception as exc:  # noqa: BLE001
            logger.exception("dispatch failed")
            return {"id": rid, "ok": False, "error": f"internal error: {type(exc).__name__}"}


# ----------------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------------

def _build_verifier(hmac_keys: list, ed25519_keys: list) -> Optional[CompositeVerifier]:
    """Build a CompositeVerifier from --hmac-key/--ed25519-pubkey CLI values, or
    None if none were supplied."""
    if not hmac_keys and not ed25519_keys:
        return None
    registry = KeyRegistry()
    for raw in hmac_keys:
        try:
            kid, agent_id, hex_secret = raw.split(":", 2)
        except ValueError:
            raise SystemExit(
                f"--hmac-key must be kid:agent_id:hex_secret, got {raw!r}")
        registry.add_key(kid, agent_id, ALGO_HMAC, bytes.fromhex(hex_secret))
    for raw in ed25519_keys:
        try:
            kid, agent_id, pem_path = raw.split(":", 2)
        except ValueError:
            raise SystemExit(
                f"--ed25519-pubkey must be kid:agent_id:path_to_pem, got {raw!r}")
        with open(pem_path, "rb") as fh:
            registry.add_key(kid, agent_id, ALGO_ED25519, fh.read())
    return CompositeVerifier(registry)


def main(argv: Optional[list] = None, *, _block: Optional[Callable[[], None]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Chainmail v5 governor over a Unix socket.")
    parser.add_argument("--socket", required=True, help="Unix socket path to listen on")
    parser.add_argument("--token", help="single shared auth token (or set CHAINMAIL_TOKEN)")
    parser.add_argument("--tokens", help='JSON map of {"token": "caller-label"} '
                                         "for per-caller auth (or set CHAINMAIL_TOKENS)")
    parser.add_argument("--allow-no-auth", action="store_true",
                        help="start without authentication (loopback / testing only)")
    parser.add_argument("--sqlite", help="path to the SQLite audit DB (default: in-memory)")
    parser.add_argument("--sqlite-synchronous", default="FULL", choices=["FULL", "NORMAL", "OFF"],
                        help="SQLite synchronous PRAGMA (default: FULL, the durable choice; "
                             "NORMAL trades a small crash-durability window for throughput)")
    parser.add_argument("--hash-chain", help="path to the hash-chain JSONL audit log")
    parser.add_argument("--production", action="store_true",
                        help="use GovernorConfig.production() -- requires --sqlite and at "
                             "least one --hmac-key/--ed25519-pubkey; refuses unsigned "
                             "proposals and in-memory-only replay protection")
    parser.add_argument("--hmac-key", action="append", default=[],
                        help="kid:agent_id:hex_secret -- repeatable, registers an HMAC "
                             "verification key")
    parser.add_argument("--ed25519-pubkey", action="append", default=[],
                        help="kid:agent_id:path_to_pem -- repeatable, registers an Ed25519 "
                             "public-key verification key")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))

    token = args.token or os.environ.get("CHAINMAIL_TOKEN")
    tokens_raw = args.tokens or os.environ.get("CHAINMAIL_TOKENS")
    token_map = None
    if tokens_raw:
        import json as _json
        token_map = _json.loads(tokens_raw)
        if not isinstance(token_map, dict) or not all(isinstance(v, str) for v in token_map.values()):
            parser.error("--tokens / CHAINMAIL_TOKENS must be a JSON object of {token: label}")

    verifier = _build_verifier(args.hmac_key, args.ed25519_pubkey)

    if args.production:
        if not args.sqlite:
            parser.error("--production requires --sqlite (durable replay/restriction storage)")
        if verifier is None:
            parser.error("--production requires at least one --hmac-key or --ed25519-pubkey")
        config = GovernorConfig.production()
    else:
        config = GovernorConfig()
        print(
            "chainmail service: starting WITHOUT --production -- this is a development "
            "configuration: proposal signatures are not enforced (any caller can act as "
            "any agent) and it uses the built-in demo authority envelope, not a "
            "deployment-specific one. Pass --production with --sqlite and a signing key "
            "for a real deployment.",
            file=sys.stderr,
        )

    audit = AuditSink(
        hash_chain=HashChainLog(args.hash_chain) if args.hash_chain else None,
        sqlite_store=(SQLiteStore(args.sqlite, synchronous=args.sqlite_synchronous)
                     if args.sqlite else None),
    )
    envelope = build_demo_envelope()
    if args.production and envelope.restrict_policy == RestrictPolicy.TTL_STEPS:
        # The demo envelope's default TTL_STEPS restriction policy is
        # rejected by production_mode (step-based expiry isn't durable or
        # multi-process-safe) -- see ChainmailGovernor.__init__. Fall back to
        # TTL_WALLCLOCK so --production is usable without a custom envelope;
        # a real deployment should still supply its own AuthorityEnvelope.
        envelope = dataclasses.replace(envelope, restrict_policy=RestrictPolicy.TTL_WALLCLOCK)
    # production_mode requires a non-permissive execution boundary, and this
    # CLI has no flag for wiring in a real one (a genuine execution handler
    # is a Python callable, not something expressible as a command-line
    # argument) -- default to DenyAllExecutionBoundary so --production is
    # usable standalone. A real deployment that needs to actually execute
    # anything should use ChainmailGovernor directly with a real
    # execution_boundary=, not this CLI.
    execution_boundary = DenyAllExecutionBoundary() if args.production else None
    governor = ChainmailGovernor(envelope, config=config, audit=audit, verifier=verifier,
                                 execution_boundary=execution_boundary)

    server = UnixSocketGovernorServer(
        governor, args.socket, auth_token=token, auth_tokens=token_map,
        allow_no_auth=args.allow_no_auth,
    )
    server.start()
    try:
        (_block or (lambda: threading.Event().wait()))()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
