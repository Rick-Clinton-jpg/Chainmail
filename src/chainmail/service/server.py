"""
Chainmail v5 service --- Unix-domain-socket governor server.

One ``ChainmailGovernor`` instance, one listening Unix socket, one thread per
connection. The governor already serialises ``evaluate`` / ``register_delegation``
internally, so concurrent clients are safe.

Auth: if ``auth_token`` is set, the first frame on every connection must be
``{"op": "auth", "token": "<token>"}`` with a matching token (compared in
constant time). Without a token the server refuses to start unless
``allow_no_auth=True`` is passed explicitly.

The socket file is created with mode 0600. This is a localhost trust boundary,
not a public endpoint.
"""

from __future__ import annotations

import argparse
import hmac
import logging
import os
import socket
import threading
from typing import Optional

from ..builders import build_demo_envelope
from ..config import GovernorConfig
from ..governor import ChainmailGovernor
from ..persistence import AuditSink, HashChainLog, SQLiteStore
from .protocol import (
    ProtocolError, authority_from_dict, proposal_from_dict, read_frame, result_to_dict,
    write_frame,
)

logger = logging.getLogger(__name__)


class UnixSocketGovernorServer:
    def __init__(self, governor: ChainmailGovernor, socket_path: str, *,
                 auth_token: Optional[str] = None,
                 auth_tokens: Optional[dict] = None,
                 allow_no_auth: bool = False,
                 backlog: int = 64) -> None:
        # ``auth_tokens`` maps token -> caller label, so callers can be issued
        # and revoked independently and the connecting identity is recorded.
        # ``auth_token`` is the single-token shorthand (label "default").
        tokens: dict = dict(auth_tokens or {})
        if auth_token:
            tokens.setdefault(auth_token, "default")
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
            t = threading.Thread(target=self._serve_conn, args=(conn,),
                                 name="chainmail-conn", daemon=True)
            t.start()
            self._conn_threads.append(t)

    def _authenticate(self, conn: socket.socket) -> Optional[str]:
        """Returns the caller label on success, None on failure. When no tokens
        are configured every connection is accepted as ``"anonymous"``."""
        if not self._tokens:
            return "anonymous"
        try:
            frame = read_frame(conn)
        except (ProtocolError, ConnectionError, OSError):
            return None
        if frame.get("op") != "auth":
            write_frame(conn, {"id": frame.get("id"), "ok": False, "error": "auth required"})
            return None
        supplied = str(frame.get("token", ""))
        label = None
        for token, caller in self._tokens.items():
            if hmac.compare_digest(supplied, token):
                label = caller
                break
        write_frame(conn, {"id": frame.get("id"), "ok": label is not None,
                           "error": None if label else "bad token",
                           "result": {"caller": label} if label else None})
        return label

    def _serve_conn(self, conn: socket.socket) -> None:
        conn.settimeout(30)
        try:
            caller = self._authenticate(conn)
            if caller is None:
                return
            logger.info("chainmail connection authenticated as %r", caller)
            while not self._stop.is_set():
                try:
                    req = read_frame(conn)
                except (ConnectionError, OSError):
                    return
                except ProtocolError as exc:
                    write_frame(conn, {"id": None, "ok": False, "error": str(exc)})
                    continue
                resp = self._dispatch(req)
                write_frame(conn, resp)
        except Exception:  # noqa: BLE001
            logger.exception("connection handler crashed")
        finally:
            conn.close()

    def _dispatch(self, req: dict) -> dict:
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
                offered = authority_from_dict(req.get("offered", {}))
                ok, msg = self.governor.register_delegation(
                    req["from_agent"], req["to_agent"], req.get("reason", ""), offered,
                )
                return {"id": rid, "ok": True, "result": {"accepted": ok, "message": msg}}
            if op == "revoke_delegation":
                ok = self.governor.revoke_delegation(req["to_agent"])
                return {"id": rid, "ok": True, "result": {"revoked": ok}}
            if op == "snapshot":
                return {"id": rid, "ok": True, "result": self.governor.snapshot()}
            if op == "suggest_envelope":
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

def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Run a Chainmail v5 governor over a Unix socket.")
    parser.add_argument("--socket", required=True, help="Unix socket path to listen on")
    parser.add_argument("--token", help="single shared auth token (or set CHAINMAIL_TOKEN)")
    parser.add_argument("--tokens", help='JSON map of {"token": "caller-label"} '
                                         "for per-caller auth (or set CHAINMAIL_TOKENS)")
    parser.add_argument("--allow-no-auth", action="store_true",
                        help="start without authentication (loopback / testing only)")
    parser.add_argument("--sqlite", help="path to the SQLite audit DB (default: in-memory)")
    parser.add_argument("--hash-chain", help="path to the hash-chain JSONL audit log")
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
    audit = AuditSink(
        hash_chain=HashChainLog(args.hash_chain) if args.hash_chain else None,
        sqlite_store=SQLiteStore(args.sqlite) if args.sqlite else None,
    )
    governor = ChainmailGovernor(build_demo_envelope(), config=GovernorConfig(), audit=audit)

    server = UnixSocketGovernorServer(
        governor, args.socket, auth_token=token, auth_tokens=token_map,
        allow_no_auth=args.allow_no_auth,
    )
    server.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
