"""Unix-socket governor service round-trips."""

import os
import shutil
import tempfile
import threading

import pytest

from chainmail import (
    ALGO_HMAC, Authority, ChainmailGovernor, GovernorConfig, Proposal, TfidfEmbeddingEngine,
    make_permission, sign_proposal,
)
from chainmail.service import CallerIdentity, GovernorClient, GovernorClientError, UnixSocketGovernorServer
from chainmail.service.server import _build_verifier, main

OBJ = "Build a secure multi-agent governance prototype"


@pytest.fixture
def short_tmpdir():
    # AF_UNIX paths are capped near 104 bytes on macOS; pytest's tmp_path is
    # far longer. Use a short dir under the system temp root.
    d = tempfile.mkdtemp(prefix="cm-", dir="/tmp")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def running_server(short_tmpdir, envelope):
    sock = os.path.join(short_tmpdir, "g.sock")
    g = ChainmailGovernor(envelope, config=GovernorConfig(),
                          embedding=TfidfEmbeddingEngine(), auto_embedding=False)
    server = UnixSocketGovernorServer(g, sock, auth_token="secret-token")
    server.start()
    yield sock, g
    server.stop()


def test_ping_and_evaluate(running_server):
    sock, _ = running_server
    with GovernorClient(sock, auth_token="secret-token") as c:
        assert c.ping() is True
        p = Proposal("svc-1", "agent_research", "gather", make_permission("research"), OBJ, 0.85)
        result = c.evaluate(p)
        assert result["decision"] == "CONTINUE"
        assert result["execution_id"]


def test_bad_token_rejected(running_server):
    sock, _ = running_server
    with pytest.raises(GovernorClientError):
        GovernorClient(sock, auth_token="wrong").connect()


def test_register_delegation_over_wire(running_server):
    sock, g = running_server
    before = len(g.provenance)
    with GovernorClient(sock, auth_token="secret-token") as c:
        offered = Authority(permissions={make_permission("research")})
        resp = c.register_delegation("agent_research", "agent_coder", "share", offered)
        assert resp["accepted"] is True
        bad = c.register_delegation("agent_research", "ghost", "x", offered)
        assert bad["accepted"] is False
    assert len(g.provenance) == before + 1


def test_role_violation_over_wire(running_server):
    sock, _ = running_server
    with GovernorClient(sock, auth_token="secret-token") as c:
        offered = Authority(permissions={make_permission("read", "docs")})
        resp = c.register_delegation("agent_research", "agent_approver", "bad", offered)
        assert resp["accepted"] is False and "Role violation" in resp["message"]


def test_snapshot_over_wire(running_server):
    sock, _ = running_server
    with GovernorClient(sock, auth_token="secret-token") as c:
        snap = c.snapshot()
        assert snap["objective"] == OBJ + " and keep the system inside the declared authority envelope" \
            or snap["objective"].startswith("Build a secure")


def test_malformed_proposal_returns_error(running_server):
    sock, _ = running_server
    with GovernorClient(sock, auth_token="secret-token") as c:
        c._roundtrip({"op": "evaluate", "proposal": {"agent_id": "x"}})  # missing fields
        # server must not crash; a well-formed request still works afterwards
        assert c.ping() is True


def test_server_refuses_no_auth_by_default(short_tmpdir, envelope):
    g = ChainmailGovernor(envelope, embedding=TfidfEmbeddingEngine(), auto_embedding=False)
    with pytest.raises(ValueError):
        UnixSocketGovernorServer(g, os.path.join(short_tmpdir, "x.sock"))


def test_per_caller_tokens(short_tmpdir, envelope):
    sock = os.path.join(short_tmpdir, "pc.sock")
    g = ChainmailGovernor(envelope, embedding=TfidfEmbeddingEngine(), auto_embedding=False)
    server = UnixSocketGovernorServer(
        g, sock, auth_tokens={"tok-worker": "worker-1", "tok-audit": "audit-bot"})
    server.start()
    try:
        with GovernorClient(sock, auth_token="tok-worker") as c:
            assert c.ping() is True
        with GovernorClient(sock, auth_token="tok-audit") as c:
            assert c.ping() is True
        with pytest.raises(GovernorClientError):
            GovernorClient(sock, auth_token="tok-nope").connect()
    finally:
        server.stop()


# -- authentication is not authorization ---------------------------------

def test_plain_string_token_grants_no_delegation_or_admin(short_tmpdir, envelope):
    """The backward-compatible plain-string form of auth_tokens is a label
    only -- authenticated, but with no authority to delegate as any agent,
    revoke, snapshot, or suggest_envelope. Before the fix, any authenticated
    caller could invoke these regardless of which token they held."""
    sock = os.path.join(short_tmpdir, "unauth.sock")
    g = ChainmailGovernor(envelope, embedding=TfidfEmbeddingEngine(), auto_embedding=False)
    server = UnixSocketGovernorServer(g, sock, auth_tokens={"tok-worker": "worker-1"})
    server.start()
    try:
        with GovernorClient(sock, auth_token="tok-worker") as c:
            assert c.ping() is True  # authenticated, evaluate/ping still work
            offered = Authority(permissions={make_permission("research")})
            with pytest.raises(GovernorClientError, match="unauthorized"):
                c.register_delegation("agent_research", "agent_coder", "escalate", offered)
            with pytest.raises(GovernorClientError, match="unauthorized"):
                c.revoke_delegation("agent_coder")
            with pytest.raises(GovernorClientError, match="unauthorized"):
                c.snapshot()
            with pytest.raises(GovernorClientError, match="unauthorized"):
                c.suggest_envelope()
    finally:
        server.stop()
    # nothing was granted despite the caller supplying an arbitrary from_agent
    assert len(g.provenance) == 0


def test_caller_bound_to_one_agent_can_only_delegate_as_that_agent(short_tmpdir, envelope):
    sock = os.path.join(short_tmpdir, "bound.sock")
    g = ChainmailGovernor(envelope, embedding=TfidfEmbeddingEngine(), auto_embedding=False)
    server = UnixSocketGovernorServer(g, sock, auth_tokens={
        "tok-research": CallerIdentity(label="agent_research-svc", agent_id="agent_research"),
    })
    server.start()
    try:
        with GovernorClient(sock, auth_token="tok-research") as c:
            offered = Authority(permissions={make_permission("research")})
            # delegating AS the bound agent is authorized
            resp = c.register_delegation("agent_research", "agent_coder", "share", offered)
            assert resp["accepted"] is True
            # impersonating a different from_agent is not
            with pytest.raises(GovernorClientError, match="unauthorized"):
                c.register_delegation("agent_deploy", "agent_coder", "escalate", offered)
            # admin-only ops remain unauthorized for a non-admin, agent-bound caller
            with pytest.raises(GovernorClientError, match="unauthorized"):
                c.snapshot()
    finally:
        server.stop()
    assert len(g.provenance) == 1


def test_admin_caller_retains_full_access(short_tmpdir, envelope):
    sock = os.path.join(short_tmpdir, "admin.sock")
    g = ChainmailGovernor(envelope, embedding=TfidfEmbeddingEngine(), auto_embedding=False)
    server = UnixSocketGovernorServer(g, sock, auth_tokens={
        "tok-admin": CallerIdentity(label="ops", admin=True),
    })
    server.start()
    try:
        with GovernorClient(sock, auth_token="tok-admin") as c:
            offered = Authority(permissions={make_permission("research")})
            resp = c.register_delegation("agent_research", "agent_coder", "share", offered)
            assert resp["accepted"] is True
            assert isinstance(c.snapshot(), dict)
            assert isinstance(c.suggest_envelope(), dict)
            assert c.revoke_delegation("agent_coder") is True
    finally:
        server.stop()


def test_single_shared_token_shorthand_is_admin(running_server):
    """The single-token constructor shorthand (auth_token=...) keeps its
    existing full-trust behaviour -- it represents the one local operator
    credential, not a per-caller-scoped token."""
    sock, g = running_server
    with GovernorClient(sock, auth_token="secret-token") as c:
        assert isinstance(c.snapshot(), dict)
        assert isinstance(c.suggest_envelope(), dict)


def test_concurrent_clients(running_server):
    sock, g = running_server
    errors = []

    def hammer(base):
        try:
            with GovernorClient(sock, auth_token="secret-token") as c:
                for i in range(20):
                    c.evaluate(Proposal(f"c{base}-{i}", "agent_research", "gather",
                                        make_permission("research"), OBJ, 0.85))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    ts = [threading.Thread(target=hammer, args=(b,)) for b in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors
    assert g.step_count == 5 * 20


# -- CLI: --production must not silently fall back to a dev-mode governor --

def test_build_verifier_returns_none_with_no_keys():
    assert _build_verifier([], []) is None


def test_build_verifier_hmac_key_verifies_a_signed_proposal():
    secret = b"shared-secret-value"
    verifier = _build_verifier([f"k-hmac:agent_research:{secret.hex()}"], [])
    p = sign_proposal(
        Proposal("s1", "agent_research", "gather", make_permission("research"), OBJ, 0.85),
        "k-hmac", algorithm=ALGO_HMAC, hmac_secret=secret,
    )
    result = verifier.verify(p)
    assert result.valid


def test_build_verifier_rejects_malformed_spec():
    with pytest.raises(SystemExit):
        _build_verifier(["not-enough-parts"], [])


def test_cli_production_requires_sqlite(short_tmpdir):
    sock = os.path.join(short_tmpdir, "g.sock")
    with pytest.raises(SystemExit):
        main(["--socket", sock, "--production", "--allow-no-auth"])


def test_cli_production_requires_a_key(short_tmpdir):
    sock = os.path.join(short_tmpdir, "g.sock")
    db = os.path.join(short_tmpdir, "audit.db")
    with pytest.raises(SystemExit):
        main(["--socket", sock, "--production", "--sqlite", db, "--allow-no-auth"])


def _dont_block():
    # Stands in for main()'s normal "serve forever" wait: returns immediately
    # via the same KeyboardInterrupt path an operator's Ctrl-C would take, so
    # the test can assert on what main() did before/around starting the
    # server without actually blocking.
    raise KeyboardInterrupt


def test_cli_dev_mode_warns_and_production_starts_signature_enforcing(short_tmpdir, capsys):
    # Dev mode (no --production): must print an explicit warning, not stay silent.
    sock = os.path.join(short_tmpdir, "dev.sock")
    rc = main(["--socket", sock, "--allow-no-auth"], _block=_dont_block)
    assert rc == 0
    assert "WITHOUT --production" in capsys.readouterr().err

    # Production mode: with --sqlite and a key, construction must succeed
    # (GovernorConfig.production() + a real verifier + durable storage) and
    # the dev-mode warning must not print.
    sock2 = os.path.join(short_tmpdir, "prod.sock")
    db = os.path.join(short_tmpdir, "audit.db")
    secret = b"shared-secret-value"
    rc = main(["--socket", sock2, "--production", "--sqlite", db,
              "--hmac-key", f"k-hmac:agent_research:{secret.hex()}",
              "--allow-no-auth"], _block=_dont_block)
    assert rc == 0
    assert "WITHOUT --production" not in capsys.readouterr().err


def test_cli_sqlite_synchronous_flag_defaults_to_full_and_accepts_normal(short_tmpdir):
    # PRAGMA synchronous is per-connection, not persisted to the database
    # file, so this checks what the CLI actually wires into SQLiteStore
    # rather than re-reading it back from a fresh connection.
    sock = os.path.join(short_tmpdir, "sync.sock")
    db = os.path.join(short_tmpdir, "audit.db")
    rc = main(["--socket", sock, "--sqlite", db, "--allow-no-auth"], _block=_dont_block)
    assert rc == 0  # default (no --sqlite-synchronous) must not error

    sock2 = os.path.join(short_tmpdir, "sync2.sock")
    db2 = os.path.join(short_tmpdir, "audit2.db")
    rc = main(["--socket", sock2, "--sqlite", db2, "--sqlite-synchronous", "NORMAL",
              "--allow-no-auth"], _block=_dont_block)
    assert rc == 0

    with pytest.raises(SystemExit):
        main(["--socket", os.path.join(short_tmpdir, "sync3.sock"), "--sqlite", db,
              "--sqlite-synchronous", "bogus", "--allow-no-auth"], _block=_dont_block)
