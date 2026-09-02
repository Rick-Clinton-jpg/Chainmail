"""Unix-socket governor service round-trips."""

import os
import shutil
import tempfile
import threading

import pytest

from chainmail import (
    Authority, ChainmailGovernor, GovernorConfig, Proposal, TfidfEmbeddingEngine, make_permission,
)
from chainmail.service import GovernorClient, GovernorClientError, UnixSocketGovernorServer

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
