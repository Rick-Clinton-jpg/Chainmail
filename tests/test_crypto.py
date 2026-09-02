"""Signature verification + key management."""

import time

import pytest

from chainmail import (
    ALGO_ED25519, ALGO_HMAC, CompositeVerifier, Decision, GovernorConfig, KeyRegistry,
    Permission, Proposal, RiskSignal, canonical_signing_bytes, generate_ed25519_keypair,
    make_permission, sign_proposal,
)

OBJ = "Build a secure multi-agent governance prototype"


def _prop(pid="s1", agent="agent_research", action="gather", perm=None, **kw):
    return Proposal(pid, agent, action, perm or make_permission("research"), OBJ, 0.85, **kw)


# -- HMAC ----------------------------------------------------------

def test_hmac_signed_proposal_continues(make_governor):
    reg = KeyRegistry()
    secret = b"shared-secret-value"
    reg.add_key("k-hmac", "agent_research", ALGO_HMAC, secret)
    g = make_governor(verifier=CompositeVerifier(reg))
    p = sign_proposal(_prop(), "k-hmac", algorithm=ALGO_HMAC, hmac_secret=secret)
    assert g.evaluate(p).decision == Decision.CONTINUE


def test_hmac_tampered_signature_escalates(make_governor):
    reg = KeyRegistry()
    reg.add_key("k-hmac", "agent_research", ALGO_HMAC, b"shared-secret-value")
    g = make_governor(verifier=CompositeVerifier(reg))
    p = _prop(signature="k-hmac:deadbeef", nonce="n-1")
    r = g.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SIGNATURE_INVALID in r.signals


# -- signature binds the whole proposal -----------------------------

def test_signature_binds_permission_and_payload(make_governor):
    reg = KeyRegistry()
    secret = b"shared-secret-value"
    reg.add_key("k-hmac", "agent_coder", ALGO_HMAC, secret)
    g = make_governor(verifier=CompositeVerifier(reg))

    honest = Proposal("bind-1", "agent_coder", "write_code", make_permission("code", "write"),
                      OBJ, 0.85, payload={"file": "repo/a.py"})
    sign_proposal(honest, "k-hmac", algorithm=ALGO_HMAC, hmac_secret=secret)
    assert g.evaluate(honest).decision == Decision.CONTINUE

    # Attacker keeps the signature+nonce but swaps in a stronger permission.
    forged = Proposal("bind-2", "agent_coder", "write_code",
                      make_permission("deploy", "staging"), OBJ, 0.85,
                      payload={"file": "repo/a.py"},
                      signature=honest.signature, nonce=honest.nonce)
    r = g.evaluate(forged)
    assert r.decision == Decision.HUMAN and RiskSignal.SIGNATURE_INVALID in r.signals


# -- Ed25519 -----------------------------------------------------

def test_ed25519_roundtrip(make_governor):
    priv, pub = generate_ed25519_keypair()
    reg = KeyRegistry()
    reg.add_key("k-ed", "agent_research", ALGO_ED25519, pub)
    g = make_governor(verifier=CompositeVerifier(reg))
    p = sign_proposal(_prop("ed-1"), "k-ed", algorithm=ALGO_ED25519, ed25519_private_pem=priv)
    assert g.evaluate(p).decision == Decision.CONTINUE


def test_ed25519_wrong_key_rejected(make_governor):
    priv_a, _ = generate_ed25519_keypair()
    _, pub_b = generate_ed25519_keypair()
    reg = KeyRegistry()
    reg.add_key("k-ed", "agent_research", ALGO_ED25519, pub_b)
    g = make_governor(verifier=CompositeVerifier(reg))
    p = sign_proposal(_prop("ed-2"), "k-ed", algorithm=ALGO_ED25519, ed25519_private_pem=priv_a)
    r = g.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SIGNATURE_INVALID in r.signals


# -- key lifecycle ----------------------------------------------

def test_revoked_key_rejected(make_governor):
    reg = KeyRegistry()
    secret = b"shared-secret-value"
    reg.add_key("k-hmac", "agent_research", ALGO_HMAC, secret)
    g = make_governor(verifier=CompositeVerifier(reg))
    reg.revoke("k-hmac")
    p = sign_proposal(_prop("rv-1"), "k-hmac", algorithm=ALGO_HMAC, hmac_secret=secret)
    r = g.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SIGNATURE_INVALID in r.signals


def test_expired_key_rejected(make_governor):
    reg = KeyRegistry()
    secret = b"shared-secret-value"
    reg.add_key("k-hmac", "agent_research", ALGO_HMAC, secret, not_after=time.time() - 1)
    g = make_governor(verifier=CompositeVerifier(reg))
    p = sign_proposal(_prop("ex-1"), "k-hmac", algorithm=ALGO_HMAC, hmac_secret=secret)
    r = g.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SIGNATURE_INVALID in r.signals


def test_key_bound_to_agent(make_governor):
    reg = KeyRegistry()
    secret = b"shared-secret-value"
    reg.add_key("k-hmac", "agent_coder", ALGO_HMAC, secret)  # bound to coder
    g = make_governor(verifier=CompositeVerifier(reg))
    # research agent signs with coder's key id
    p = sign_proposal(_prop("ba-1", agent="agent_research"), "k-hmac",
                      algorithm=ALGO_HMAC, hmac_secret=secret)
    r = g.evaluate(p)
    assert r.decision == Decision.HUMAN and RiskSignal.SIGNATURE_INVALID in r.signals


def test_rotate_key(make_governor):
    reg = KeyRegistry()
    old, new = b"old-secret-value!!", b"new-secret-value!!"
    reg.add_key("k-old", "agent_research", ALGO_HMAC, old)
    reg.rotate("k-old", "k-new", new)
    g = make_governor(verifier=CompositeVerifier(reg))
    stale = sign_proposal(_prop("rot-1"), "k-old", algorithm=ALGO_HMAC, hmac_secret=old)
    assert g.evaluate(stale).decision == Decision.HUMAN
    fresh = sign_proposal(_prop("rot-2"), "k-new", algorithm=ALGO_HMAC, hmac_secret=new)
    assert g.evaluate(fresh).decision == Decision.CONTINUE


# -- config: require_signature --------------------------------------

def test_require_signature(make_governor):
    g = make_governor(config=GovernorConfig(require_signature=True))
    r = g.evaluate(_prop("req-1"))
    assert r.decision == Decision.HUMAN and RiskSignal.SIGNATURE_MISSING in r.signals


def test_canonical_bytes_are_stable():
    p1 = Proposal("c1", "a", "act", make_permission("x"), "frag", 0.5,
                  payload={"b": 2, "a": 1}, nonce="n")
    p2 = Proposal("c1", "a", "act", make_permission("x"), "frag", 0.5,
                  payload={"a": 1, "b": 2}, nonce="n")
    assert canonical_signing_bytes(p1) == canonical_signing_bytes(p2)
