"""
Chainmail v5 --- proposal authentication and key management.

A proposal signature must bind *every* field an attacker could usefully tamper
with -- not just ``action`` as in v4. The canonical signing payload is a sorted,
separator-normalised JSON encoding of ``Proposal.signing_dict()``.

Key material is held in a ``KeyRegistry``:

* multiple keys per agent, addressed by ``kid``;
* per-key ``not_before`` / ``not_after`` validity window;
* explicit revocation;
* algorithm tag (``ed25519`` preferred, ``hmac`` supported).

``CompositeVerifier`` is the one the governor uses -- it dispatches to Ed25519 or
HMAC by the registered key's algorithm.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol, Tuple

from .core import Proposal

logger = logging.getLogger(__name__)

ALGO_ED25519 = "ed25519"
ALGO_HMAC = "hmac"


# ============================================================================
# Canonical signing payload
# ============================================================================

def canonical_signing_bytes(proposal: Proposal) -> bytes:
    return json.dumps(
        proposal.signing_dict(), sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


# ============================================================================
# Key registry
# ============================================================================

class KeyExpired(Exception):
    pass


class KeyRevoked(Exception):
    pass


@dataclass
class KeyRecord:
    kid: str
    agent_id: str
    algorithm: str          # ALGO_ED25519 | ALGO_HMAC
    material: bytes          # ed25519: PEM public key bytes; hmac: shared secret
    not_before: float = 0.0
    not_after: Optional[float] = None
    revoked: bool = False

    def active_at(self, when: float) -> bool:
        if self.revoked:
            return False
        if when < self.not_before:
            return False
        if self.not_after is not None and when > self.not_after:
            return False
        return True


class KeyRegistry:
    """Thread-safe store of signing keys, addressed by ``kid``."""

    def __init__(self) -> None:
        self._by_kid: Dict[str, KeyRecord] = {}
        self._lock = threading.RLock()

    def add_key(self, kid: str, agent_id: str, algorithm: str, material: bytes, *,
                not_before: float = 0.0, not_after: Optional[float] = None) -> KeyRecord:
        if not kid or not isinstance(kid, str):
            raise ValueError("kid must be a non-empty string")
        if not agent_id or not isinstance(agent_id, str):
            raise ValueError("agent_id must be a non-empty string")
        if algorithm not in (ALGO_ED25519, ALGO_HMAC):
            raise ValueError(f"unsupported algorithm {algorithm!r}")
        if not isinstance(material, (bytes, bytearray)) or not material:
            raise ValueError("key material must be non-empty bytes")
        rec = KeyRecord(kid, agent_id, algorithm, bytes(material),
                        not_before=not_before, not_after=not_after)
        with self._lock:
            if kid in self._by_kid:
                raise ValueError(f"kid {kid!r} already registered")
            self._by_kid[kid] = rec
        return rec

    def revoke(self, kid: str) -> bool:
        with self._lock:
            rec = self._by_kid.get(kid)
            if rec is None:
                return False
            rec.revoked = True
            logger.info("key %s for agent %s revoked", kid, rec.agent_id)
            return True

    def rotate(self, old_kid: str, new_kid: str, material: bytes, *,
               algorithm: Optional[str] = None, not_after: Optional[float] = None) -> KeyRecord:
        """Register ``new_kid`` for the same agent and revoke ``old_kid``."""
        with self._lock:
            old = self._by_kid.get(old_kid)
            if old is None:
                raise KeyError(old_kid)
            rec = self.add_key(new_kid, old.agent_id, algorithm or old.algorithm, material,
                               not_after=not_after)
            old.revoked = True
            logger.info("rotated key %s -> %s for agent %s", old_kid, new_kid, old.agent_id)
            return rec

    def get(self, kid: str) -> Optional[KeyRecord]:
        with self._lock:
            return self._by_kid.get(kid)

    def resolve(self, kid: str, agent_id: str, when: Optional[float] = None) -> KeyRecord:
        when = time.time() if when is None else when
        rec = self.get(kid)
        if rec is None:
            raise KeyError(f"unknown kid {kid!r}")
        if rec.agent_id != agent_id:
            raise KeyRevoked(f"kid {kid!r} is not bound to agent {agent_id!r}")
        if rec.revoked:
            raise KeyRevoked(f"kid {kid!r} is revoked")
        if not rec.active_at(when):
            raise KeyExpired(f"kid {kid!r} is outside its validity window")
        return rec

    def keys_for(self, agent_id: str) -> List[KeyRecord]:
        with self._lock:
            return [r for r in self._by_kid.values() if r.agent_id == agent_id]


# ============================================================================
# Verifier protocol + implementations
# ============================================================================

@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.valid


class ApprovalVerifier(Protocol):
    def verify(self, proposal: Proposal) -> VerificationResult: ...


def _split_signature(signature: Optional[str]) -> Optional[Tuple[str, str]]:
    if not signature or not isinstance(signature, str) or ":" not in signature:
        return None
    kid, sig = signature.split(":", 1)
    if not kid or not sig:
        return None
    return kid, sig


class CompositeVerifier:
    """Registry-backed verifier. Dispatches by the resolved key's algorithm."""

    def __init__(self, registry: KeyRegistry) -> None:
        self._registry = registry
        self._crypto = _load_crypto()

    def verify(self, proposal: Proposal) -> VerificationResult:
        parts = _split_signature(proposal.signature)
        if parts is None:
            return VerificationResult(False, "malformed or missing signature")
        if not proposal.nonce:
            return VerificationResult(False, "missing nonce")
        kid, sig_hex = parts
        try:
            rec = self._registry.resolve(kid, proposal.agent_id)
        except (KeyError, KeyRevoked, KeyExpired) as exc:
            return VerificationResult(False, str(exc))

        payload = canonical_signing_bytes(proposal)
        if rec.algorithm == ALGO_HMAC:
            expected = hmac.new(rec.material, payload, hashlib.sha256).hexdigest()
            if hmac.compare_digest(sig_hex, expected):
                return VerificationResult(True, "hmac ok")
            return VerificationResult(False, "hmac mismatch")

        if rec.algorithm == ALGO_ED25519:
            if self._crypto is None:
                return VerificationResult(False, "cryptography package not installed")
            try:
                pub = self._crypto["load_pem_public_key"](rec.material)
                pub.verify(bytes.fromhex(sig_hex), payload)
                return VerificationResult(True, "ed25519 ok")
            except Exception as exc:  # noqa: BLE001
                return VerificationResult(False, f"ed25519 verify failed: {type(exc).__name__}")

        return VerificationResult(False, f"unsupported algorithm {rec.algorithm!r}")


class NullApprovalVerifier:
    """Accepts everything. Development only -- logs a warning on construction."""

    def __init__(self) -> None:
        logger.warning("NullApprovalVerifier in use: proposal signatures are NOT checked")

    def verify(self, proposal: Proposal) -> VerificationResult:
        return VerificationResult(True, "null verifier")


# ============================================================================
# Signing helpers (agent / harness / test side)
# ============================================================================

def _load_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization

        return {
            "Ed25519PrivateKey": Ed25519PrivateKey,
            "Ed25519PublicKey": Ed25519PublicKey,
            "serialization": serialization,
            "load_pem_public_key": serialization.load_pem_public_key,
        }
    except Exception:  # noqa: BLE001
        return None


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Return ``(private_pem, public_pem)``. Raises if ``cryptography`` is absent."""
    crypto = _load_crypto()
    if crypto is None:
        raise RuntimeError("cryptography package is required for Ed25519 key generation")
    priv = crypto["Ed25519PrivateKey"].generate()
    serialization = crypto["serialization"]
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_proposal(proposal: Proposal, kid: str, *, algorithm: str,
                  hmac_secret: Optional[bytes] = None,
                  ed25519_private_pem: Optional[bytes] = None,
                  nonce: Optional[str] = None) -> Proposal:
    """Attach ``signature`` and ``nonce`` to ``proposal`` in place, then return it.

    The signature binds the full canonical payload (see ``signing_dict``).
    """
    proposal.nonce = nonce or secrets.token_hex(16)
    payload = canonical_signing_bytes(proposal)

    if algorithm == ALGO_HMAC:
        if not hmac_secret:
            raise ValueError("hmac_secret is required for HMAC signing")
        sig = hmac.new(hmac_secret, payload, hashlib.sha256).hexdigest()
    elif algorithm == ALGO_ED25519:
        crypto = _load_crypto()
        if crypto is None:
            raise RuntimeError("cryptography package is required for Ed25519 signing")
        if not ed25519_private_pem:
            raise ValueError("ed25519_private_pem is required for Ed25519 signing")
        priv = crypto["serialization"].load_pem_private_key(ed25519_private_pem, password=None)
        sig = priv.sign(payload).hex()
    else:
        raise ValueError(f"unsupported algorithm {algorithm!r}")

    proposal.signature = f"{kid}:{sig}"
    return proposal
