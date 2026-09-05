"""Executable specification for the keyed-authentication and
rollback-detection layer described in docs/DURABILITY.md.

Row-level MAC verification for ``live_authority``/``live_authority_agents``
(step 1 of docs/DURABILITY.md's "Smallest correct next step") is now
implemented -- see ``SQLiteStore``'s ``key_provider`` seam, ``KeyProvider``/
``InMemoryKeyProvider``, ``RowIntegrityError``, and ``_verify_mac`` in
``src/chainmail/persistence.py``. The un-skipped tests below (tamper
detection, forged-mac rejection, the unauthenticated no-op path, mac staying
current across ``consume_permission_budget``/``replace_live_authority``, and
key rotation) exercise that implementation. What remains skipped is the
deleted-marker gap (a per-row MAC cannot prove a row *used to exist*) and the
entire rollback-checkpoint half, which needs new external infrastructure this
repository does not ship -- design only, not implemented. Un-skip the rest
one at a time as each piece lands; do not weaken an assertion to make it pass
without the guarantee it names actually existing.
"""

import hashlib
import hmac

import pytest

from chainmail.persistence import InMemoryKeyProvider, RowIntegrityError, SQLiteStore


def test_tampered_live_authority_row_is_rejected():
    """Directly editing a live_authority row's remaining/max_budget/
    permission_name/permission_scope with a raw sqlite3 connection (bypassing
    SQLiteStore's own write API entirely) must be detected on the next read
    that feeds an authorization decision (get_live_authority_rows) -- fail
    closed, not silently trusted."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    assert store.get_live_authority_rows(namespace="default", agent_id="agent_a")

    # Bypass SQLiteStore's write API entirely -- edit the row with a raw
    # sqlite3 statement on the same connection, as a direct-filesystem
    # attacker with a sqlite3 client would.
    store._conn.execute(
        "UPDATE live_authority SET remaining = 999 "
        "WHERE deployment_namespace = 'default' AND agent_id = 'agent_a'"
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.get_live_authority_rows(namespace="default", agent_id="agent_a")


def test_tampered_row_without_the_key_cannot_forge_a_valid_mac():
    """An attacker who can write to the SQLite file but does not hold the
    external MAC key cannot produce a row that passes verification, however
    they compute a replacement 'mac' column value from the row's own
    plaintext contents."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )

    # Attacker doesn't hold the key, so they forge a MAC from a guessed
    # (and wrong) key, or any deterministic function of the plaintext that
    # isn't a real HMAC keyed by the real secret -- either way it must not
    # verify.
    forged = hmac.new(b"guessed-wrong-key", b"whatever", hashlib.sha256).hexdigest()
    store._conn.execute(
        "UPDATE live_authority SET remaining = 999, mac = ? "
        "WHERE deployment_namespace = 'default' AND agent_id = 'agent_a'",
        (forged,),
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.get_live_authority_rows(namespace="default", agent_id="agent_a")


def test_unauthenticated_store_is_unaffected_by_row_verification():
    """A SQLiteStore constructed without a key_provider (the default) must
    keep behaving exactly as schema v5 did -- no verification, no
    RowIntegrityError, mac/key_id columns simply stay NULL. Authentication
    is opt-in."""
    store = SQLiteStore(":memory:")
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    store._conn.execute(
        "UPDATE live_authority SET remaining = 999 "
        "WHERE deployment_namespace = 'default' AND agent_id = 'agent_a'"
    )
    store._conn.commit()
    rows = store.get_live_authority_rows(namespace="default", agent_id="agent_a")
    assert rows[0]["remaining"] == 999


def test_consume_permission_budget_keeps_the_mac_current():
    """consume_permission_budget must refresh the row's mac to match its
    new `remaining` in the same call -- otherwise a legitimate consume
    would itself make the row look tampered on the next read."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    assert store.consume_permission_budget(
        namespace="default", agent_id="agent_a", permission_name="read_docs",
        permission_scope="*", amount=3,
    )
    rows = store.get_live_authority_rows(namespace="default", agent_id="agent_a")
    assert rows[0]["remaining"] == 7


def test_replace_live_authority_keeps_the_mac_current():
    """replace_live_authority (delegation/revocation) must write a valid mac
    for every replacement row, not just initialize_agent_authority's initial
    seed."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    store.replace_live_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("write_docs", "*", 5)], source="delegation",
        envelope_fingerprint="fp2",
    )
    rows = store.get_live_authority_rows(namespace="default", agent_id="agent_a")
    assert rows == [{"permission_name": "write_docs", "permission_scope": "*",
                     "max_budget": 5, "remaining": 5}]


def test_key_rotation_does_not_invalidate_existing_rows():
    """Rotating the external MAC key (via key_provider) must not make
    previously-written, legitimately-unmodified rows fail verification --
    either a key-id is recorded per row (like replay claims already record
    key_id for signature verification) or rotation re-MACs existing rows in
    one pass; either way, a rotation must never look identical to tampering."""
    key_provider = InMemoryKeyProvider("k1", b"first-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )

    # Rotate: new writes sign under k2, but the row written under k1 above
    # is untouched by the rotation itself.
    key_provider.rotate("k2", b"second-key-material")

    # The pre-rotation row must still verify -- its recorded key_id (k1) is
    # still resolvable via key_provider.get, so rotation must never look
    # identical to tampering.
    rows = store.get_live_authority_rows(namespace="default", agent_id="agent_a")
    assert rows[0]["remaining"] == 10

    # A write made after rotation is signed under the new key.
    store.replace_live_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("write_docs", "*", 4)], source="delegation",
        envelope_fingerprint="fp2",
    )
    row = store._conn.execute(
        "SELECT key_id FROM live_authority WHERE agent_id = 'agent_a'"
    ).fetchone()
    assert row[0] == "k2"
    assert store.get_live_authority_rows(namespace="default", agent_id="agent_a")


_STILL_DESIGN_ONLY = pytest.mark.skip(
    reason="keyed authentication / rollback-checkpoint layer is design-only -- see docs/DURABILITY.md"
)


@_STILL_DESIGN_ONLY
def test_deleted_row_is_indistinguishable_from_never_having_existed_today_but_wont_be():
    """Today, deleting a live_authority row and re-initializing looks
    identical to a first-ever startup (both produce is_authority_initialized
    -> False for a fresh marker). The integrity layer's initialization
    marker itself must be authenticated too, so a deleted marker row cannot
    be used to re-seed authority at the envelope ceiling by making the store
    look never-initialized."""


@_STILL_DESIGN_ONLY
def test_rollback_to_an_earlier_valid_database_is_detected_with_a_checkpoint_configured():
    """Restoring an older (at-the-time correctly MAC'd) copy of the database
    file, when a host-provided monotonic checkpoint is configured, must be
    detected at SQLiteStore construction: the restored file's own recorded
    high-water mark is behind the external checkpoint's, and construction
    fails closed rather than silently accepting the older, valid-looking
    state."""


@_STILL_DESIGN_ONLY
def test_rollback_without_a_configured_checkpoint_is_honestly_unsupported():
    """Without an external checkpoint configured, SQLiteStore must not claim
    to detect rollback -- security_report() (or an equivalent) must say so
    explicitly, rather than implying the keyed-MAC layer alone (which cannot
    detect rollback -- see docs/DURABILITY.md) covers this case."""


@_STILL_DESIGN_ONLY
def test_checkpoint_advances_atomically_with_the_state_it_protects():
    """The external checkpoint must advance in the same logical step as the
    durable state it protects (e.g. within the same transaction, or with an
    explicit two-phase protocol that fails closed on a partial update) --
    never as a separate, unsynchronised write that could itself race and
    leave the checkpoint behind the state it's supposed to bound."""
