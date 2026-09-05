"""Executable specification for the keyed-authentication and
rollback-detection layer described in docs/DURABILITY.md.

Everything this file originally set out to pin down is now implemented:
row-level MAC verification (schema v6-v7), the deleted-marker/status-flip
ledger fixes (schema v8-v9), and the rollback checkpoint (schema v10) -- see
``SQLiteStore``'s ``key_provider``/``rollback_checkpoint`` seams,
``KeyProvider``/``InMemoryKeyProvider``, ``RollbackCheckpoint``/
``InMemoryRollbackCheckpoint``, ``RowIntegrityError``/
``RollbackDetectedError``, and their supporting methods in
``src/chainmail/persistence.py``. Nothing in this file is skipped any more.
Do not weaken an assertion to make it pass without the guarantee it names
actually existing.
"""

import hashlib
import hmac
import tempfile

import pytest

from chainmail.persistence import (
    InMemoryKeyProvider, InMemoryRollbackCheckpoint, RollbackDetectedError,
    RowIntegrityError, SQLiteStore,
)


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


# -- restrictions, replay tables, step_counters (schema v7) -----------------

def test_tampered_restriction_row_is_rejected():
    """Directly editing an ACTIVE restriction's permission_scope/
    permission_max_budget/expiry with a raw sqlite3 connection must be
    detected on the next active_restrictions() read -- fail closed."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    restriction_id = store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    assert store.active_restrictions(namespace="default", agent_id="agent_a")

    store._conn.execute(
        "UPDATE restrictions SET permission_scope = 'staging' WHERE restriction_id = ?",
        (restriction_id,),
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.active_restrictions(namespace="default", agent_id="agent_a")


def test_forged_active_restriction_row_is_rejected():
    """A brand-new ACTIVE restriction row inserted directly (bypassing
    impose_restriction entirely) has no valid mac and must be rejected,
    not silently treated as a legitimately-imposed restriction."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store._conn.execute(
        "INSERT INTO restrictions (restriction_id, deployment_namespace, agent_id, "
        "permission_name, permission_scope, permission_max_budget, status, reason_code, "
        "source_proposal_id, expiry_kind, expiry_value, created_at, updated_at) "
        "VALUES ('forged', 'default', 'agent_a', 'deploy', 'prod', NULL, 'ACTIVE', "
        "'FORGED', 'p0', 'human', NULL, 0, 0)"
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.active_restrictions(namespace="default", agent_id="agent_a")


def test_restriction_status_flip_is_now_caught_by_the_ledger_cross_check():
    """Previously a known, open gap (see docs/DURABILITY.md's history):
    active_restrictions() filters on status = 'ACTIVE' in SQL before any
    row mac is checked, so an attacker who flips an ACTIVE row's status
    column directly (rather than editing one of the columns the query
    still returns) used to make it vanish from the result silently -- the
    same category of gap as a deleted live_authority_agents marker.
    restriction_ledger (schema v9) now closes this: active_restrictions
    cross-checks, per call, whether the ledger's latest known transition
    for each restriction_id it has ever seen for this agent is IMPOSED
    (i.e. "should still be ACTIVE") against what the ACTIVE query actually
    returned."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    restriction_id = store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    assert store.active_restrictions(namespace="default", agent_id="agent_a")

    store._conn.execute(
        "UPDATE restrictions SET status = 'CLEARED' WHERE restriction_id = ?",
        (restriction_id,),
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.active_restrictions(namespace="default", agent_id="agent_a")


def test_restriction_ledger_keeps_active_restrictions_working_for_legitimate_transitions():
    """The ledger cross-check must not raise on ordinary, non-adversarial
    use: impose, then legitimately clear/expire through the real API, and
    a later active_restrictions call for the same agent (with other,
    still-active restrictions) must not treat the legitimate transition as
    tampering."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    rid_a = store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    rid_b = store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="staging", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p2", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    assert store.clear_restriction(
        namespace="default", agent_id="agent_a", restriction_id=rid_a,
        authorised_by="human_ops", reason="resolved", policy_version="fp1",
    ) == "cleared"

    active = store.active_restrictions(namespace="default", agent_id="agent_a")
    assert {row["restriction_id"] for row in active} == {rid_b}
    store.verify_integrity_ledger()


def test_forged_ledger_entry_without_the_key_cannot_hide_a_status_flip():
    """An attacker who flips status AND tries to plant a matching-looking
    restriction_ledger row (to make the cross-check's own read agree)
    cannot produce a valid mac without the key -- the forged ledger entry
    itself fails verification."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    restriction_id = store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    store._conn.execute(
        "UPDATE restrictions SET status = 'CLEARED' WHERE restriction_id = ?",
        (restriction_id,),
    )
    store._conn.execute(
        "INSERT INTO restriction_ledger (deployment_namespace, agent_id, restriction_id, "
        "event_type, permission_name, permission_scope, permission_max_budget, "
        "expiry_kind, expiry_value, prev_mac, mac, key_id) VALUES "
        "('default', 'agent_a', ?, 'CLEARED', 'deploy', 'prod', NULL, 'human', NULL, "
        "?, 'forged', 'k1')",
        (restriction_id, "0" * 64),
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.active_restrictions(namespace="default", agent_id="agent_a")


def test_restriction_ledger_chain_catches_a_middle_entry_deleted():
    """Same chain-linkage protection as initialization_ledger: deleting an
    entry that something else was later chained onto breaks the next
    entry's prev_mac -- detectable via the full walk without needing
    anything external."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    store.impose_restriction(
        namespace="default", agent_id="agent_b", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p2", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    store._conn.execute(
        "DELETE FROM restriction_ledger WHERE agent_id = 'agent_a'"
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.verify_integrity_ledger()


def test_restriction_ledger_does_not_catch_the_current_tip_being_deleted():
    """Documented, known residual limit shared with initialization_ledger
    and the rollback problem generally: deleting the single most-recent
    transition, with nothing chained after it, leaves the remaining chain
    fully self-consistent."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    restriction_id_b = store.impose_restriction(
        namespace="default", agent_id="agent_b", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p2", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    store._conn.execute(
        "DELETE FROM restriction_ledger WHERE agent_id = 'agent_b'"
    )
    store._conn.execute(
        "UPDATE restrictions SET status = 'CLEARED' WHERE restriction_id = ?",
        (restriction_id_b,),
    )
    store._conn.commit()

    store.verify_integrity_ledger()  # does not raise
    assert store.active_restrictions(namespace="default", agent_id="agent_b") == []


def test_unauthenticated_store_never_writes_to_the_restriction_ledger():
    """Without a key_provider, restriction_ledger stays untouched --
    authentication (and the ledger it enables) is entirely opt-in."""
    store = SQLiteStore(":memory:")
    store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    assert store._conn.execute(
        "SELECT COUNT(*) FROM restriction_ledger"
    ).fetchone()[0] == 0
    store.verify_integrity_ledger()  # no-op, does not raise


def test_mark_expired_and_clear_restriction_keep_mac_current():
    """Both restriction-transition methods must write a mac reflecting the
    row's *new* status -- otherwise the transition itself would make the
    row look tampered the next time something reads it before it expires
    from view (e.g. restriction_history, or a second active_restrictions
    call racing with the transition)."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    rid_a = store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="prod", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p1", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    rid_b = store.impose_restriction(
        namespace="default", agent_id="agent_a", permission_name="deploy",
        permission_scope="staging", permission_max_budget=None, reason_code="TEST",
        source_proposal_id="p2", envelope_fingerprint="fp1", expiry_kind="human",
        expiry_value=None,
    )
    assert store.mark_expired(namespace="default", agent_id="agent_a", restriction_id=rid_a)
    assert store.clear_restriction(
        namespace="default", agent_id="agent_a", restriction_id=rid_b,
        authorised_by="human_ops", reason="resolved", policy_version="fp1",
    ) == "cleared"
    # Both transitioned out of ACTIVE, so neither shows up here -- this
    # just proves the transitions themselves didn't raise RowIntegrityError
    # (a stale/mismatched mac written by mark_expired/clear_restriction
    # would only surface on a read that includes CLEARED/EXPIRED rows,
    # which active_restrictions deliberately never does; this test's job
    # is only to prove those two methods don't crash writing it).
    assert store.active_restrictions(namespace="default", agent_id="agent_a") == []


def test_tampered_replay_nonce_claim_is_rejected():
    """A replay_nonces row inserted directly (bypassing claim_nonce) has no
    valid mac. When a real claim for the same nonce then hits the UNIQUE
    conflict, the existing (forged) row must fail verification rather than
    being trusted as a genuine prior claim."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store._conn.execute(
        "INSERT INTO replay_nonces (deployment_namespace, agent_id, nonce, claimed_at) "
        "VALUES ('default', 'agent_a', 'n1', 0)"
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.claim_nonce(namespace="default", agent_id="agent_a", nonce="n1")


def test_tampered_replay_proposal_id_claim_is_rejected():
    """Same as the nonce case, for replay_proposal_ids."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store._conn.execute(
        "INSERT INTO replay_proposal_ids (deployment_namespace, proposal_id, agent_id, "
        "claimed_at) VALUES ('default', 'p1', 'agent_a', 0)"
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.claim_proposal_id(namespace="default", proposal_id="p1", agent_id="agent_a")


def test_legitimate_replay_claims_still_detect_real_replays():
    """The mac coverage on replay tables must not interfere with the
    ordinary, non-adversarial replay-detection path: a second legitimate
    claim of the same nonce/proposal_id is still reported as already
    claimed, not as tampering."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    assert store.claim_nonce(namespace="default", agent_id="agent_a", nonce="n1") is True
    assert store.claim_nonce(namespace="default", agent_id="agent_a", nonce="n1") is False
    assert store.claim_proposal_id(
        namespace="default", proposal_id="p1", agent_id="agent_a") is True
    assert store.claim_proposal_id(
        namespace="default", proposal_id="p1", agent_id="agent_a") is False


def test_tampered_step_counter_is_rejected():
    """Directly rewriting a step_counters row's count (e.g. to reset a
    consumed step budget) must be detected on the next peek or increment."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.increment_step_counter(namespace="default", scope="fleet", max_allowed=None)
    store.increment_step_counter(namespace="default", scope="fleet", max_allowed=None)

    store._conn.execute(
        "UPDATE step_counters SET count = 0 WHERE deployment_namespace = 'default' "
        "AND scope = 'fleet'"
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.peek_step_counter(namespace="default", scope="fleet")
    with pytest.raises(RowIntegrityError):
        store.increment_step_counter(namespace="default", scope="fleet", max_allowed=None)


def test_step_counter_keeps_the_mac_current_across_increments():
    """Repeated legitimate increments must keep verifying -- the mac
    refresh on each increment must actually work, not just not-crash once."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    for expected in (1, 2, 3):
        count, within = store.increment_step_counter(
            namespace="default", scope="fleet", max_allowed=None)
        assert count == expected
        assert within
    assert store.peek_step_counter(namespace="default", scope="fleet") == 3


# -- deleted-marker gap: initialization_ledger (schema v8) -------------------

def test_deleted_row_is_indistinguishable_from_never_having_existed_today_but_wont_be():
    """Deleting a live_authority_agents marker row (bypassing SQLiteStore's
    write API) while its initialization_ledger entry survives must be
    detected -- otherwise a deleted marker looks identical to a genuine
    first-ever startup, and re-initializing would re-seed authority at the
    envelope ceiling, restoring whatever was previously delegated away or
    consumed (exactly what invariant #1 forbids, laundered via direct file
    tampering instead of a restart)."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    assert store.is_authority_initialized(namespace="default", agent_id="agent_a") is True

    store._conn.execute(
        "DELETE FROM live_authority_agents WHERE agent_id = 'agent_a'"
    )
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.is_authority_initialized(namespace="default", agent_id="agent_a")


def test_deleting_both_marker_and_ledger_entry_is_not_caught_by_the_cheap_check():
    """Documented, known limit of the cheap per-call cross-check: deleting
    BOTH the marker row and its ledger entry together makes the agent look
    genuinely never-initialized again, with no disagreement to detect. The
    full ledger-chain walk (verify_integrity_ledger) still catches this
    when the deleted entry isn't the chain's current tip -- see the next
    test -- but the cheap presence-only check used on every
    is_authority_initialized call cannot, by itself."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    # A second agent is initialized afterward, so agent_a's ledger entry is
    # no longer the chain's tip.
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_b",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )

    store._conn.execute("DELETE FROM live_authority_agents WHERE agent_id = 'agent_a'")
    store._conn.execute("DELETE FROM initialization_ledger WHERE agent_id = 'agent_a'")
    store._conn.commit()

    # The cheap check alone doesn't notice -- both are consistently absent.
    assert store.is_authority_initialized(namespace="default", agent_id="agent_a") is False


def test_ledger_chain_catches_a_middle_entry_deleted_even_when_its_marker_is_also_deleted():
    """What the cheap check in the previous test misses, the full chain
    walk still catches: agent_b's ledger entry was chained onto agent_a's
    (now-deleted) entry's mac, so the chain breaks at agent_b -- detectable
    without needing anything external, because the deleted entry was not
    the chain's tip when it was removed."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_b",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    store._conn.execute("DELETE FROM live_authority_agents WHERE agent_id = 'agent_a'")
    store._conn.execute("DELETE FROM initialization_ledger WHERE agent_id = 'agent_a'")
    store._conn.commit()

    with pytest.raises(RowIntegrityError):
        store.verify_integrity_ledger()


def test_ledger_chain_does_not_catch_the_current_tip_being_deleted():
    """Documented, known limit shared with the rollback problem: deleting
    the single most-recently-initialized agent's marker AND ledger entry
    together, when nothing has been chained after it yet, leaves the
    remaining chain fully self-consistent -- undetectable without an
    external, host-provided checkpoint (see docs/DURABILITY.md)."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_b",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    # agent_b is the current tip -- delete it and its ledger entry.
    store._conn.execute("DELETE FROM live_authority_agents WHERE agent_id = 'agent_b'")
    store._conn.execute("DELETE FROM initialization_ledger WHERE agent_id = 'agent_b'")
    store._conn.commit()

    store.verify_integrity_ledger()  # does not raise
    assert store.is_authority_initialized(namespace="default", agent_id="agent_b") is False


def test_ledger_key_rotation_does_not_invalidate_existing_entries():
    """Same rotation guarantee as live_authority rows: an entry written
    under an old key must still verify after the provider rotates to a new
    one, via the recorded key_id."""
    key_provider = InMemoryKeyProvider("k1", b"first-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    key_provider.rotate("k2", b"second-key-material")
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_b",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    store.verify_integrity_ledger()  # does not raise across the key rotation
    assert store.is_authority_initialized(namespace="default", agent_id="agent_a") is True
    assert store.is_authority_initialized(namespace="default", agent_id="agent_b") is True


def test_unauthenticated_store_never_writes_to_the_ledger():
    """Without a key_provider, initialization_ledger stays untouched --
    authentication (and the ledger it enables) is entirely opt-in."""
    store = SQLiteStore(":memory:")
    store.initialize_agent_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("read_docs", "*", 10)], envelope_fingerprint="fp1",
    )
    assert store._conn.execute(
        "SELECT COUNT(*) FROM initialization_ledger"
    ).fetchone()[0] == 0
    store.verify_integrity_ledger()  # no-op, does not raise


def test_replace_live_authority_first_time_init_also_writes_a_ledger_entry():
    """replace_live_authority can itself be the call that first initializes
    an agent (delegation before the envelope-ceiling seeding path ever
    ran) -- that path must append a ledger entry too, not just
    initialize_agent_authority's."""
    key_provider = InMemoryKeyProvider("k1", b"secret-key-material")
    store = SQLiteStore(":memory:", key_provider=key_provider)
    store.replace_live_authority(
        namespace="default", agent_id="agent_a",
        permissions=[("write_docs", "*", 5)], source="delegation",
        envelope_fingerprint="fp1",
    )
    assert store._conn.execute(
        "SELECT COUNT(*) FROM initialization_ledger WHERE agent_id = 'agent_a'"
    ).fetchone()[0] == 1
    store.verify_integrity_ledger()
    assert store.is_authority_initialized(namespace="default", agent_id="agent_a") is True


# -- rollback checkpoint (schema v10) ---------------------------------------

def test_rollback_to_an_earlier_valid_database_is_detected_with_a_checkpoint_configured():
    """Restoring an older (at-the-time correctly MAC'd) copy of the database
    file, when a host-provided monotonic checkpoint is configured, must be
    detected at SQLiteStore construction: the restored file's own recorded
    high-water mark is behind the external checkpoint's, and construction
    fails closed rather than silently accepting the older, valid-looking
    state."""
    checkpoint = InMemoryRollbackCheckpoint()
    db_path = ":memory:"
    # Simulate the "earlier backup" directly against the checkpoint object
    # (an in-memory :memory: SQLite database can't be file-copied the way a
    # real deployment's on-disk backup would be, but the property under
    # test -- local seq behind the external checkpoint's -- is identical
    # either way): advance the external checkpoint ahead of what any local
    # database has recorded, simulating a real deployment where later
    # sessions advanced the checkpoint further than this (older, restored)
    # copy of the database ever did.
    store = SQLiteStore(db_path, rollback_checkpoint=checkpoint)
    store.advance_checkpoint()
    store.advance_checkpoint()
    assert checkpoint.read() == 2

    # A fresh connection to a fresh (local seq=0) database, with the
    # checkpoint already ahead at 2 -- exactly what opening a restored,
    # older backup looks like.
    with pytest.raises(RollbackDetectedError):
        SQLiteStore(":memory:", rollback_checkpoint=checkpoint)


def test_rollback_without_a_configured_checkpoint_is_honestly_unsupported():
    """Without an external checkpoint configured, SQLiteStore must not claim
    to detect rollback -- rollback_protected (and, at the governor level,
    security_report()) must say so explicitly, rather than implying the
    keyed-MAC layer alone (which cannot detect rollback -- see
    docs/DURABILITY.md) covers this case."""
    store = SQLiteStore(":memory:", key_provider=InMemoryKeyProvider("k1", b"secret-key-material"))
    assert store.row_authentication_configured is True
    assert store.rollback_protected is False
    with pytest.raises(ValueError):
        store.advance_checkpoint()


def test_checkpoint_advances_atomically_with_the_state_it_protects():
    """The external checkpoint must advance in the same logical step as the
    durable state it protects (e.g. within the same transaction, or with an
    explicit two-phase protocol that fails closed on a partial update) --
    never as a separate, unsynchronised write that could itself race and
    leave the checkpoint behind the state it's supposed to bound."""
    checkpoint = InMemoryRollbackCheckpoint()
    db_dir = tempfile.mkdtemp()
    db_path = f"{db_dir}/chainmail.db"

    store = SQLiteStore(db_path, rollback_checkpoint=checkpoint)
    new_seq = store.advance_checkpoint()
    assert new_seq == 1
    assert checkpoint.read() == 1
    local_seq = store._conn.execute(
        "SELECT seq FROM rollback_checkpoint_state WHERE id = 1"
    ).fetchone()[0]
    assert local_seq == 1
    store.close()

    # Reopening against the same (already-advanced, consistent) checkpoint
    # and database must not raise -- local and external agree.
    SQLiteStore(db_path, rollback_checkpoint=checkpoint).close()

    # Simulate the "crashed between advance_checkpoint's two phases"
    # window directly: the local seq is durably ahead of what the external
    # checkpoint object has recorded (as if a previous process's
    # advance_checkpoint() call committed the local bump but crashed
    # before its external advance() call landed). This is NOT a rollback
    # signal -- the file is legitimately further along than the checkpoint
    # currently knows -- so the next open must self-heal by pushing the
    # checkpoint forward to match, never raise RollbackDetectedError
    # (that's reserved for local BEHIND external).
    behind_checkpoint = InMemoryRollbackCheckpoint(initial=0)
    store2 = SQLiteStore(f"{db_dir}/chainmail2.db", rollback_checkpoint=behind_checkpoint)
    store2.advance_checkpoint()
    store2.advance_checkpoint()
    store2.advance_checkpoint()
    assert behind_checkpoint.read() == 3
    store2.close()

    # Reopen with a fresh checkpoint object that still reads 0 (simulating
    # the external advance() calls above never having reached it).
    lagging_checkpoint = InMemoryRollbackCheckpoint(initial=0)
    store3 = SQLiteStore(f"{db_dir}/chainmail2.db", rollback_checkpoint=lagging_checkpoint)
    assert lagging_checkpoint.read() == 3  # self-healed at construction, no exception
    store3.close()
