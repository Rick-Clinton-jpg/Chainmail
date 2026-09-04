"""Executable specification for the not-yet-implemented keyed-authentication
and rollback-detection layer described in docs/DURABILITY.md.

Every test here is skipped -- none of this exists yet. They are not deleted
because they pin down, precisely, what "done" looks like for that layer, so
an implementation has a concrete target instead of a re-derived one. Un-skip
them one at a time as each piece lands; do not weaken an assertion to make
it pass without the guarantee it names actually existing.
"""

import pytest

pytestmark = pytest.mark.skip(
    reason="keyed authentication / rollback-checkpoint layer is design-only -- see docs/DURABILITY.md"
)


def test_tampered_live_authority_row_is_rejected():
    """Directly editing a live_authority row's remaining/max_budget/
    permission_name/permission_scope with a raw sqlite3 connection (bypassing
    SQLiteStore's own write API entirely) must be detected on the next read
    that feeds an authorization decision (get_live_authority_rows) -- fail
    closed, not silently trusted."""


def test_tampered_row_without_the_key_cannot_forge_a_valid_mac():
    """An attacker who can write to the SQLite file but does not hold the
    external MAC key cannot produce a row that passes verification, however
    they compute a replacement 'mac' column value from the row's own
    plaintext contents."""


def test_deleted_row_is_indistinguishable_from_never_having_existed_today_but_wont_be():
    """Today, deleting a live_authority row and re-initializing looks
    identical to a first-ever startup (both produce is_authority_initialized
    -> False for a fresh marker). The integrity layer's initialization
    marker itself must be authenticated too, so a deleted marker row cannot
    be used to re-seed authority at the envelope ceiling by making the store
    look never-initialized."""


def test_key_rotation_does_not_invalidate_existing_rows():
    """Rotating the external MAC key (via key_provider) must not make
    previously-written, legitimately-unmodified rows fail verification --
    either a key-id is recorded per row (like replay claims already record
    key_id for signature verification) or rotation re-MACs existing rows in
    one pass; either way, a rotation must never look identical to tampering."""


def test_rollback_to_an_earlier_valid_database_is_detected_with_a_checkpoint_configured():
    """Restoring an older (at-the-time correctly MAC'd) copy of the database
    file, when a host-provided monotonic checkpoint is configured, must be
    detected at SQLiteStore construction: the restored file's own recorded
    high-water mark is behind the external checkpoint's, and construction
    fails closed rather than silently accepting the older, valid-looking
    state."""


def test_rollback_without_a_configured_checkpoint_is_honestly_unsupported():
    """Without an external checkpoint configured, SQLiteStore must not claim
    to detect rollback -- security_report() (or an equivalent) must say so
    explicitly, rather than implying the keyed-MAC layer alone (which cannot
    detect rollback -- see docs/DURABILITY.md) covers this case."""


def test_checkpoint_advances_atomically_with_the_state_it_protects():
    """The external checkpoint must advance in the same logical step as the
    durable state it protects (e.g. within the same transaction, or with an
    explicit two-phase protocol that fails closed on a partial update) --
    never as a separate, unsynchronised write that could itself race and
    leave the checkpoint behind the state it's supposed to bound."""
