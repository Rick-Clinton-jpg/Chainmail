"""
Typed-pattern PII redaction for text that lands on an audit surface -- the
hash-chain log, the SQLite store, snapshots, and anything a future service
endpoint might echo back.

Deliberately NOT an entropy / "looks random" scrubber: that would destroy
commit hashes, nonces, execution ids, and UUIDs that are the whole point of an
audit trail. Only known PII shapes are touched.

Adapted from ``Quorum/gate/redaction.py`` (Rick-Clinton-jpg, PolyForm NC 1.0.0).
"""

from __future__ import annotations

import re

PLACEHOLDER = "[REDACTED]"

_PII_PATTERN = re.compile(
    r"(\b\d{3}-\d{2}-\d{4}\b"                                      # US SSN
    r"|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"        # email
    r"|\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}\b"                    # 16-digit card, spaced/dashed
    # spelled-out email: "jane dot doe at example dot com"
    r"|\b[a-z0-9_]+(?:\s+dot\s+[a-z0-9_]+)+\s+at\s+[a-z0-9_]+(?:\s+dot\s+[a-z0-9_]+)+\b)",
    re.IGNORECASE,
)


def scrub_pii(text: str) -> str:
    """Replace any PII-shaped span (email, SSN, card number, spelled-out email)
    with ``[REDACTED]``. Safe on ``None``/empty and on arbitrary text -- a
    commit SHA, trace id, or UUID passes through untouched."""
    if not text:
        return text
    return _PII_PATTERN.sub(PLACEHOLDER, text)
