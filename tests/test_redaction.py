"""PII redaction on audit surfaces."""

from chainmail import AuditSink, HashChainLog, Proposal, make_permission
from chainmail.redaction import scrub_pii

OBJ = "Build a secure multi-agent governance prototype"


def test_scrub_pii_shapes():
    assert scrub_pii("contact 123-45-6789 today") == "contact [REDACTED] today"
    assert scrub_pii("mail jane.doe@example.com now") == "mail [REDACTED] now"
    assert scrub_pii("card 4111 1111 1111 1111 ok") == "card [REDACTED] ok"
    assert scrub_pii("reach jane dot doe at example dot com") == "reach [REDACTED]"


def test_scrub_pii_keeps_evidence():
    # commit SHA, UUID, hex trace id must survive untouched
    for keep in ("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                 "550e8400-e29b-41d4-a716-446655440000",
                 "execution_id 4f9a2b7c1d3e"):
        assert scrub_pii(keep) == keep


def test_hash_chain_scrubs_pii(make_governor):
    chain = HashChainLog()
    g = make_governor(audit=AuditSink(hash_chain=chain))
    g.evaluate(Proposal("r1", "agent_research", "gather", make_permission("research"),
                        "gather notes, ping bob@corp.example when done", 0.85))
    blob = "".join(str(e) for e in chain.entries)
    assert "bob@corp.example" not in blob
    assert "[REDACTED]" in blob
