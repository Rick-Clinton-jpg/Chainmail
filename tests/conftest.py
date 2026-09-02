import logging

import pytest

logging.disable(logging.CRITICAL)


class JaccardEmbeddingEngine:
    """Deterministic, dependency-free similarity for behavioural tests:
    Jaccard overlap of lower-cased word sets. No fitting, no randomness."""

    def fit(self, documents):
        return None

    def similarity(self, text_a, text_b):
        if not isinstance(text_a, str) or not isinstance(text_b, str):
            return 0.0
        a = {w for w in text_a.lower().split() if len(w) > 2}
        b = {w for w in text_b.lower().split() if len(w) > 2}
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)


@pytest.fixture
def envelope():
    from chainmail import build_demo_envelope
    return build_demo_envelope()


@pytest.fixture
def make_governor(envelope):
    from chainmail import ChainmailGovernor, GovernorConfig

    def _make(env=None, *, config=None, embedding=None, **kwargs):
        return ChainmailGovernor(
            env or envelope,
            config=config or GovernorConfig(),
            embedding=embedding or JaccardEmbeddingEngine(),
            auto_embedding=False,
            **kwargs,
        )

    return _make


@pytest.fixture
def governor(make_governor):
    return make_governor()
