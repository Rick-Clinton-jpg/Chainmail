"""Embedding engines. The model2vec test is skipped if the package/model is
unavailable so the suite still runs in a minimal environment."""

import pytest

from chainmail import TfidfEmbeddingEngine, auto_embedding_engine


def test_tfidf_separates_related_from_unrelated():
    eng = TfidfEmbeddingEngine()
    a = "Implement secure multi-agent governance with cryptographic provenance chains"
    b = "Design safe distributed agent oversight using cryptographic provenance chains"
    eng.fit([a, b, "Cooking recipes for beginners", "Gardening tips for summer"])
    assert eng.similarity(a, b) > eng.similarity(a, "Cooking recipes for beginners")


def test_tfidf_handles_empty_and_nonstring():
    eng = TfidfEmbeddingEngine()
    assert eng.similarity("", "x") == 0.0
    assert eng.similarity(None, "x") == 0.0  # type: ignore[arg-type]


def test_auto_engine_returns_something_usable():
    eng = auto_embedding_engine(prefer="tfidf")
    assert 0.0 <= eng.similarity("a b c", "a b c") <= 1.0


def test_model2vec_if_available():
    m2v = pytest.importorskip("model2vec")
    from chainmail import Model2VecEmbeddingEngine
    try:
        eng = Model2VecEmbeddingEngine(lazy=False)
    except Exception as exc:  # noqa: BLE001 -- model download unavailable
        pytest.skip(f"model2vec model unavailable: {exc}")
    related = eng.similarity("secure multi-agent governance prototype",
                             "safe distributed agent oversight system")
    unrelated = eng.similarity("secure multi-agent governance prototype",
                               "banana bread recipe with walnuts")
    assert related > unrelated
    assert 0.0 <= unrelated <= 1.0 and 0.0 <= related <= 1.0
