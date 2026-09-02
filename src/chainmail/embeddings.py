"""
Chainmail v5 --- semantic continuity engines.

The governor needs one operation: ``similarity(text_a, text_b) -> [0, 1]``. Three
implementations are provided, in descending order of quality:

1. ``Model2VecEmbeddingEngine`` -- real static embeddings (``model2vec``), no
   torch, ~30 MB on disk, pure-numpy inference. This is the recommended default.
2. ``SentenceTransformerEmbeddingEngine`` -- transformer embeddings, heavier.
3. ``TfidfEmbeddingEngine`` -- zero-dependency fallback. Unlike the v4 version it
   is actually fitted by the governor against a live corpus.

``auto_embedding_engine()`` picks the best one that imports and can load.
"""

from __future__ import annotations

import logging
import math
import threading
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class EmbeddingEngine(Protocol):
    def similarity(self, text_a: str, text_b: str) -> float: ...
    def fit(self, documents: List[str]) -> None: ...


# ============================================================================
# TF-IDF fallback (stdlib only)
# ============================================================================

class TfidfEmbeddingEngine:
    """TF-IDF + cosine similarity. Thread-safe for concurrent ``similarity``
    once fitted; ``fit`` takes a brief exclusive lock."""

    _STRIP = ".,!?;:'()[]{}\"<>"

    def __init__(self) -> None:
        self._idf: Dict[str, float] = {}
        self._doc_count = 0
        self._fitted = False
        self._lock = threading.RLock()

    def _tokenize(self, text: str) -> List[str]:
        if not isinstance(text, str):
            return []
        out = []
        for tok in text.lower().split():
            tok = tok.strip(self._STRIP)
            if len(tok) > 2:
                out.append(tok)
        return out

    def fit(self, documents: List[str]) -> None:
        docs = [d for d in documents if isinstance(d, str) and d.strip()]
        with self._lock:
            corpus_df: Dict[str, int] = defaultdict(int)
            for doc in docs:
                for term in set(self._tokenize(doc)):
                    corpus_df[term] += 1
            self._doc_count = len(docs)
            self._idf = {
                term: math.log((1 + self._doc_count) / (1 + df)) + 1.0
                for term, df in corpus_df.items()
            }
            self._fitted = bool(self._idf)

    def _vectorize(self, text: str) -> Dict[str, float]:
        tokens = self._tokenize(text)
        if not tokens:
            return {}
        tf = Counter(tokens)
        total = len(tokens)
        return {
            term: (count / total) * (self._idf.get(term, 1.0) if self._fitted else 1.0)
            for term, count in tf.items()
        }

    def similarity(self, text_a: str, text_b: str) -> float:
        vec_a = self._vectorize(text_a)
        vec_b = self._vectorize(text_b)
        if not vec_a or not vec_b:
            return 0.0
        dot = sum(val * vec_b.get(term, 0.0) for term, val in vec_a.items())
        norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
        norm_b = math.sqrt(sum(v * v for v in vec_b.values()))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return max(0.0, min(1.0, dot / (norm_a * norm_b)))


# ============================================================================
# model2vec static embeddings (recommended default)
# ============================================================================

class Model2VecEmbeddingEngine:
    """Static-embedding engine backed by ``model2vec``. Returns raw cosine
    similarity clamped to [0, 1]; for this domain unrelated text sits near 0 and
    on-objective text well above the ~0.25 default threshold (verified against
    ``potion-base-8M``)."""

    def __init__(self, model_name: str = "minishlab/potion-base-8M", *, lazy: bool = True) -> None:
        self.model_name = model_name
        self._model = None
        self._np = None
        self._lock = threading.RLock()
        if not lazy:
            self._ensure_loaded()

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:
                return
            from model2vec import StaticModel  # noqa: import-time dependency
            import numpy as np

            self._model = StaticModel.from_pretrained(self.model_name)
            self._np = np
            logger.info("Model2VecEmbeddingEngine loaded model %s", self.model_name)

    def fit(self, documents: List[str]) -> None:  # pre-trained; nothing to fit
        return None

    def similarity(self, text_a: str, text_b: str) -> float:
        if not isinstance(text_a, str) or not isinstance(text_b, str) or not text_a or not text_b:
            return 0.0
        self._ensure_loaded()
        np = self._np
        emb = self._model.encode([text_a, text_b])
        a, b = emb[0], emb[1]
        denom = float(np.linalg.norm(a) * np.linalg.norm(b))
        if denom == 0.0:
            return 0.0
        cos = float(np.dot(a, b) / denom)
        return max(0.0, min(1.0, cos))


# ============================================================================
# sentence-transformers (optional, heavy)
# ============================================================================

class SentenceTransformerEmbeddingEngine:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2", *, lazy: bool = True) -> None:
        self.model_name = model_name
        self._model = None
        self._np = None
        self._lock = threading.RLock()
        if not lazy:
            self._ensure_loaded()

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:
                return
            from sentence_transformers import SentenceTransformer
            import numpy as np

            self._model = SentenceTransformer(self.model_name)
            self._np = np
            logger.info("SentenceTransformerEmbeddingEngine loaded model %s", self.model_name)

    def fit(self, documents: List[str]) -> None:
        return None

    def similarity(self, text_a: str, text_b: str) -> float:
        if not isinstance(text_a, str) or not isinstance(text_b, str) or not text_a or not text_b:
            return 0.0
        self._ensure_loaded()
        np = self._np
        emb = self._model.encode([text_a, text_b], normalize_embeddings=True)
        cos = float(np.dot(emb[0], emb[1]))
        return max(0.0, min(1.0, cos))


# ============================================================================
# Auto-selection
# ============================================================================

def auto_embedding_engine(prefer: Optional[str] = None) -> EmbeddingEngine:
    """Return the best available engine.

    ``prefer`` may be ``"model2vec"``, ``"sentence-transformers"``, or ``"tfidf"``
    to force a choice; on failure it still falls back to TF-IDF.
    """
    order = ["model2vec", "sentence-transformers", "tfidf"]
    if prefer:
        order = [prefer] + [o for o in order if o != prefer]

    for choice in order:
        try:
            if choice == "model2vec":
                engine = Model2VecEmbeddingEngine(lazy=False)
                logger.info("auto_embedding_engine -> model2vec")
                return engine
            if choice == "sentence-transformers":
                engine = SentenceTransformerEmbeddingEngine(lazy=False)
                logger.info("auto_embedding_engine -> sentence-transformers")
                return engine
            if choice == "tfidf":
                logger.info("auto_embedding_engine -> tfidf (fallback)")
                return TfidfEmbeddingEngine()
        except Exception as exc:  # noqa: BLE001 -- fall through to next engine
            logger.warning("embedding engine %r unavailable: %s", choice, exc)

    return TfidfEmbeddingEngine()
