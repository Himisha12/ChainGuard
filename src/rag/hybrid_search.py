"""Hybrid search and reranking engine for vulnerability advisories (D12, D13).

Combines BM25 keyword search with dense semantic search, fused via
Reciprocal Rank Fusion (RRF) for high-recall, high-precision retrieval
over local vulnerability databases and CVE advisory notes.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from src.models.schemas import Severity, Vulnerability
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class SearchDocument:
    """Document indexed for hybrid retrieval."""

    doc_id: str
    title: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    tokens: list[str] = field(default_factory=list)


@dataclass
class SearchResult:
    """Ranked search result with scoring breakdown."""

    doc_id: str
    title: str
    content: str
    metadata: dict[str, Any]
    bm25_rank: Optional[int] = None
    dense_rank: Optional[int] = None
    bm25_score: float = 0.0
    dense_score: float = 0.0
    rrf_score: float = 0.0


def _tokenize(text: str) -> list[str]:
    """Lowercase tokenization with alphanumeric filtering."""
    return [word for word in re.findall(r"\b[a-zA-Z0-9_\-\.]+\b", text.lower()) if len(word) > 1]


class BM25Retriever:
    """Okapi BM25 keyword retrieval engine (D12)."""

    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.corpus: list[SearchDocument] = []
        self.doc_lens: list[int] = []
        self.avg_doc_len: float = 0.0
        self.doc_freqs: dict[str, int] = {}
        self.idf: dict[str, float] = {}
        self.total_docs: int = 0

    def fit(self, documents: list[SearchDocument]) -> None:
        """Index documents and precompute IDF tables."""
        self.corpus = documents
        self.total_docs = len(documents)
        if self.total_docs == 0:
            return

        self.doc_lens = [len(doc.tokens) for doc in documents]
        self.avg_doc_len = sum(self.doc_lens) / max(self.total_docs, 1)

        self.doc_freqs = {}
        for doc in documents:
            unique_tokens = set(doc.tokens)
            for token in unique_tokens:
                self.doc_freqs[token] = self.doc_freqs.get(token, 0) + 1

        # Calculate BM25 IDF: ln((N - n + 0.5) / (n + 0.5) + 1)
        self.idf = {}
        for token, freq in self.doc_freqs.items():
            self.idf[token] = math.log(
                (self.total_docs - freq + 0.5) / (freq + 0.5) + 1.0
            )

    def search(self, query: str, top_k: int = 10) -> list[tuple[SearchDocument, float]]:
        """Score documents against query terms."""
        if self.total_docs == 0:
            return []

        query_tokens = _tokenize(query)
        if not query_tokens:
            return []

        scores: list[float] = [0.0] * self.total_docs

        for token in query_tokens:
            if token not in self.idf:
                continue
            idf_val = self.idf[token]

            for i, doc in enumerate(self.corpus):
                # Count term freq in document
                tf = doc.tokens.count(token)
                if tf == 0:
                    continue

                doc_len = self.doc_lens[i]
                numerator = tf * (self.k1 + 1.0)
                denominator = tf + self.k1 * (1.0 - self.b + self.b * (doc_len / max(self.avg_doc_len, 1e-6)))
                scores[i] += idf_val * (numerator / denominator)

        ranked_indices = sorted(
            [i for i in range(self.total_docs) if scores[i] > 0.0],
            key=lambda i: scores[i],
            reverse=True,
        )[:top_k]

        return [(self.corpus[i], scores[i]) for i in ranked_indices]


_TRANSFORMER_MODEL = None


class DenseSemanticRetriever:
    """Dense semantic retriever using embeddings with fast cosine similarity (D12)."""

    def __init__(self, use_neural: bool = False) -> None:
        self.use_neural = use_neural
        self.corpus: list[SearchDocument] = []
        self._embeddings: list[list[float]] = []

    def _embed_text(self, text: str) -> list[float]:
        """Generate dense vector representation.

        Uses cached sentence-transformers if enabled, otherwise uses a deterministic
        subword n-gram hashing vectorizer for instantaneous offline operation.
        """
        global _TRANSFORMER_MODEL
        if self.use_neural:
            try:
                if _TRANSFORMER_MODEL is None:
                    from sentence_transformers import SentenceTransformer  # type: ignore
                    _TRANSFORMER_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
                vector = _TRANSFORMER_MODEL.encode(text).tolist()
                return [float(v) for v in vector]
            except Exception:
                pass

        # Deterministic character n-gram hashing vector (dimension = 128)
        dim = 128
        vec = [0.0] * dim
        tokens = _tokenize(text)
        for token in tokens:
            for i in range(len(token) - 2):
                tri = token[i : i + 3]
                idx = abs(hash(tri)) % dim
                vec[idx] += 1.0
        # L2 normalize
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec

    def fit(self, documents: list[SearchDocument]) -> None:
        """Compute and store embeddings for all corpus documents."""
        self.corpus = documents
        self._embeddings = []
        for doc in documents:
            text = f"{doc.title} {doc.content}"
            self._embeddings.append(self._embed_text(text))

    def search(self, query: str, top_k: int = 10) -> list[tuple[SearchDocument, float]]:
        """Dense similarity search using cosine distance."""
        if not self.corpus or not self._embeddings:
            return []

        query_vec = self._embed_text(query)
        q_norm = math.sqrt(sum(v * v for v in query_vec))
        if q_norm == 0:
            return []

        scores: list[float] = []
        for d_vec in self._embeddings:
            dot = sum(q * d for q, d in zip(query_vec, d_vec))
            scores.append(dot)

        ranked_indices = sorted(
            range(len(self.corpus)),
            key=lambda i: scores[i],
            reverse=True,
        )[:top_k]

        return [(self.corpus[i], scores[i]) for i in ranked_indices if scores[i] > 0.0]


class HybridVulnSearch:
    """Hybrid Search (BM25 + Dense) with Reciprocal Rank Fusion (RRF) (D12, D13)."""

    def __init__(self, rrf_k: int = 60) -> None:
        self.rrf_k = rrf_k
        self.bm25 = BM25Retriever()
        self.dense = DenseSemanticRetriever()
        self.documents: list[SearchDocument] = []

    def index_vulnerabilities(self, vuln_db: dict[str, list[dict[str, Any]]]) -> int:
        """Index vulnerabilities from the structured database."""
        docs: list[SearchDocument] = []

        for pkg_name, vulns in vuln_db.items():
            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN")
                desc = vuln.get("description", "")
                affected = vuln.get("affected_versions", "")
                fixed = vuln.get("fixed_version", "")
                cvss = vuln.get("cvss_score", 0.0)

                content = (
                    f"Package: {pkg_name}\n"
                    f"Vulnerability: {vuln_id}\n"
                    f"Affected Versions: {affected}\n"
                    f"Fixed Version: {fixed}\n"
                    f"CVSS Score: {cvss}\n"
                    f"Description: {desc}"
                )

                doc = SearchDocument(
                    doc_id=vuln_id,
                    title=f"{pkg_name} {vuln_id}",
                    content=content,
                    metadata={
                        "package_name": pkg_name,
                        "vuln_id": vuln_id,
                        "affected_versions": affected,
                        "fixed_version": fixed,
                        "cvss_score": cvss,
                    },
                    tokens=_tokenize(content),
                )
                docs.append(doc)

        self.documents = docs
        self.bm25.fit(docs)
        self.dense.fit(docs)

        logger.info("hybrid_search_indexed", doc_count=len(docs))
        return len(docs)

    def index_from_file(self, db_path: Path | str) -> int:
        """Load and index database from a JSON file."""
        path = Path(db_path)
        if not path.exists():
            return 0
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return self.index_vulnerabilities(data)

    def search(
        self,
        query: str,
        top_k: int = 5,
        bm25_weight: float = 1.0,
        dense_weight: float = 1.0,
    ) -> list[SearchResult]:
        """Execute hybrid search using Reciprocal Rank Fusion (RRF).

        RRF score = sum(weight / (k + rank_i))
        """
        if not self.documents:
            return []

        # 1. Retrieve candidates from both systems
        bm25_results = self.bm25.search(query, top_k=top_k * 2)
        dense_results = self.dense.search(query, top_k=top_k * 2)

        # 2. Build rank mappings
        bm25_ranks: dict[str, tuple[int, float]] = {}
        for rank, (doc, score) in enumerate(bm25_results, start=1):
            bm25_ranks[doc.doc_id] = (rank, score)

        dense_ranks: dict[str, tuple[int, float]] = {}
        for rank, (doc, score) in enumerate(dense_results, start=1):
            dense_ranks[doc.doc_id] = (rank, score)

        # 3. Fuse scores with RRF
        all_doc_ids = set(bm25_ranks.keys()) | set(dense_ranks.keys())
        doc_map = {doc.doc_id: doc for doc in self.documents}

        fused_results: list[SearchResult] = []
        for doc_id in all_doc_ids:
            doc = doc_map.get(doc_id)
            if not doc:
                continue

            bm25_rank, bm25_score = bm25_ranks.get(doc_id, (None, 0.0))
            dense_rank, dense_score = dense_ranks.get(doc_id, (None, 0.0))

            rrf_score = 0.0
            if bm25_rank is not None:
                rrf_score += bm25_weight / (self.rrf_k + bm25_rank)
            if dense_rank is not None:
                rrf_score += dense_weight / (self.rrf_k + dense_rank)

            fused_results.append(
                SearchResult(
                    doc_id=doc.doc_id,
                    title=doc.title,
                    content=doc.content,
                    metadata=doc.metadata,
                    bm25_rank=bm25_rank,
                    dense_rank=dense_rank,
                    bm25_score=bm25_score,
                    dense_score=dense_score,
                    rrf_score=rrf_score,
                )
            )

        # 4. Sort by final RRF score
        fused_results.sort(key=lambda x: x.rrf_score, reverse=True)
        return fused_results[:top_k]
