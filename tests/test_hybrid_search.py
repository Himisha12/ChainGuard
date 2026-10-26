"""Tests for hybrid search (BM25 + dense) and RRF reranking (D12, D13)."""

from __future__ import annotations

import pytest

from src.rag.hybrid_search import BM25Retriever, DenseSemanticRetriever, HybridVulnSearch, SearchDocument
from src.tools.vuln_lookup import VULN_DB_PATH


class TestBM25Retriever:
    """Test BM25 keyword matching."""

    def test_fit_and_search_keyword(self) -> None:
        retriever = BM25Retriever()
        docs = [
            SearchDocument(
                doc_id="DOC1",
                title="Flask injection",
                content="Vulnerability in Flask allows remote code execution via jinja templates",
                tokens=["vulnerability", "in", "flask", "allows", "remote", "code", "execution", "jinja"],
            ),
            SearchDocument(
                doc_id="DOC2",
                title="Requests proxy leak",
                content="Requests leaks credentials through HTTP proxy redirects",
                tokens=["requests", "leaks", "credentials", "through", "http", "proxy", "redirects"],
            ),
        ]
        retriever.fit(docs)
        results = retriever.search("proxy redirects", top_k=5)
        assert len(results) > 0
        assert results[0][0].doc_id == "DOC2"


class TestHybridVulnSearch:
    """Test complete hybrid search and RRF fusion."""

    def test_search_indexed_bundled_db(self) -> None:
        engine = HybridVulnSearch(rrf_k=60)
        indexed_count = engine.index_from_file(VULN_DB_PATH)
        assert indexed_count > 0

        # Query for denial of service in urllib3
        results = engine.search("urllib3 header injection", top_k=3)
        assert len(results) > 0
        assert any("urllib3" in r.metadata.get("package_name", "").lower() for r in results)
        assert results[0].rrf_score > 0.0

    def test_rrf_scoring_order(self) -> None:
        engine = HybridVulnSearch(rrf_k=60)
        engine.index_from_file(VULN_DB_PATH)
        results = engine.search("flask session cookie secret", top_k=5)
        assert len(results) > 0
        # Results must be strictly descending by RRF score
        for i in range(len(results) - 1):
            assert results[i].rrf_score >= results[i + 1].rrf_score
