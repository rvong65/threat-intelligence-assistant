"""Integration tests for retrieval against the persisted FAISS index."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import get_settings
from src.embeddings.factory import get_embeddings
from src.rag.retriever import retrieve
from src.vectorstore.factory import load_vectorstore


@pytest.fixture(scope="module")
def vectorstore():
    settings = get_settings()
    index_dir = settings.indices_dir
    if not index_dir.exists():
        pytest.skip("FAISS index not built")
    return load_vectorstore(get_embeddings(settings), settings)


def test_t1059_query_retrieves_technique_not_only_kev(vectorstore) -> None:
    settings = get_settings()
    chunks = retrieve(vectorstore, "How is T1059 used?", settings)
    assert chunks
    assert any(c.source_id.startswith("T1059") for c in chunks)


def test_windows_kev_query_retrieves_cve_sources(vectorstore) -> None:
    settings = get_settings()
    chunks = retrieve(
        vectorstore, "Recent exploited CVEs affecting Windows?", settings
    )
    assert chunks
    assert all(c.source_id.startswith("CVE-") for c in chunks)
    assert any("windows" in c.document.page_content.lower() for c in chunks)
