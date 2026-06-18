"""Integration tests for retrieval against the persisted FAISS index."""

from __future__ import annotations

import os

import pytest

from config.settings import get_settings
from src.embeddings.factory import get_embeddings
from src.rag.retriever import retrieve
from src.vectorstore.factory import load_vectorstore

# Nomic embed vectors in the committed index are 768-dimensional.
_FAISS_EMBED_SIZE = 768


@pytest.fixture(scope="module")
def vectorstore():
    settings = get_settings()
    index_dir = settings.indices_dir
    if not index_dir.exists():
        pytest.skip("FAISS index not built")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        from langchain_community.embeddings import FakeEmbeddings

        embeddings = FakeEmbeddings(size=_FAISS_EMBED_SIZE)
    else:
        embeddings = get_embeddings(settings)
    return load_vectorstore(embeddings, settings)


def test_t1059_query_retrieves_technique_not_only_kev(vectorstore) -> None:
    settings = get_settings()
    chunks = retrieve(vectorstore, "How is T1059 used?", settings)
    assert chunks
    assert any(c.source_id.startswith("T1059") for c in chunks)


def test_windows_kev_query_retrieves_cve_sources(vectorstore) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        pytest.skip(
            "KEV semantic ranking requires real embedding models; run locally."
        )
    settings = get_settings()
    chunks = retrieve(
        vectorstore, "Recent exploited CVEs affecting Windows?", settings
    )
    assert chunks
    assert all(c.source_id.startswith("CVE-") for c in chunks)
    assert any("windows" in c.document.page_content.lower() for c in chunks)
