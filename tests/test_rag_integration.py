"""Integration tests — full RAG chain (same core path as Streamlit UI).

Verifies answer text, sidebar-equivalent sources (``citations.sources``),
and confidence for representative analyst queries. CI uses FakeEmbeddings +
mocked LLM; optional live Groq test runs locally when ``GROQ_API_KEY`` is set.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
from langchain_community.embeddings import FakeEmbeddings
from langchain_core.messages import AIMessage

from config.settings import Settings, get_settings, groq_api_key_configured
from src.embeddings.factory import get_embeddings
from src.llm.factory import get_llm
from src.rag.chain import ThreatIntelRAGChain
from src.llm.errors import LLMUserError
from src.vectorstore.factory import load_vectorstore

_FAISS_EMBED_SIZE = 768

_T1059_LLM_ANSWER = (
    "T1059 (Command and Scripting Interpreter) is used by adversaries to run "
    "code on target systems [T1059]. PowerShell sub-technique [T1059.001] is "
    "commonly abused on Windows."
)


@pytest.fixture(scope="module")
def vectorstore():
    settings = Settings(_env_file=None)
    index_dir = settings.indices_dir
    if not index_dir.exists():
        pytest.skip("FAISS index not built")
    embeddings = FakeEmbeddings(size=_FAISS_EMBED_SIZE)
    return load_vectorstore(embeddings, settings)


@pytest.fixture
def chain_settings() -> Settings:
    return Settings(
        _env_file=None,
        hard_abstention_enabled=False,
        retrieval_only_fallback_enabled=True,
    )


def test_t1059_full_pipeline_answer_sources_and_confidence(
    vectorstore, chain_settings: Settings
) -> None:
    """Same query path as Streamlit: answer + sources + confidence."""
    chain = ThreatIntelRAGChain(
        vectorstore=vectorstore,
        llm=MagicMock(),
        settings=chain_settings,
    )
    with patch(
        "src.rag.chain.invoke_llm",
        return_value=AIMessage(content=_T1059_LLM_ANSWER),
    ):
        response = chain.invoke("How is T1059 used?")

    assert not response.out_of_scope
    assert not response.degraded_retrieval_only
    assert not response.is_abstention
    assert "T1059" in response.answer
    assert response.confidence.overall >= 40
    assert response.citations.sources
    assert any(s.source_id.startswith("T1059") for s in response.citations.sources)
    assert len(response.chunks) == len(response.citations.sources)
    for source in response.citations.sources:
        assert source.source_id
        assert source.rank >= 1


def test_t1059_llm_failure_still_returns_sources_and_confidence(
    vectorstore, chain_settings: Settings
) -> None:
    """Degraded mode: sidebar sources + confidence when LLM fails after retrieve."""
    chain = ThreatIntelRAGChain(
        vectorstore=vectorstore,
        llm=MagicMock(),
        settings=chain_settings,
    )
    with patch(
        "src.rag.chain.invoke_llm",
        side_effect=LLMUserError(user_message="LLM unavailable"),
    ):
        response = chain.invoke("How is T1059 used?")

    assert response.degraded_retrieval_only is True
    assert "Language model unavailable" in response.answer
    assert response.citations.sources
    assert any(s.source_id.startswith("T1059") for s in response.citations.sources)
    assert response.confidence.overall >= 0
    assert len(response.chunks) == len(response.citations.sources)


def test_off_topic_query_no_sources_or_llm(vectorstore, chain_settings: Settings) -> None:
    chain = ThreatIntelRAGChain(
        vectorstore=vectorstore,
        llm=MagicMock(),
        settings=chain_settings,
    )
    response = chain.invoke("What is the weather in Tokyo?")

    assert response.out_of_scope is True
    assert not response.citations.sources
    assert response.confidence.overall == 0


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") == "true" or not groq_api_key_configured(),
    reason="Live Groq pipeline runs locally with GROQ_API_KEY only",
)
def test_t1059_live_groq_answer_sources_and_confidence() -> None:
    """End-to-end with real Groq + HF embeddings (maintainer / local verification)."""
    get_settings.cache_clear()
    settings = get_settings()
    embeddings = get_embeddings(settings)
    vectorstore = load_vectorstore(embeddings, settings)
    llm = get_llm(settings)
    chain = ThreatIntelRAGChain(
        vectorstore=vectorstore,
        llm=llm,
        settings=settings,
    )
    response = chain.invoke("How is T1059 used?")

    assert not response.out_of_scope
    assert not response.is_abstention
    assert response.answer.strip()
    assert response.citations.sources
    assert any(s.source_id.startswith("T1059") for s in response.citations.sources)
    assert response.confidence.overall >= 40
