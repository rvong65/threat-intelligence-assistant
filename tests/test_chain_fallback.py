"""Tests for RAG chain retrieval-only fallback on LLM failure."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from langchain_core.documents import Document
from langchain_core.messages import AIMessage

from config.settings import Settings
from src.llm.errors import LLMUserError
from src.rag.chain import ThreatIntelRAGChain
from src.rag.retriever import RetrievedChunk


def _chunk(source_id: str) -> RetrievedChunk:
    return RetrievedChunk(
        document=Document(
            page_content="Technique content for testing.",
            metadata={
                "source_id": source_id,
                "title": "Test Technique",
                "url": "https://attack.mitre.org/techniques/T1059/",
            },
        ),
        score=0.5,
        rank=1,
    )


@pytest.fixture
def chain_with_mock_llm() -> tuple[ThreatIntelRAGChain, MagicMock]:
    llm = MagicMock()
    vectorstore = MagicMock()
    settings = Settings(
        _env_file=None,
        retrieval_only_fallback_enabled=True,
        hard_abstention_enabled=False,
    )
    chain = ThreatIntelRAGChain(
        vectorstore=vectorstore,
        llm=llm,
        settings=settings,
    )
    return chain, llm


def test_llm_failure_returns_degraded_response(chain_with_mock_llm) -> None:
    chain, llm = chain_with_mock_llm
    chunks = [_chunk("T1059")]

    with patch("src.rag.chain.retrieve", return_value=chunks):
        with patch(
            "src.rag.chain.invoke_llm",
            side_effect=LLMUserError(user_message="LLM down"),
        ):
            response = chain.invoke("How is T1059 used?")

    assert response.degraded_retrieval_only is True
    assert response.chunks == chunks
    assert "Language model unavailable" in response.answer
    assert "T1059" in response.answer


def test_llm_failure_reraises_when_fallback_disabled(chain_with_mock_llm) -> None:
    chain, _ = chain_with_mock_llm
    chain.settings.retrieval_only_fallback_enabled = False
    chunks = [_chunk("T1059")]

    with patch("src.rag.chain.retrieve", return_value=chunks):
        with patch(
            "src.rag.chain.invoke_llm",
            side_effect=LLMUserError(user_message="LLM down"),
        ):
            with pytest.raises(LLMUserError):
                chain.invoke("How is T1059 used?")


def test_llm_success_normal_path(chain_with_mock_llm) -> None:
    chain, _ = chain_with_mock_llm
    chunks = [_chunk("T1059")]

    with patch("src.rag.chain.retrieve", return_value=chunks):
        with patch(
            "src.rag.chain.invoke_llm",
            return_value=AIMessage(content="T1059 is used for scripting [T1059]."),
        ):
            response = chain.invoke("How is T1059 used?")

    assert response.degraded_retrieval_only is False
    assert "T1059" in response.answer
