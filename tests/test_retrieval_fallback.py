"""Tests for retrieval-only degraded mode formatter."""

from __future__ import annotations

from langchain_core.documents import Document

from src.rag.retrieval_fallback import RETRIEVAL_ONLY_BANNER, format_retrieval_only_answer
from src.rag.retriever import RetrievedChunk


def _chunk(source_id: str, rank: int = 1) -> RetrievedChunk:
    return RetrievedChunk(
        document=Document(
            page_content="Command and scripting interpreter technique details.",
            metadata={
                "source_id": source_id,
                "title": "Command and Scripting Interpreter",
                "url": "https://attack.mitre.org/techniques/T1059/",
            },
        ),
        score=0.55,
        rank=rank,
    )


def test_format_includes_banner_and_source_id() -> None:
    text = format_retrieval_only_answer("How is T1059 used?", [_chunk("T1059")])
    assert RETRIEVAL_ONLY_BANNER.strip() in text
    assert "T1059" in text
    assert "Command and Scripting Interpreter" in text
    assert "attack.mitre.org" in text


def test_format_empty_chunks() -> None:
    text = format_retrieval_only_answer("How is T1059 used?", [])
    assert "Language model unavailable" in text
    assert "No matching MITRE/KEV sources" in text
