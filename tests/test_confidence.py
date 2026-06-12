"""Tests for confidence scoring."""

from __future__ import annotations

from langchain_core.documents import Document

from src.rag.confidence import compute_confidence
from src.rag.retriever import RetrievedChunk


def _chunk(source_id: str, score: float) -> RetrievedChunk:
    return RetrievedChunk(
        document=Document(page_content="test", metadata={"source_id": source_id}),
        score=score,
        rank=1,
    )


def test_high_retrieval_produces_higher_confidence() -> None:
    good = compute_confidence(
        chunks=[_chunk("T1059", 0.5)],
        cited_ids=["T1059"],
        valid_cited_ids=["T1059"],
        threshold=40,
    )
    poor = compute_confidence(
        chunks=[_chunk("T1059", 1.4)],
        cited_ids=["T1059"],
        valid_cited_ids=["T1059"],
        threshold=40,
    )
    assert good.overall > poor.overall


def test_low_confidence_flagged_below_threshold() -> None:
    result = compute_confidence(
        chunks=[_chunk("T1059", 1.45)],
        cited_ids=[],
        valid_cited_ids=[],
        threshold=40,
    )
    assert result.is_low_confidence is True
    assert result.overall < 40


def test_empty_chunks_zero_confidence() -> None:
    result = compute_confidence([], [], [], threshold=40)
    assert result.overall == 0
    assert result.is_low_confidence is True
