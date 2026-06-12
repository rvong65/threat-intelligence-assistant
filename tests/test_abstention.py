"""Tests for hard abstention gate."""

from __future__ import annotations

from langchain_core.documents import Document

from src.rag.confidence import compute_retrieval_only_percent, should_abstain_pre_generation
from src.rag.retriever import (
    RetrievedChunk,
    _apply_entity_boost,
    extract_metadata_keywords,
    is_kev_query,
)


def _chunk(source_id: str, score: float, product: str = "") -> RetrievedChunk:
    return RetrievedChunk(
        document=Document(
            page_content=f"Product: {product}",
            metadata={"source_id": source_id, "product": product, "vendor": "Microsoft"},
        ),
        score=score,
        rank=1,
    )


def test_should_abstain_on_poor_retrieval() -> None:
    chunks = [_chunk("T9999", 1.45)]
    assert should_abstain_pre_generation(chunks, threshold=40) is True


def test_should_not_abstain_on_good_retrieval() -> None:
    chunks = [_chunk("T1059", 0.6)]
    assert should_abstain_pre_generation(chunks, threshold=40) is False


def test_retrieval_only_percent() -> None:
    good = compute_retrieval_only_percent([_chunk("T1059", 0.5)])
    poor = compute_retrieval_only_percent([_chunk("T1059", 1.4)])
    assert good > poor


def test_metadata_keyword_extraction() -> None:
    keywords = extract_metadata_keywords("Recent exploited CVEs affecting Windows?")
    assert "windows" in keywords


def test_kev_query_detection() -> None:
    assert is_kev_query("Recent exploited CVEs affecting Windows?") is True
    assert is_kev_query("How is T1059 used?") is False


def test_metadata_boost_promotes_windows_product() -> None:
    windows_doc = Document(
        page_content="Windows vulnerability",
        metadata={"source_id": "CVE-2024-0001", "product": "Windows", "vendor": "Microsoft"},
    )
    other_doc = Document(
        page_content="Linux vulnerability",
        metadata={"source_id": "CVE-2024-0002", "product": "Linux", "vendor": "Red Hat"},
    )
    raw = [(other_doc, 0.5), (windows_doc, 0.7)]
    boosted = _apply_entity_boost(
        raw, [], [], [], [], metadata_keywords=["windows"], kev_query=False
    )
    assert boosted[0][0].metadata["source_id"] == "CVE-2024-0001"
