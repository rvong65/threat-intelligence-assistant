"""Tests for retriever entity extraction and metadata boosting."""

from __future__ import annotations

from langchain_core.documents import Document

from src.rag.retriever import _apply_entity_boost, extract_entity_ids


def test_extract_entity_ids_technique_and_cve() -> None:
    query = "How is T1059 used and what about CVE-2024-1234?"
    techniques, groups, software, cves = extract_entity_ids(query)
    assert techniques == ["T1059"]
    assert groups == []
    assert software == []
    assert cves == ["CVE-2024-1234"]


def test_extract_entity_ids_group_and_software() -> None:
    query = "What techniques does APT28 G0007 use with S0154?"
    techniques, groups, software, cves = extract_entity_ids(query)
    assert techniques == []
    assert groups == ["G0007"]
    assert software == ["S0154"]
    assert cves == []


def test_entity_boost_promotes_matching_technique() -> None:
    parent = Document(
        page_content="parent",
        metadata={"source_id": "T1059"},
    )
    sub = Document(
        page_content="sub",
        metadata={"source_id": "T1059.001"},
    )
    other = Document(
        page_content="other",
        metadata={"source_id": "T1558"},
    )
    raw = [(other, 0.6), (sub, 0.7), (parent, 0.8)]
    boosted = _apply_entity_boost(
        raw,
        techniques=["T1059"],
        groups=[],
        software=[],
        cves=[],
        metadata_keywords=[],
        kev_query=False,
    )

    # After boost, T1059 family should rank before T1558.
    top_id = boosted[0][0].metadata["source_id"]
    assert top_id in {"T1059", "T1059.001"}
    assert boosted[0][2] is True  # boosted flag
