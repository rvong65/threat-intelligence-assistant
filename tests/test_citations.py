"""Tests for citation extraction and validation."""

from __future__ import annotations

from langchain_core.documents import Document

from src.rag.citations import extract_citation_ids, validate_citations
from src.rag.retriever import RetrievedChunk


def test_extract_citation_ids_bracketed() -> None:
    text = "PowerShell execution [T1059.001] and scripting [T1059]."
    ids = extract_citation_ids(text)
    assert ids == ["T1059.001", "T1059"]


def test_extract_citation_ids_cve() -> None:
    text = "See [CVE-2024-1234] for details."
    assert extract_citation_ids(text) == ["CVE-2024-1234"]


def test_extract_citation_ids_group_and_software() -> None:
    text = "APT28 [G0007] uses Mimikatz [S0002]."
    assert extract_citation_ids(text) == ["G0007", "S0002"]


def test_validate_citations_flags_hallucinations() -> None:
    chunks = [
        RetrievedChunk(
            document=Document(
                page_content="ctx",
                metadata={
                    "source_id": "T1059",
                    "title": "T1059: Command and Scripting Interpreter",
                    "url": "https://attack.mitre.org/techniques/T1059",
                    "source_type": "mitre_attack",
                },
            ),
            score=0.7,
            rank=1,
        )
    ]
    answer = "Technique [T1059] is used often. Also see [T9999]."
    result = validate_citations(answer, chunks)
    assert "T1059" in result.valid_ids
    assert "T9999" in result.hallucinated_ids
