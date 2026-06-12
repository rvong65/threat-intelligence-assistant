"""Tests for context-prefixed chunking."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.chunking import chunk_documents
from src.loaders.mitre_attack import load_mitre_attack


FIXTURE = Path(__file__).parent / "fixtures" / "sample_mitre.json"


def test_mitre_chunks_have_context_prefix() -> None:
    docs = load_mitre_attack(FIXTURE)
    chunks = chunk_documents(docs)
    assert len(chunks) == 1
    content = chunks[0].content
    assert content.startswith("MITRE ATT&CK Technique T1059")
    assert "Tactic:" in content
    assert chunks[0].chunk_id == "T1059"
