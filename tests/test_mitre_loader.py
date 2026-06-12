"""Smoke tests for MITRE ATT&CK loader."""

from __future__ import annotations

from pathlib import Path

from src.loaders.mitre_attack import load_mitre_attack


FIXTURE = Path(__file__).parent / "fixtures" / "sample_mitre.json"


def test_load_mitre_attack_extracts_technique() -> None:
    docs = load_mitre_attack(FIXTURE)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.source_id == "T1059"
    assert doc.source_type == "mitre_attack"
    assert "Command and Scripting Interpreter" in doc.title
    assert doc.citation.tactics == ["Execution"]
    assert doc.citation.url.endswith("/techniques/T1059")
    assert "Windows" in doc.citation.platforms


def test_load_mitre_attack_skips_revoked() -> None:
    docs = load_mitre_attack(FIXTURE)
    assert all(doc.source_id != "T9999" for doc in docs)
