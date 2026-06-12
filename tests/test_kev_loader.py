"""Smoke tests for CISA KEV loader."""

from __future__ import annotations

from pathlib import Path

from src.loaders.cisa_kev import load_cisa_kev


FIXTURE = Path(__file__).parent / "fixtures" / "sample_kev.csv"


def test_load_cisa_kev_extracts_cve() -> None:
    docs = load_cisa_kev(FIXTURE)
    assert len(docs) == 1
    doc = docs[0]
    assert doc.source_id == "CVE-2024-0001"
    assert doc.source_type == "cisa_kev"
    assert doc.citation.vendor == "Microsoft"
    assert doc.citation.product == "Windows"
    assert "nvd.nist.gov" in doc.citation.url
    assert "Windows Test Vulnerability" in doc.title
