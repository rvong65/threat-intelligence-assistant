"""Unified document schema for ingestion, retrieval, and citation rendering."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


SourceType = Literal[
    "mitre_attack",
    "mitre_group",
    "mitre_software",
    "cisa_kev",
    "nvd_cve",
]


class CitationMetadata(BaseModel):
    """Fields required for mandatory, verifiable citations in the RAG UI."""

    source_id: str = Field(
        ...,
        description="Stable identifier, e.g. T1059 or CVE-2024-1234.",
    )
    source_type: SourceType
    title: str
    url: str
    retrieved_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    vendor: str | None = None
    product: str | None = None
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    date_added: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ThreatDocument(BaseModel):
    """
    One citable intelligence unit before chunking.

    The `content` field holds human-readable text for embedding.
    Citation metadata is preserved separately for grounding checks.
    """

    source_id: str
    source_type: SourceType
    title: str
    content: str
    citation: CitationMetadata
    chunk_id: str | None = None

    def to_langchain_metadata(self) -> dict[str, Any]:
        """Flatten citation fields for LangChain Document.metadata."""
        meta = self.citation.model_dump(mode="json")
        meta["source_id"] = self.source_id
        meta["source_type"] = self.source_type
        meta["title"] = self.title
        if self.chunk_id:
            meta["chunk_id"] = self.chunk_id
        return meta
