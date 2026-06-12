"""Citation extraction and validation against retrieved source IDs."""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.rag.retriever import RetrievedChunk

# Bracketed or bare IDs in LLM output.
CITATION_PATTERN = re.compile(
    r"\[(T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|CVE-\d{4}-\d{4,})\]"
    r"|(?<![A-Za-z0-9])(T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|CVE-\d{4}-\d{4,})(?![A-Za-z0-9])",
    re.IGNORECASE,
)


@dataclass
class SourceReference:
    """One citable source for sidebar rendering."""

    source_id: str
    title: str
    url: str
    source_type: str
    score: float
    rank: int
    boosted: bool = False


@dataclass
class CitationValidation:
    """Result of post-generation citation checks."""

    cited_ids: list[str]
    valid_ids: list[str]
    hallucinated_ids: list[str]
    sources: list[SourceReference]


def extract_citation_ids(text: str) -> list[str]:
    """Extract unique MITRE/CVE IDs from answer text, preserving order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for match in CITATION_PATTERN.finditer(text):
        raw = match.group(1) or match.group(2)
        normalized = raw.upper()
        if normalized.startswith("T"):
            normalized = normalized.upper()
        if normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)
    return ordered


def validate_citations(
    answer: str,
    chunks: list[RetrievedChunk],
) -> CitationValidation:
    """Validate cited IDs against retrieved chunk metadata."""
    allowed_ids = {chunk.source_id.upper() for chunk in chunks if chunk.source_id}
    # Also allow parent technique when sub-technique retrieved and vice versa.
    expanded_allowed = set(allowed_ids)
    for sid in allowed_ids:
        if "." in sid:
            expanded_allowed.add(sid.split(".")[0])
        else:
            expanded_allowed.add(sid)

    cited_ids = extract_citation_ids(answer)
    valid_ids: list[str] = []
    hallucinated_ids: list[str] = []

    for cid in cited_ids:
        cid_upper = cid.upper()
        if cid_upper in expanded_allowed or any(
            cid_upper.startswith(f"{a}.") for a in expanded_allowed if a.startswith("T")
        ):
            valid_ids.append(cid)
        else:
            hallucinated_ids.append(cid)

    sources: list[SourceReference] = []
    for chunk in chunks:
        meta = chunk.metadata
        sources.append(
            SourceReference(
                source_id=chunk.source_id,
                title=str(meta.get("title", chunk.source_id)),
                url=str(meta.get("url", "")),
                source_type=str(meta.get("source_type", "")),
                score=chunk.score,
                rank=chunk.rank,
                boosted=chunk.boosted,
            )
        )

    return CitationValidation(
        cited_ids=cited_ids,
        valid_ids=valid_ids,
        hallucinated_ids=hallucinated_ids,
        sources=sources,
    )
