"""Transparent confidence scoring for responsible-AI disclosure."""

from __future__ import annotations

from dataclasses import dataclass

from src.rag.retriever import RetrievedChunk

# Typical L2 distance range observed with nomic-embed-text on this corpus.
MAX_DISTANCE = 1.5
MIN_DISTANCE = 0.0

WEIGHT_RETRIEVAL = 0.60
WEIGHT_COVERAGE = 0.25
WEIGHT_CITATION = 0.15


@dataclass
class ConfidenceBreakdown:
    """Component scores and final 0–100 confidence."""

    retrieval_score: float
    context_coverage: float
    citation_match: float
    overall: int
    is_low_confidence: bool
    formula: str = (
        "confidence = 0.60×retrieval + 0.25×coverage + 0.15×citation_match"
    )

    def explanation_lines(self) -> list[str]:
        return [
            f"Retrieval quality: {self.retrieval_score:.0%}",
            f"Context coverage: {self.context_coverage:.0%}",
            f"Citation match: {self.citation_match:.0%}",
            f"Overall confidence: {self.overall}/100",
        ]


def _distance_to_retrieval_score(best_distance: float) -> float:
    """Convert FAISS L2 distance to 0–1 score (lower distance = higher score)."""
    clamped = max(MIN_DISTANCE, min(best_distance, MAX_DISTANCE))
    return 1.0 - (clamped - MIN_DISTANCE) / (MAX_DISTANCE - MIN_DISTANCE)


def compute_retrieval_only_percent(chunks: list[RetrievedChunk]) -> int:
    """Retrieval-only confidence (0–100) for pre-generation abstention gate."""
    if not chunks:
        return 0
    best_distance = min(chunk.score for chunk in chunks)
    return round(_distance_to_retrieval_score(best_distance) * 100)


def should_abstain_pre_generation(
    chunks: list[RetrievedChunk],
    threshold: int,
) -> bool:
    """Return True when retrieval quality alone is below threshold."""
    return compute_retrieval_only_percent(chunks) < threshold


def compute_confidence(
    chunks: list[RetrievedChunk],
    cited_ids: list[str],
    valid_cited_ids: list[str],
    threshold: int,
) -> ConfidenceBreakdown:
    """
    Compute transparent confidence from retrieval, coverage, and citations.

    - retrieval_score: from best (lowest) FAISS distance
    - context_coverage: share of retrieved source_ids referenced in answer
    - citation_match: share of cited IDs that exist in retrieved set
    """
    if not chunks:
        return ConfidenceBreakdown(
            retrieval_score=0.0,
            context_coverage=0.0,
            citation_match=0.0,
            overall=0,
            is_low_confidence=True,
        )

    best_distance = min(chunk.score for chunk in chunks)
    retrieval_score = _distance_to_retrieval_score(best_distance)

    retrieved_ids = {chunk.source_id for chunk in chunks if chunk.source_id}
    if retrieved_ids:
        referenced = {cid for cid in cited_ids if cid in retrieved_ids}
        context_coverage = len(referenced) / len(retrieved_ids)
    else:
        context_coverage = 0.0

    if cited_ids:
        citation_match = len(valid_cited_ids) / len(cited_ids)
    elif not cited_ids and retrieval_score > 0.5:
        citation_match = 0.0
    else:
        citation_match = 1.0

    overall_float = (
        WEIGHT_RETRIEVAL * retrieval_score
        + WEIGHT_COVERAGE * context_coverage
        + WEIGHT_CITATION * citation_match
    )
    overall = round(overall_float * 100)
    overall = max(0, min(100, overall))

    return ConfidenceBreakdown(
        retrieval_score=retrieval_score,
        context_coverage=context_coverage,
        citation_match=citation_match,
        overall=overall,
        is_low_confidence=overall < threshold,
    )
