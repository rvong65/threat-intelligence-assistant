"""Template-based answers when the LLM is unavailable (retrieval-only degraded mode)."""

from __future__ import annotations

from src.rag.retriever import RetrievedChunk

RETRIEVAL_ONLY_BANNER = (
    "**Language model unavailable** — showing retrieved sources only. "
    "Verify against primary MITRE/CISA links.\n\n"
)

_EXCERPT_MAX_LEN = 280


def _trim_excerpt(text: str, max_len: int = _EXCERPT_MAX_LEN) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 1].rstrip() + "…"


def format_retrieval_only_answer(
    question: str,
    chunks: list[RetrievedChunk],
) -> str:
    """Build a markdown answer from retrieved chunks without LLM synthesis."""
    if not chunks:
        return (
            RETRIEVAL_ONLY_BANNER
            + "No matching MITRE/KEV sources were retrieved for this query."
        )

    parts = [RETRIEVAL_ONLY_BANNER]
    for chunk in chunks:
        meta = chunk.metadata
        source_id = chunk.source_id or "unknown"
        title = str(meta.get("title", source_id))
        url = str(meta.get("url", ""))
        excerpt = _trim_excerpt(chunk.document.page_content)
        boost = " *(boosted)*" if chunk.boosted else ""
        if url:
            header = f"**{chunk.rank}. [{source_id}]({url})** — {title}{boost}"
        else:
            header = f"**{chunk.rank}. [{source_id}]** — {title}{boost}"
        parts.append(
            f"{header}\n\n"
            f"*distance: {chunk.score:.3f} (lower = better)*\n\n"
            f"{excerpt}\n\n"
        )
    return "".join(parts).rstrip()
