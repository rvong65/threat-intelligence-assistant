"""Semantic chunking with context prefixes for improved cyber-term retrieval."""

from __future__ import annotations

import logging

from src.models.document import ThreatDocument

logger = logging.getLogger(__name__)

# Maximum characters per chunk body (technique docs are usually single-chunk)
MAX_CHUNK_CHARS = 4000


def _mitre_context_prefix(doc: ThreatDocument) -> str:
    """Prefix MITRE chunks so embeddings capture IDs, tactics, and platforms."""
    citation = doc.citation
    tactic_str = ", ".join(citation.tactics) if citation.tactics else "Unknown"
    platform_str = ", ".join(citation.platforms) if citation.platforms else "Unknown"
    kind = "Sub-technique" if citation.extra.get("is_subtechnique") else "Technique"
    return (
        f"MITRE ATT&CK {kind} {doc.source_id} {doc.title.split(':', 1)[-1].strip()} "
        f"| Tactic: {tactic_str} | Platforms: {platform_str} | "
    )


def _kev_context_prefix(doc: ThreatDocument) -> str:
    """Prefix KEV chunks with CVE and vendor/product for filter-friendly retrieval."""
    vendor = doc.citation.vendor or "Unknown vendor"
    product = doc.citation.product or "Unknown product"
    return (
        f"CISA KEV {doc.source_id} {doc.title} "
        f"| Vendor: {vendor} | Product: {product} | "
    )


def _split_long_text(text: str, max_chars: int) -> list[str]:
    """Split on paragraph boundaries when content exceeds max_chars."""
    if len(text) <= max_chars:
        return [text]

    paragraphs = text.split("\n\n")
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        if current_len + len(para) + 2 > max_chars and current:
            chunks.append("\n\n".join(current))
            current = [para]
            current_len = len(para)
        else:
            current.append(para)
            current_len += len(para) + 2

    if current:
        chunks.append("\n\n".join(current))
    return chunks or [text[:max_chars]]


def chunk_documents(documents: list[ThreatDocument]) -> list[ThreatDocument]:
    """
    Produce embeddable chunks while preserving citation metadata.

    MITRE techniques and most KEV rows become a single chunk with a context prefix.
    """
    chunked: list[ThreatDocument] = []

    for doc in documents:
        if doc.source_type == "mitre_attack":
            prefix = _mitre_context_prefix(doc)
        elif doc.source_type == "mitre_group":
            prefix = f"MITRE ATT&CK Group {doc.source_id} {doc.title} | "
        elif doc.source_type == "mitre_software":
            prefix = f"MITRE ATT&CK Software {doc.source_id} {doc.title} | "
        elif doc.source_type == "nvd_cve":
            prefix = f"NVD CVE {doc.source_id} {doc.title} | "
        else:
            prefix = _kev_context_prefix(doc)

        body_chunks = _split_long_text(doc.content, MAX_CHUNK_CHARS)

        for index, body in enumerate(body_chunks):
            chunk_id = (
                f"{doc.source_id}"
                if len(body_chunks) == 1
                else f"{doc.source_id}__chunk_{index}"
            )
            chunked.append(
                ThreatDocument(
                    source_id=doc.source_id,
                    source_type=doc.source_type,
                    title=doc.title,
                    content=prefix + body,
                    citation=doc.citation,
                    chunk_id=chunk_id,
                )
            )

    logger.info("Chunking: %d source docs -> %d chunks", len(documents), len(chunked))
    return chunked
