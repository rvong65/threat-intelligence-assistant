"""FAISS retriever with metadata boosting for technique and CVE identifiers."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document

from config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
GROUP_PATTERN = re.compile(r"\bG\d{4}\b", re.IGNORECASE)
SOFTWARE_PATTERN = re.compile(r"\bS\d{4}\b", re.IGNORECASE)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Lower distance = better match for FAISS L2.
ENTITY_BOOST = 0.35
METADATA_BOOST = 0.25
KEV_SOURCE_BOOST = 0.45

KEV_QUERY_KEYWORDS = ("cve", "exploited", "vulnerability", "kev", "ransomware", "patch")

# Keywords that trigger metadata-aware re-ranking.
METADATA_KEYWORDS = (
    "windows",
    "linux",
    "macos",
    "ransomware",
    "microsoft",
    "cisco",
    "vmware",
)


@dataclass
class RetrievedChunk:
    """One retrieved document with similarity metadata."""

    document: Document
    score: float
    rank: int
    boosted: bool = False

    @property
    def source_id(self) -> str:
        return str(self.document.metadata.get("source_id", ""))

    @property
    def metadata(self) -> dict:
        return self.document.metadata


def is_kev_query(query: str) -> bool:
    """Detect vulnerability/KEV-oriented questions."""
    lower = query.lower()
    return any(kw in lower for kw in KEV_QUERY_KEYWORDS)


def extract_metadata_keywords(query: str) -> list[str]:
    """Extract platform/vendor keywords for metadata-aware re-ranking."""
    lower = query.lower()
    return [kw for kw in METADATA_KEYWORDS if kw in lower]


def _metadata_match(document: Document, keywords: list[str]) -> bool:
    if not keywords:
        return False
    meta = document.metadata
    vendor = str(meta.get("vendor") or "").lower()
    product = str(meta.get("product") or "").lower()
    platforms = [str(p).lower() for p in meta.get("platforms", [])]
    content = document.page_content.lower()
    haystack = " ".join([vendor, product, content, *platforms])
    return any(kw in haystack for kw in keywords)


def extract_entity_ids(query: str) -> tuple[list[str], list[str], list[str], list[str]]:
    """Extract MITRE technique, group, software, and CVE IDs from a query."""
    techniques = [m.upper() for m in TECHNIQUE_PATTERN.findall(query)]
    groups = [m.upper() for m in GROUP_PATTERN.findall(query)]
    software = [m.upper() for m in SOFTWARE_PATTERN.findall(query)]
    cves = [m.upper() for m in CVE_PATTERN.findall(query)]
    return techniques, groups, software, cves


def _is_entity_match(
    source_id: str,
    techniques: list[str],
    groups: list[str],
    software: list[str],
    cves: list[str],
) -> bool:
    source_upper = source_id.upper()
    for tech in techniques:
        if source_upper == tech or source_upper.startswith(f"{tech}."):
            return True
    for group in groups:
        if source_upper == group:
            return True
    for sw in software:
        if source_upper == sw:
            return True
    for cve in cves:
        if source_upper == cve:
            return True
    return False


def _apply_entity_boost(
    results: list[tuple[Document, float]],
    techniques: list[str],
    groups: list[str],
    software: list[str],
    cves: list[str],
    metadata_keywords: list[str],
    kev_query: bool,
) -> list[tuple[Document, float, bool]]:
    """Reduce score (improve rank) on entity ID or metadata keyword matches."""
    boosted: list[tuple[Document, float, bool]] = []
    for doc, score in results:
        source_id = str(doc.metadata.get("source_id", ""))
        source_type = str(doc.metadata.get("source_type", ""))
        entity_hit = _is_entity_match(source_id, techniques, groups, software, cves)
        metadata_hit = _metadata_match(doc, metadata_keywords)
        kev_hit = kev_query and source_type == "cisa_kev"
        adjusted = score
        if entity_hit:
            adjusted -= ENTITY_BOOST
        if metadata_hit:
            adjusted -= METADATA_BOOST
        if kev_hit:
            adjusted -= KEV_SOURCE_BOOST
        boosted.append((doc, adjusted, entity_hit or metadata_hit or kev_hit))
    boosted.sort(key=lambda item: item[1])
    return boosted


def _lookup_entity_documents(
    vectorstore: FAISS,
    techniques: list[str],
    groups: list[str],
    software: list[str],
    cves: list[str],
) -> list[Document]:
    """Direct docstore lookup when the query names explicit MITRE/CVE IDs."""
    if not (techniques or groups or software or cves):
        return []

    exact_ids = {g.upper() for g in groups} | {s.upper() for s in software} | {c.upper() for c in cves}
    technique_roots = [t.upper() for t in techniques]
    matches: list[Document] = []
    seen: set[str] = set()

    for doc in vectorstore.docstore._dict.values():
        source_id = str(doc.metadata.get("source_id", "")).upper()
        if not source_id or source_id in seen:
            continue

        matched = source_id in exact_ids
        if not matched:
            for tech in technique_roots:
                if source_id == tech or source_id.startswith(f"{tech}."):
                    matched = True
                    break

        if matched:
            seen.add(source_id)
            matches.append(doc)

    return matches


def _inject_entity_matches(
    raw_results: list[tuple[Document, float]],
    entity_docs: list[Document],
) -> list[tuple[Document, float]]:
    """Prepend exact ID matches with the best possible score."""
    if not entity_docs:
        return raw_results

    seen = {id(doc) for doc in entity_docs}
    injected = [(doc, 0.0) for doc in entity_docs]
    remainder = [(doc, score) for doc, score in raw_results if id(doc) not in seen]
    return injected + remainder


def _prioritize_kev_results(
    ranked: list[tuple[Document, float, bool]],
    top_k: int,
    min_kev: int = 3,
) -> list[tuple[Document, float, bool]]:
    """Ensure KEV documents appear when the query is vulnerability-oriented."""
    kev_items = [
        item for item in ranked if item[0].metadata.get("source_type") == "cisa_kev"
    ]
    if not kev_items:
        return ranked

    selected_kev = kev_items[:min_kev]
    selected_ids = {id(item[0]) for item in selected_kev}
    remainder = [item for item in ranked if id(item[0]) not in selected_ids]
    return (selected_kev + remainder)[: max(top_k, len(selected_kev))]


def retrieve(
    vectorstore: FAISS,
    query: str,
    settings: Settings | None = None,
) -> list[RetrievedChunk]:
    """
    Run similarity search with optional metadata boosting.

    Fetches extra candidates when entity IDs are present, then re-ranks.
    """
    settings = settings or get_settings()
    techniques, groups, software, cves = extract_entity_ids(query)
    metadata_keywords = extract_metadata_keywords(query)
    kev_query = is_kev_query(query)
    entity_lookup = bool(techniques or groups or software or cves)
    needs_extra = bool(entity_lookup or metadata_keywords or kev_query)
    # KEV and explicit-ID queries need a wide pool — MITRE/KEV chunks are often
    # semantically distant from natural-language questions in embedding space.
    if kev_query or entity_lookup:
        fetch_k = max(100, settings.retrieval_top_k * 10)
    elif needs_extra:
        fetch_k = settings.retrieval_top_k * 2
    else:
        fetch_k = settings.retrieval_top_k

    raw_results = vectorstore.similarity_search_with_score(query, k=fetch_k)

    entity_docs = _lookup_entity_documents(
        vectorstore, techniques, groups, software, cves
    )
    if entity_docs:
        raw_results = _inject_entity_matches(raw_results, entity_docs)

    if kev_query:
        kev_filtered = [
            (doc, score)
            for doc, score in raw_results
            if doc.metadata.get("source_type") == "cisa_kev"
        ]
        if kev_filtered:
            seen = {id(doc) for doc, _ in kev_filtered}
            raw_results = kev_filtered + [
                (doc, score) for doc, score in raw_results if id(doc) not in seen
            ]

    ranked = _apply_entity_boost(
        raw_results, techniques, groups, software, cves, metadata_keywords, kev_query
    )

    if kev_query:
        ranked = _prioritize_kev_results(ranked, settings.retrieval_top_k)

    chunks: list[RetrievedChunk] = []
    for rank, (doc, score, boosted) in enumerate(ranked[: settings.retrieval_top_k], start=1):
        chunks.append(
            RetrievedChunk(
                document=doc,
                score=score,
                rank=rank,
                boosted=boosted,
            )
        )

    if techniques or groups or software or cves or metadata_keywords:
        logger.debug(
            "Retrieval boost applied for techniques=%s groups=%s software=%s "
            "cves=%s keywords=%s",
            techniques,
            groups,
            software,
            cves,
            metadata_keywords,
        )
    return chunks
