"""Normalize raw sources into a unified ThreatDocument corpus."""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path

from config.settings import Settings, get_settings
from src.loaders.cisa_kev import load_cisa_kev
from src.loaders.mitre_attack import load_mitre_attack
from src.loaders.mitre_groups_software import load_mitre_groups_software
from src.loaders.nvd_cve import load_nvd_for_cve_ids
from src.models.document import ThreatDocument

logger = logging.getLogger(__name__)


def load_all_documents(
    settings: Settings | None = None,
    *,
    include_groups_software: bool = True,
    enrich_nvd: bool = False,
) -> list[ThreatDocument]:
    """Load and merge MITRE ATT&CK, groups/software, KEV, and optional NVD enrichment."""
    settings = settings or get_settings()

    mitre_docs = load_mitre_attack(settings.mitre_path)
    kev_docs = load_cisa_kev(settings.kev_path)
    all_docs: list[ThreatDocument] = mitre_docs + kev_docs

    if include_groups_software:
        all_docs.extend(load_mitre_groups_software(settings.mitre_path))

    if enrich_nvd:
        cve_ids = [doc.source_id for doc in kev_docs if doc.source_id.startswith("CVE-")]
        nvd_docs = load_nvd_for_cve_ids(
            cve_ids,
            settings.nvd_cache_path,
            limit=settings.nvd_enrich_limit,
        )
        all_docs.extend(nvd_docs)
    counts = Counter(doc.source_type for doc in all_docs)
    logger.info(
        "Normalized corpus: %d total (%s)",
        len(all_docs),
        ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
    )
    return all_docs


def save_documents_jsonl(
    documents: list[ThreatDocument],
    path: Path | None = None,
    settings: Settings | None = None,
) -> Path:
    """Persist normalized documents as JSONL for reproducible re-indexing."""
    settings = settings or get_settings()
    path = path or settings.documents_jsonl_path
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as handle:
        for doc in documents:
            handle.write(doc.model_dump_json())
            handle.write("\n")

    logger.info("Wrote %d documents to %s", len(documents), path)
    return path


def load_documents_jsonl(path: Path) -> list[ThreatDocument]:
    """Load previously normalized documents from JSONL."""
    documents: list[ThreatDocument] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                documents.append(ThreatDocument.model_validate(json.loads(line)))
    return documents
