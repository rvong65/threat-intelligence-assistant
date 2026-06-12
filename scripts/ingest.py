#!/usr/bin/env python3
"""
Ingestion CLI for the Threat Intelligence Assistant.

Usage:
    python scripts/ingest.py --validate-only
    python scripts/ingest.py --build-index
    python scripts/ingest.py --build-index --test-query "How is T1059 used?"
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

import requests

# Ensure project root is on sys.path when running as a script.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import Settings, get_settings
from src.embeddings.factory import get_embeddings
from src.ingestion.chunking import chunk_documents
from src.ingestion.normalize import load_all_documents, save_documents_jsonl
from src.vectorstore.factory import build_faiss_index, save_vectorstore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("ingest")


def download_file(url: str, destination: Path, timeout: int = 120) -> None:
    """Download a dataset file if missing from data/raw/."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading %s -> %s", url, destination)

    response = requests.get(url, timeout=timeout, stream=True)
    response.raise_for_status()

    with destination.open("wb") as handle:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                handle.write(chunk)

    logger.info("Download complete (%s bytes)", destination.stat().st_size)


def ensure_datasets(settings: Settings) -> None:
    """Download MITRE + KEV files when not present locally."""
    datasets = [
        (settings.mitre_path, settings.mitre_download_url, "MITRE ATT&CK"),
        (settings.kev_path, settings.kev_download_url, "CISA KEV"),
    ]

    for path, url, label in datasets:
        if path.exists():
            logger.info("%s found: %s", label, path)
            continue
        logger.warning("%s missing — downloading...", label)
        try:
            download_file(url, path)
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Failed to download {label} from {url}. "
                f"Place the file manually at {path}."
            ) from exc


def run_validate(
    settings: Settings,
    *,
    enrich_nvd: bool = False,
) -> dict[str, int]:
    """Load and validate sources without building embeddings."""
    ensure_datasets(settings)
    documents = load_all_documents(
        settings,
        include_groups_software=settings.include_groups_software,
        enrich_nvd=enrich_nvd,
    )
    counts = Counter(doc.source_type for doc in documents)
    chunked = chunk_documents(documents)
    save_documents_jsonl(documents, settings=settings)

    print("\n=== Validation Summary ===")
    print(f"MITRE techniques : {counts.get('mitre_attack', 0)}")
    print(f"MITRE groups     : {counts.get('mitre_group', 0)}")
    print(f"MITRE software   : {counts.get('mitre_software', 0)}")
    print(f"CISA KEV entries : {counts.get('cisa_kev', 0)}")
    print(f"NVD CVE records  : {counts.get('nvd_cve', 0)}")
    print(f"Total documents  : {len(documents)}")
    print(f"Total chunks     : {len(chunked)}")
    print(f"JSONL output     : {settings.documents_jsonl_path}")
    return dict(counts)


def run_build_index(
    settings: Settings,
    test_query: str | None,
    *,
    enrich_nvd: bool = False,
) -> None:
    """Full pipeline: load, chunk, embed, persist FAISS, optional test query."""
    counts = run_validate(settings, enrich_nvd=enrich_nvd)
    documents = load_all_documents(
        settings,
        include_groups_software=settings.include_groups_software,
        enrich_nvd=enrich_nvd,
    )
    chunked = chunk_documents(documents)

    try:
        embeddings = get_embeddings(settings)
    except Exception as exc:
        logger.error("Embedding initialization failed: %s", exc)
        print(
            "\nHint: For local ingestion, ensure Ollama is running and pull the model:\n"
            "  ollama pull nomic-embed-text\n"
            "  ollama pull gemma3:4b     # local chat model\n"
        )
        raise

    print(
        f"\nEmbedding {len(chunked)} chunks in batches of "
        f"{settings.ingest_batch_size} (close Streamlit/other Ollama apps first)..."
    )
    vectorstore = build_faiss_index(
        chunked, embeddings, batch_size=settings.ingest_batch_size
    )
    save_vectorstore(
        vectorstore,
        settings=settings,
        extra_manifest={
            "document_count": len(documents),
            "chunk_count": len(chunked),
            "source_counts": dict(counts),
        },
    )

    print("\n=== Index Build Complete ===")
    print(f"FAISS index : {settings.indices_dir}")
    print(f"Manifest    : {settings.manifest_path}")

    query = test_query or "How is T1059 used?"
    print(f"\n=== Test Query: {query!r} ===")
    results = vectorstore.similarity_search_with_score(query, k=3)
    for rank, (doc, score) in enumerate(results, start=1):
        meta = doc.metadata
        print(
            f"\n{rank}. score={score:.4f} | "
            f"{meta.get('source_id')} | {meta.get('title')}"
        )
        print(f"   URL: {meta.get('url')}")
        preview = doc.page_content[:220].replace("\n", " ")
        print(f"   Preview: {preview}...")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Assistant — data ingestion CLI",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--validate-only",
        action="store_true",
        help="Parse and validate datasets; write documents.jsonl without embeddings.",
    )
    group.add_argument(
        "--build-index",
        action="store_true",
        help="Full ingest: validate, embed, and persist FAISS index.",
    )
    parser.add_argument(
        "--test-query",
        type=str,
        default=None,
        help="Similarity search query after index build (default: 'How is T1059 used?').",
    )
    parser.add_argument(
        "--enrich-nvd",
        action="store_true",
        help="Fetch NVD JSON for KEV CVEs (cached; respects --nvd-limit).",
    )
    parser.add_argument(
        "--nvd-limit",
        type=int,
        default=None,
        help="Max NVD CVE fetches per run (default: settings.nvd_enrich_limit).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = get_settings()

    for warning in settings.validate_runtime():
        logger.warning("Config: %s", warning)

    if args.nvd_limit is not None:
        settings = settings.model_copy(update={"nvd_enrich_limit": args.nvd_limit})

    if args.validate_only:
        run_validate(settings, enrich_nvd=args.enrich_nvd)
    elif args.build_index:
        run_build_index(settings, args.test_query, enrich_nvd=args.enrich_nvd)


if __name__ == "__main__":
    main()
