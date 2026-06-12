"""Vector store factory — FAISS default (cloud-safe), Chroma optional for local dev."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import VectorStore

from config.settings import Settings, VectorStoreBackend, get_settings
from src.models.document import ThreatDocument

logger = logging.getLogger(__name__)


def _to_langchain_documents(documents: list[ThreatDocument]) -> list[Document]:
    return [
        Document(page_content=doc.content, metadata=doc.to_langchain_metadata())
        for doc in documents
    ]


def build_faiss_index(
    documents: list[ThreatDocument],
    embeddings: Embeddings,
    *,
    batch_size: int | None = None,
) -> FAISS:
    """Build an in-memory FAISS index from chunked ThreatDocuments."""
    settings = get_settings()
    batch_size = batch_size or settings.ingest_batch_size
    lc_docs = _to_langchain_documents(documents)
    total = len(lc_docs)
    if total == 0:
        raise ValueError("No documents to index")

    logger.info(
        "Building FAISS index over %d chunks (batch_size=%d)...",
        total,
        batch_size,
    )

    # Embed in small batches — Ollama's llama-server can crash when thousands of
    # texts are tokenized/embedded in a single client call on Windows.
    vectorstore = FAISS.from_documents(lc_docs[:batch_size], embeddings)
    embedded = batch_size
    while embedded < total:
        end = min(embedded + batch_size, total)
        vectorstore.add_documents(lc_docs[embedded:end])
        embedded = end
        logger.info("Embedded %d / %d chunks", embedded, total)

    return vectorstore


def save_vectorstore(
    vectorstore: FAISS,
    settings: Settings | None = None,
    extra_manifest: dict[str, Any] | None = None,
) -> Path:
    """Persist FAISS index and write a manifest for reproducibility."""
    settings = settings or get_settings()
    index_dir = settings.indices_dir
    index_dir.mkdir(parents=True, exist_ok=True)

    vectorstore.save_local(str(index_dir))
    logger.info("Saved FAISS index to %s", index_dir)

    manifest: dict[str, Any] = {
        "corpus_version": settings.corpus_version,
        "vectorstore_backend": settings.vectorstore_backend.value,
        "embedding_model": settings.embedding_model,
        "embedding_provider": settings.embedding_provider.value,
        "document_count": extra_manifest.get("document_count") if extra_manifest else None,
        "chunk_count": extra_manifest.get("chunk_count") if extra_manifest else None,
        "source_counts": extra_manifest.get("source_counts") if extra_manifest else {},
        "built_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra_manifest:
        manifest.update({k: v for k, v in extra_manifest.items() if k not in manifest})

    manifest_path = settings.manifest_path
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info("Wrote manifest to %s", manifest_path)
    return index_dir


def load_vectorstore(
    embeddings: Embeddings,
    settings: Settings | None = None,
) -> FAISS:
    """Load a persisted FAISS index from disk."""
    settings = settings or get_settings()
    index_dir = settings.indices_dir

    if not index_dir.exists():
        raise FileNotFoundError(
            f"FAISS index not found at {index_dir}. "
            "Run: python scripts/ingest.py --build-index"
        )

    logger.info("Loading FAISS index from %s", index_dir)
    return FAISS.load_local(
        str(index_dir),
        embeddings,
        allow_dangerous_deserialization=True,
    )


def get_vectorstore(
    documents: list[ThreatDocument] | None,
    embeddings: Embeddings,
    settings: Settings | None = None,
) -> VectorStore:
    """
    Build or load a vector store based on backend setting.

    FAISS is the default and recommended for Streamlit Cloud.
    """
    settings = settings or get_settings()

    if settings.vectorstore_backend == VectorStoreBackend.FAISS:
        if documents:
            return build_faiss_index(documents, embeddings)
        return load_vectorstore(embeddings, settings)

    if settings.vectorstore_backend == VectorStoreBackend.CHROMA:
        # ------------------------------------------------------------------
        # Optional local-only backend. Avoid on Streamlit Cloud (SQLite issues).
        # ------------------------------------------------------------------
        try:
            from langchain_community.vectorstores import Chroma
        except ImportError as exc:
            raise ImportError(
                "chromadb is required for Chroma backend. "
                "Uncomment chromadb in requirements.txt and pip install."
            ) from exc

        persist_dir = settings.indices_dir.parent / "chroma_db"
        lc_docs = _to_langchain_documents(documents or [])
        logger.info("Building Chroma index at %s (%d chunks)", persist_dir, len(lc_docs))
        return Chroma.from_documents(
            lc_docs,
            embeddings,
            persist_directory=str(persist_dir),
        )

    raise ValueError(f"Unsupported vector store backend: {settings.vectorstore_backend}")
