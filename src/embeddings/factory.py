"""Embedding model factory for local (Ollama) and API providers."""

from __future__ import annotations

import logging

from langchain_core.embeddings import Embeddings

from config.settings import EmbeddingProvider, Settings, get_settings

logger = logging.getLogger(__name__)


def get_embeddings(settings: Settings | None = None) -> Embeddings:
    """
    Return a LangChain Embeddings instance based on configuration.

    Local default: Ollama `nomic-embed-text`.
    Cloud deploys should pre-build the FAISS index locally and ship it in the repo.
    """
    settings = settings or get_settings()

    if settings.embedding_provider == EmbeddingProvider.OLLAMA:
        try:
            from langchain_ollama import OllamaEmbeddings
        except ImportError as exc:
            raise ImportError(
                "langchain-ollama is required for Ollama embeddings. "
                "Install with: pip install langchain-ollama"
            ) from exc

        logger.info(
            "Using Ollama embeddings: model=%s base_url=%s",
            settings.embedding_model,
            settings.ollama_base_url,
        )
        return OllamaEmbeddings(
            model=settings.embedding_model,
            base_url=settings.ollama_base_url,
        )

    if settings.embedding_provider == EmbeddingProvider.HUGGINGFACE:
        try:
            from langchain_huggingface import HuggingFaceEmbeddings
        except ImportError as exc:
            raise ImportError(
                "langchain-huggingface is required for HuggingFace embeddings. "
                "Install with: pip install langchain-huggingface sentence-transformers"
            ) from exc

        model_name = settings.huggingface_embedding_model
        revision = settings.huggingface_embedding_revision
        logger.info(
            "Using HuggingFace embeddings: model=%s revision=%s",
            model_name,
            revision,
        )
        return HuggingFaceEmbeddings(
            model_name=model_name,
            model_kwargs={
                "device": "cpu",
                "revision": revision,
                # nomic-embed-text-v1 ships custom architecture code on the Hub.
                "trust_remote_code": True,
            },
            encode_kwargs={"normalize_embeddings": True},
        )

    if settings.embedding_provider == EmbeddingProvider.OPENAI_COMPATIBLE:
        try:
            from langchain_openai import OpenAIEmbeddings
        except ImportError as exc:
            raise ImportError(
                "langchain-openai is required for openai_compatible embeddings."
            ) from exc

        logger.info("Using OpenAI-compatible embeddings: %s", settings.embedding_model)
        return OpenAIEmbeddings(model=settings.embedding_model)

    raise ValueError(f"Unsupported embedding provider: {settings.embedding_provider}")
