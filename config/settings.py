"""Application settings loaded from environment variables and Streamlit secrets."""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Default chat models per provider (Groq uses API model IDs, not Ollama tags).
OLLAMA_DEFAULT_LLM_MODEL = "gemma3:4b"
GROQ_DEFAULT_LLM_MODEL = "llama-3.1-8b-instant"
# Pin HF embed model to a fixed commit (avoids re-downloading new remote code).
HUGGINGFACE_NOMIC_EMBED_REVISION = "3ac47f125a41961d13b397d0332866be2f9152e1"


def is_groq_chat_model(model: str) -> bool:
    """Return True if *model* looks like a Groq-hosted chat model ID."""
    normalized = model.strip().lower()
    if not normalized:
        return False
    if normalized in {GROQ_DEFAULT_LLM_MODEL, "llama-3.3-70b-versatile"}:
        return True
    return (
        "instant" in normalized
        or "versatile" in normalized
        or normalized.startswith("meta-llama/")
        or normalized.startswith("openai/")
        or normalized.startswith("qwen/")
    )


class DeploymentProfile(str, Enum):
    LOCAL = "local"
    CLOUD = "cloud"


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    GROQ = "groq"
    TOGETHER = "together"
    FIREWORKS = "fireworks"


class EmbeddingProvider(str, Enum):
    OLLAMA = "ollama"
    HUGGINGFACE = "huggingface"
    OPENAI_COMPATIBLE = "openai_compatible"


class VectorStoreBackend(str, Enum):
    FAISS = "faiss"
    CHROMA = "chroma"  # Local development only — not recommended for Streamlit Cloud


class Settings(BaseSettings):
    """Central configuration for ingestion, retrieval, and deployment."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Deployment
    deployment_profile: DeploymentProfile = DeploymentProfile.LOCAL

    # LLM
    llm_provider: LLMProvider = LLMProvider.OLLAMA
    llm_model: str = OLLAMA_DEFAULT_LLM_MODEL
    together_api_key: str = ""
    fireworks_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"

    # Embeddings
    embedding_provider: EmbeddingProvider = EmbeddingProvider.OLLAMA
    embedding_model: str = "nomic-embed-text"
    huggingface_embedding_model: str = "nomic-ai/nomic-embed-text-v1"
    huggingface_embedding_revision: str = HUGGINGFACE_NOMIC_EMBED_REVISION

    # Conversational memory
    memory_max_turns: int = Field(default=3, ge=1, le=10)

    # Vector store
    vectorstore_backend: VectorStoreBackend = VectorStoreBackend.FAISS

    # Retrieval / responsible-AI thresholds
    retrieval_top_k: int = Field(default=5, ge=1, le=20)
    confidence_threshold: int = Field(default=40, ge=0, le=100)
    hard_abstention_enabled: bool = Field(default=True, validation_alias="HARD_ABSTENTION_ENABLED")
    llm_rewrite_followups: bool = Field(default=True, validation_alias="LLM_REWRITE_FOLLOWUPS")
    include_groups_software: bool = Field(default=True, validation_alias="INCLUDE_GROUPS_SOFTWARE")
    nvd_enrich_limit: int = Field(default=100, ge=0, le=2000)
    ingest_batch_size: int = Field(default=32, ge=1, le=256)

    # Paths
    data_raw_dir: Path = Field(default=PROJECT_ROOT / "data" / "raw")
    data_processed_dir: Path = Field(default=PROJECT_ROOT / "data" / "processed")
    indices_dir: Path = Field(default=PROJECT_ROOT / "indices" / "faiss_index")

    # Dataset filenames
    mitre_filename: str = "enterprise-attack.json"
    kev_filename: str = "known_exploited_vulnerabilities.csv"

    # Public download URLs (used by ingest.py when raw files are missing)
    mitre_download_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    kev_download_url: str = (
        "https://www.cisa.gov/sites/default/files/csv/"
        "known_exploited_vulnerabilities.csv"
    )

    # Corpus manifest
    corpus_version: str = "1.0.0"

    @field_validator("data_raw_dir", "data_processed_dir", "indices_dir", mode="before")
    @classmethod
    def resolve_paths(cls, value: str | Path) -> Path:
        path = Path(value)
        if not path.is_absolute():
            return PROJECT_ROOT / path
        return path

    @property
    def mitre_path(self) -> Path:
        return self.data_raw_dir / self.mitre_filename

    @property
    def kev_path(self) -> Path:
        return self.data_raw_dir / self.kev_filename

    @property
    def documents_jsonl_path(self) -> Path:
        return self.data_processed_dir / "documents.jsonl"

    @property
    def manifest_path(self) -> Path:
        return self.indices_dir / "manifest.json"

    @property
    def nvd_cache_path(self) -> Path:
        return self.data_processed_dir / "nvd_cache.json"

    @model_validator(mode="after")
    def apply_deployment_defaults(self) -> Settings:
        """Apply cloud profile defaults and Groq provider model normalization."""
        if self.deployment_profile == DeploymentProfile.CLOUD:
            if self.llm_provider == LLMProvider.OLLAMA:
                self.llm_provider = LLMProvider.GROQ
            if self.embedding_provider == EmbeddingProvider.OLLAMA:
                self.embedding_provider = EmbeddingProvider.HUGGINGFACE
            if "LLM_REWRITE_FOLLOWUPS" not in os.environ:
                self.llm_rewrite_followups = False

        if self.llm_provider == LLMProvider.GROQ and not is_groq_chat_model(
            self.llm_model
        ):
            self.llm_model = GROQ_DEFAULT_LLM_MODEL

        return self

    def is_cloud(self) -> bool:
        return self.deployment_profile == DeploymentProfile.CLOUD

    def uses_groq_llm(self) -> bool:
        return self.llm_provider == LLMProvider.GROQ

    def effective_embedding_model_name(self) -> str:
        """Return the model identifier used by the active embedding provider."""
        if self.embedding_provider == EmbeddingProvider.HUGGINGFACE:
            return self.huggingface_embedding_model
        return self.embedding_model

    def validate_runtime(self) -> list[str]:
        """Return human-readable configuration warnings (non-fatal)."""
        warnings: list[str] = []

        if self.is_cloud():
            if self.llm_provider == LLMProvider.OLLAMA:
                warnings.append(
                    "Cloud profile with Ollama LLM — switch LLM_PROVIDER to groq."
                )
            if self.vectorstore_backend == VectorStoreBackend.CHROMA:
                warnings.append(
                    "Chroma is not recommended on Streamlit Cloud; use faiss."
                )
        if self.uses_groq_llm() and not groq_api_key_configured():
            warnings.append(
                "GROQ_API_KEY is not set — Groq requests will fail until you add it "
                "to your environment or Streamlit Secrets."
            )

        if self.embedding_provider == EmbeddingProvider.OLLAMA and not self.is_cloud():
            warnings.append(
                "Local embeddings require Ollama with model: "
                f"{self.embedding_model}"
            )

        if self.embedding_provider == EmbeddingProvider.HUGGINGFACE:
            warnings.append(
                "HuggingFace embeddings load on first query (cold start may be slow)."
            )

        return warnings


def _flatten_secrets(obj: object, prefix: str = "") -> dict[str, str]:
    """Flatten nested Streamlit secrets TOML into ENV-style keys."""
    flat: dict[str, str] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{prefix}_{key}" if prefix else str(key)
            flat.update(_flatten_secrets(value, full_key))
    elif isinstance(obj, str):
        if prefix:
            flat[prefix.upper()] = obj
    return flat


def groq_api_key_configured() -> bool:
    """Return True if GROQ_API_KEY is set in the environment (value never read elsewhere)."""
    return bool(os.environ.get("GROQ_API_KEY"))


def load_streamlit_secrets_into_env() -> None:
    """Overlay Streamlit secrets into os.environ when running on Streamlit Cloud."""
    try:
        import os

        import streamlit as st

        if hasattr(st, "secrets") and st.secrets:
            for key, value in _flatten_secrets(dict(st.secrets)).items():
                os.environ.setdefault(key, value)
    except Exception:
        # Not running inside Streamlit or secrets unavailable.
        pass


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    load_streamlit_secrets_into_env()
    return Settings()
