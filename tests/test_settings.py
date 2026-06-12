"""Settings deployment and Groq provider defaults."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from config.settings import (
    GROQ_DEFAULT_LLM_MODEL,
    DeploymentProfile,
    EmbeddingProvider,
    LLMProvider,
    Settings,
    get_settings,
    is_groq_chat_model,
)


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("llama-3.1-8b-instant", True),
        ("llama-3.3-70b-versatile", True),
        ("meta-llama/llama-4-scout-17b-16e-instruct", True),
        ("gemma3:4b", False),
        ("llama3.1:8b", False),
    ],
)
def test_is_groq_chat_model(model: str, expected: bool) -> None:
    assert is_groq_chat_model(model) is expected


def test_default_settings_target_cloud_deploy() -> None:
    settings = Settings(_env_file=None)
    assert settings.deployment_profile == DeploymentProfile.CLOUD
    assert settings.llm_provider == LLMProvider.GROQ
    assert settings.llm_model == GROQ_DEFAULT_LLM_MODEL
    assert settings.embedding_provider == EmbeddingProvider.HUGGINGFACE
    assert settings.llm_rewrite_followups is False


def test_cloud_profile_defaults_to_groq_and_hf() -> None:
    settings = Settings(
        deployment_profile=DeploymentProfile.CLOUD,
        llm_provider=LLMProvider.OLLAMA,
        embedding_provider=EmbeddingProvider.OLLAMA,
    )
    assert settings.llm_provider == LLMProvider.GROQ
    assert settings.llm_model == GROQ_DEFAULT_LLM_MODEL
    assert settings.embedding_provider == EmbeddingProvider.HUGGINGFACE
    assert settings.llm_rewrite_followups is False


def test_groq_provider_normalizes_ollama_model_name() -> None:
    settings = Settings(
        deployment_profile=DeploymentProfile.LOCAL,
        llm_provider=LLMProvider.GROQ,
        llm_model="gemma3:4b",
    )
    assert settings.llm_model == GROQ_DEFAULT_LLM_MODEL


def test_groq_provider_keeps_explicit_groq_model() -> None:
    settings = Settings(
        deployment_profile=DeploymentProfile.LOCAL,
        llm_provider=LLMProvider.GROQ,
        llm_model="llama-3.3-70b-versatile",
    )
    assert settings.llm_model == "llama-3.3-70b-versatile"


def test_llm_rewrite_followups_respects_explicit_env() -> None:
    with patch.dict(os.environ, {"LLM_REWRITE_FOLLOWUPS": "true"}, clear=False):
        settings = Settings(deployment_profile=DeploymentProfile.CLOUD)
    assert settings.llm_rewrite_followups is True


def test_get_settings_cache_can_be_cleared() -> None:
    get_settings.cache_clear()
    assert get_settings() is get_settings()
    get_settings.cache_clear()
