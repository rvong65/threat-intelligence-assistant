"""LLM factory for local (Ollama) and cloud (Groq) providers."""

from __future__ import annotations

import logging

from langchain_core.language_models import BaseChatModel

import os

from config.settings import LLMProvider, Settings, get_settings

logger = logging.getLogger(__name__)


def get_llm(settings: Settings | None = None) -> BaseChatModel:
    """
    Return a LangChain chat model based on configuration.

    Local default: Ollama gemma3:4b
    Cloud default: Groq llama-3.1-8b-instant (via apply_deployment_defaults)
    """
    settings = settings or get_settings()

    if settings.llm_provider == LLMProvider.OLLAMA:
        try:
            from langchain_ollama import ChatOllama
        except ImportError as exc:
            raise ImportError(
                "langchain-ollama is required for Ollama LLM."
            ) from exc

        logger.info(
            "Using Ollama LLM: model=%s base_url=%s",
            settings.llm_model,
            settings.ollama_base_url,
        )
        return ChatOllama(
            model=settings.llm_model,
            base_url=settings.ollama_base_url,
            temperature=0.1,
        )

    if settings.llm_provider == LLMProvider.GROQ:
        try:
            from langchain_groq import ChatGroq
        except ImportError as exc:
            raise ImportError(
                "langchain-groq is required for Groq LLM."
            ) from exc

        if not os.environ.get("GROQ_API_KEY"):
            raise ValueError(
                "GROQ_API_KEY is required when LLM_PROVIDER=groq. "
                "Set it in the environment or Streamlit Secrets."
            )

        logger.info("Using Groq LLM: model=%s", settings.llm_model)
        return ChatGroq(
            model=settings.llm_model,
            groq_api_key=os.environ.get("GROQ_API_KEY"),
            temperature=0.1,
        )

    if settings.llm_provider == LLMProvider.TOGETHER:
        try:
            from langchain_together import ChatTogether
        except ImportError as exc:
            raise ImportError(
                "langchain-together is required for Together LLM."
            ) from exc

        if not settings.together_api_key:
            raise ValueError("TOGETHER_API_KEY is required when LLM_PROVIDER=together.")

        logger.info("Using Together LLM: model=%s", settings.llm_model)
        return ChatTogether(
            model=settings.llm_model,
            together_api_key=settings.together_api_key,
            temperature=0.1,
        )

    raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")
