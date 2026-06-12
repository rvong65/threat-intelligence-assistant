"""Map LLM provider exceptions to user-safe messages."""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMUserError(Exception):
    """Raised when the LLM provider fails; carries a safe message for the UI."""

    user_message: str
    is_rate_limit: bool = False
    is_auth_error: bool = False

    def __str__(self) -> str:
        return self.user_message


def map_llm_exception(exc: BaseException) -> LLMUserError:
    """Convert provider/SDK errors into LLMUserError (no stack traces in UI)."""
    try:
        from groq import APIConnectionError, APIStatusError, AuthenticationError, RateLimitError
    except ImportError:
        RateLimitError = AuthenticationError = APIConnectionError = APIStatusError = ()  # type: ignore

    if isinstance(exc, LLMUserError):
        return exc

    if isinstance(exc, RateLimitError):
        return LLMUserError(
            user_message=(
                "**Groq rate limit reached.** Wait a moment and try again."
            ),
            is_rate_limit=True,
        )

    if isinstance(exc, AuthenticationError):
        return LLMUserError(
            user_message=(
                "**The service could not authenticate with Groq.** "
                "Please try again later."
            ),
            is_auth_error=True,
        )

    if isinstance(exc, APIConnectionError):
        return LLMUserError(
            user_message=(
                "**Cannot reach Groq.** Check your network connection and try again."
            ),
        )

    if isinstance(exc, APIStatusError) and getattr(exc, "status_code", 0) >= 500:
        return LLMUserError(
            user_message=(
                "**Groq is temporarily unavailable.** Please try again in a few moments."
            ),
        )

    status_code = getattr(exc, "status_code", None)
    if status_code == 429:
        return LLMUserError(
            user_message=(
                "**Groq rate limit reached.** Wait a minute and try again."
            ),
            is_rate_limit=True,
        )

    logger.exception("Unhandled LLM error")
    return LLMUserError(
        user_message=(
            "**Could not generate an answer.** The language model returned an error. "
            "Please try again."
        ),
    )


def invoke_llm(llm, messages):
    """Invoke an LLM and map failures to LLMUserError."""
    try:
        return llm.invoke(messages)
    except Exception as exc:
        raise map_llm_exception(exc) from exc
