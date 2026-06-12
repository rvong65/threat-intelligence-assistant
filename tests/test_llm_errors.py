"""Tests for LLM error mapping (no live API calls)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.llm.errors import LLMUserError, map_llm_exception


class _FakeRateLimitError(Exception):
    status_code = 429


class _FakeAuthError(Exception):
    pass


class _FakeConnectionError(Exception):
    pass


class _FakeServerError(Exception):
    status_code = 503


def test_map_rate_limit_by_status_code() -> None:
    err = map_llm_exception(_FakeRateLimitError("too many"))
    assert err.is_rate_limit
    assert "rate limit" in err.user_message.lower()


def test_map_generic_exception() -> None:
    err = map_llm_exception(RuntimeError("boom"))
    assert "Could not generate" in err.user_message


def test_llm_user_error_passthrough() -> None:
    original = LLMUserError("custom", is_rate_limit=True)
    assert map_llm_exception(original) is original


def _groq_error(groq_module, error_cls: type, message: str) -> Exception:
    response = MagicMock()
    response.request = MagicMock()
    return error_cls(message, response=response, body=None)


def test_groq_rate_limit_type_when_available() -> None:
    groq = pytest.importorskip("groq")
    err = map_llm_exception(_groq_error(groq, groq.RateLimitError, "limited"))
    assert err.is_rate_limit


def test_groq_auth_error_when_available() -> None:
    groq = pytest.importorskip("groq")
    err = map_llm_exception(
        _groq_error(groq, groq.AuthenticationError, "bad key")
    )
    assert err.is_auth_error
