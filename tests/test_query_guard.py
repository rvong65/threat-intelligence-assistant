"""Tests for out-of-scope query guard."""

from __future__ import annotations

from src.rag.query_guard import is_threat_intel_query


def test_greeting_blocked() -> None:
    assert is_threat_intel_query("Hi") is False
    assert is_threat_intel_query("Hello!") is False
    assert is_threat_intel_query("How are you?") is False


def test_technique_query_allowed() -> None:
    assert is_threat_intel_query("How is T1059 used?") is True


def test_software_id_query_allowed() -> None:
    assert is_threat_intel_query("What is S0002?") is True


def test_group_id_query_allowed() -> None:
    assert is_threat_intel_query("What techniques does G0007 use?") is True


def test_weather_blocked() -> None:
    assert is_threat_intel_query("What is the weather in Tokyo?") is False


def test_intel_keywords_allowed() -> None:
    assert is_threat_intel_query("Recent exploited CVEs affecting Windows?") is True


def test_vague_attacks_blocked() -> None:
    assert is_threat_intel_query("Tell me about attacks") is False
