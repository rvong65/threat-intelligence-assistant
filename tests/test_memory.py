"""Tests for conversational memory."""

from __future__ import annotations

from src.rag.memory import ConversationMemory, rewrite_followup


def test_memory_keeps_max_turns() -> None:
    memory = ConversationMemory(max_turns=2)
    memory.add("Q1", "A1")
    memory.add("Q2", "A2")
    memory.add("Q3", "A3")
    assert len(memory.turns) == 2
    assert memory.turns[0].question == "Q2"


def test_rewrite_skips_greeting_even_with_history() -> None:
    from src.rag.memory import rewrite_followup

    memory = ConversationMemory()
    memory.add("How is T1059 used?", "T1059 is used for execution.")
    assert rewrite_followup("Hi", memory) == "Hi"


def test_rewrite_followup_expands_short_query() -> None:
    memory = ConversationMemory()
    memory.add("How is T1059 used?", "It is used for execution.")
    rewritten = rewrite_followup("what about PowerShell?", memory)
    assert "T1059" in rewritten
    assert "follow-up" in rewritten
