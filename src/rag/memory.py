"""Conversational memory for multi-turn analyst queries."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.rag.query_guard import is_out_of_scope_query


@dataclass
class ChatTurn:
    """One question-answer exchange."""

    question: str
    answer: str


@dataclass
class ConversationMemory:
    """Rolling buffer of recent chat turns."""

    max_turns: int = 3
    turns: list[ChatTurn] = field(default_factory=list)

    def add(self, question: str, answer: str) -> None:
        self.turns.append(ChatTurn(question=question, answer=answer))
        if len(self.turns) > self.max_turns:
            self.turns = self.turns[-self.max_turns :]

    def format_history(self) -> str:
        if not self.turns:
            return ""
        lines: list[str] = []
        for index, turn in enumerate(self.turns, start=1):
            lines.append(f"Turn {index} Q: {turn.question}")
            lines.append(f"Turn {index} A: {turn.answer[:500]}")
        return "\n".join(lines)

    def clear(self) -> None:
        self.turns.clear()


def rewrite_followup(question: str, memory: ConversationMemory) -> str:
    """
    Expand a short follow-up into a standalone retrieval query.

    Uses a lightweight heuristic (no extra LLM call) when LLM rewrite is disabled.
    """
    if not memory.turns:
        return question

    q = question.strip()

    # Never treat greetings or social chat as technique/CVE follow-ups.
    if is_out_of_scope_query(q):
        return question
    followup_starters = (
        "what about",
        "and ",
        "how about",
        "tell me more",
        "any ",
        "which ",
        "can you",
        "what else",
        "also",
        "more ",
    )
    is_followup = len(q.split()) <= 8 or q.lower().startswith(followup_starters)
    if not is_followup:
        return question

    last_question = memory.turns[-1].question
    return f"{last_question} — follow-up: {q}"
