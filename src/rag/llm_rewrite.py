"""LLM-based standalone query rewriting for follow-up questions."""

from __future__ import annotations

import logging

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from src.llm.errors import LLMUserError, invoke_llm

logger = logging.getLogger(__name__)

REWRITE_SYSTEM = """You rewrite analyst follow-up questions into standalone retrieval queries.
Output ONLY the rewritten query — no explanation.
Preserve technique IDs (T####) and CVE IDs exactly.
If the follow-up is already standalone, return it unchanged."""


def rewrite_followup_with_llm(
    question: str,
    history_text: str,
    llm: BaseChatModel,
) -> str:
    """Use the LLM to produce a standalone retrieval query."""
    prompt = (
        f"Conversation history:\n{history_text or '(none)'}\n\n"
        f"Follow-up question:\n{question}\n\n"
        "Standalone retrieval query:"
    )
    try:
        response = invoke_llm(
            llm,
            [
                SystemMessage(content=REWRITE_SYSTEM),
                HumanMessage(content=prompt),
            ],
        )
        rewritten = str(response.content).strip()
        return rewritten or question
    except LLMUserError:
        raise
    except Exception as exc:
        logger.warning("LLM follow-up rewrite failed: %s", exc)
        return question
