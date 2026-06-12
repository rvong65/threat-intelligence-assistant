"""Threat Intelligence RAG chain: retrieve, generate, validate, score."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from langchain_community.vectorstores import FAISS
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from config.settings import Settings, get_settings
from src.llm.errors import invoke_llm
from src.rag.citations import CitationValidation, validate_citations
from src.rag.confidence import (
    ConfidenceBreakdown,
    compute_confidence,
    should_abstain_pre_generation,
)
from src.rag.llm_rewrite import rewrite_followup_with_llm
from src.rag.memory import ConversationMemory, rewrite_followup
from src.rag.prompts import build_prompt_messages
from src.rag.query_guard import is_threat_intel_query, out_of_scope_message
from src.rag.retriever import RetrievedChunk, retrieve

logger = logging.getLogger(__name__)

LOW_CONFIDENCE_DISCLAIMER = (
    "**Low confidence ({score}/100):** Retrieval evidence is weak. "
    "Treat this answer with caution and verify against primary sources.\n\n"
)

ABSTENTION_PHRASE = "I don't have enough grounded evidence to answer confidently."

HARD_ABSTENTION_SUFFIX = (
    "\n\n*Hard abstention: generation was blocked or replaced because "
    "confidence was below the configured threshold. Try a more specific query "
    "or include a technique/CVE ID.*"
)


@dataclass
class RAGResponse:
    """Structured output from one RAG invocation."""

    question: str
    answer: str
    raw_answer: str
    chunks: list[RetrievedChunk]
    confidence: ConfidenceBreakdown
    citations: CitationValidation
    retrieval_query: str
    disclaimer: str = ""
    hard_abstained: bool = False
    out_of_scope: bool = False

    @property
    def is_abstention(self) -> bool:
        return ABSTENTION_PHRASE in self.answer or self.hard_abstained


def _abstention_response(
    question: str,
    retrieval_query: str,
    chunks: list[RetrievedChunk],
    *,
    hard: bool = False,
    threshold: int = 40,
) -> RAGResponse:
    """Build a standard abstention RAGResponse."""
    confidence = compute_confidence(chunks, [], [], threshold)
    citations = validate_citations("", chunks)
    suffix = HARD_ABSTENTION_SUFFIX if hard else ""
    answer = ABSTENTION_PHRASE + suffix
    return RAGResponse(
        question=question,
        answer=answer,
        raw_answer=ABSTENTION_PHRASE,
        chunks=chunks,
        confidence=confidence,
        citations=citations,
        retrieval_query=retrieval_query,
        hard_abstained=hard,
    )


class ThreatIntelRAGChain:
    """End-to-end grounded RAG pipeline."""

    def __init__(
        self,
        vectorstore: FAISS,
        llm: BaseChatModel,
        settings: Settings | None = None,
        memory: ConversationMemory | None = None,
    ) -> None:
        self.vectorstore = vectorstore
        self.llm = llm
        self.settings = settings or get_settings()
        self.memory = memory or ConversationMemory(max_turns=self.settings.memory_max_turns)

    def invoke(self, question: str) -> RAGResponse:
        """Run full RAG pipeline for an analyst question."""
        threshold = self.settings.confidence_threshold
        hard = self.settings.hard_abstention_enabled

        if not is_threat_intel_query(question):
            logger.info("Out-of-scope query blocked: %s", question[:80])
            guidance = out_of_scope_message(question)
            empty_confidence = compute_confidence([], [], [], threshold)
            return RAGResponse(
                question=question,
                answer=guidance,
                raw_answer=guidance,
                chunks=[],
                confidence=empty_confidence,
                citations=validate_citations("", []),
                retrieval_query=question,
                out_of_scope=True,
            )

        retrieval_query = rewrite_followup(question, self.memory)
        if (
            self.settings.llm_rewrite_followups
            and self.memory.turns
            and retrieval_query != question
        ):
            retrieval_query = rewrite_followup_with_llm(
                question,
                self.memory.format_history(),
                self.llm,
            )

        chunks = retrieve(self.vectorstore, retrieval_query, self.settings)
        if not chunks:
            return _abstention_response(
                question, retrieval_query, [], hard=hard, threshold=threshold
            )

        if hard and should_abstain_pre_generation(chunks, threshold):
            logger.info("Hard abstention (pre-generation) for: %s", question[:80])
            return _abstention_response(
                question, retrieval_query, chunks, hard=True, threshold=threshold
            )

        history_text = self.memory.format_history()
        messages = build_prompt_messages(
            question=question,
            context_documents=[c.document for c in chunks],
            history_text=history_text,
        )

        lc_messages = []
        for role, content in messages:
            if role == "system":
                lc_messages.append(SystemMessage(content=content))
            else:
                lc_messages.append(HumanMessage(content=content))

        logger.info("Invoking LLM for question: %s", question[:80])
        response = invoke_llm(self.llm, lc_messages)
        raw_answer = str(response.content).strip()

        citation_result = validate_citations(raw_answer, chunks)
        confidence = compute_confidence(
            chunks=chunks,
            cited_ids=citation_result.cited_ids,
            valid_cited_ids=citation_result.valid_ids,
            threshold=threshold,
        )

        if hard and confidence.is_low_confidence and ABSTENTION_PHRASE not in raw_answer:
            logger.info("Hard abstention (post-generation) for: %s", question[:80])
            result = _abstention_response(
                question, retrieval_query, chunks, hard=True, threshold=threshold
            )
            self.memory.add(question, ABSTENTION_PHRASE)
            return result

        final_answer = raw_answer
        disclaimer = ""

        if not hard and confidence.is_low_confidence and ABSTENTION_PHRASE not in raw_answer:
            disclaimer = LOW_CONFIDENCE_DISCLAIMER.format(score=confidence.overall)
            final_answer = disclaimer + raw_answer

        if citation_result.hallucinated_ids:
            warning = (
                f"**Citation warning:** Unverified IDs: "
                f"{', '.join(citation_result.hallucinated_ids)}\n\n"
            )
            final_answer = warning + final_answer

        self.memory.add(question, raw_answer)

        return RAGResponse(
            question=question,
            answer=final_answer,
            raw_answer=raw_answer,
            chunks=chunks,
            confidence=confidence,
            citations=citation_result,
            retrieval_query=retrieval_query,
            disclaimer=disclaimer,
        )
